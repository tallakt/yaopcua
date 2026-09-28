defmodule OPCUA.Server.Subscriptions do
  @moduledoc false
  # The subscription services of one session (Part 4, 5.13 and 5.12).
  #
  # Each subscription has two timers in the connection process: sampling,
  # which reads its monitored items and queues the ones that changed, and
  # publishing, which sends what's queued in the answer to a waiting Publish
  # request. A cycle with nothing to send counts toward a keep-alive, and a
  # cycle without a waiting Publish request toward the subscription's
  # lifetime.
  #
  # Responses that don't answer the request at hand, such as a Publish
  # answered by a timer, go to `session.outbox` for the connection to send.

  alias OPCUA.{DataValue, StatusCode, Variant}
  alias OPCUA.Server.{AddressSpace, Conditions, Events, Node, Services}
  alias OPCUA.Server.Session.{MonitoredItem, Subscription}
  alias OPCUA.Types

  @min_interval 10
  @max_interval 3_600_000
  @max_queue 1000
  @max_publishes 10
  @retransmit 10

  # DeadbandType (Part 4, 7.22.2). Percent deadbands, of an analog item's
  # range, aren't supported.
  @no_deadband 0
  @absolute_deadband 1

  ## Subscriptions

  @doc false
  def handle(%Types.CreateSubscriptionRequest{} = request, session, state) do
    id = OPCUA.Server.next_id(state.config, :subscription)
    sub = %{revise(%Subscription{id: id}, request) | publishing: request.publishing_enabled}

    schedule(session.auth, sub, :publish)
    schedule(session.auth, sub, :sample)

    response = %Types.CreateSubscriptionResponse{
      response_header: Services.header(request, 0),
      subscription_id: id,
      revised_publishing_interval: sub.interval * 1.0,
      revised_lifetime_count: sub.lifetime_count,
      revised_max_keep_alive_count: sub.keep_alive_count
    }

    {response, put_in(session.subscriptions[id], sub)}
  end

  def handle(%Types.ModifySubscriptionRequest{} = request, session, _state) do
    case session.subscriptions[request.subscription_id] do
      nil ->
        {Services.fault(request, :bad_subscription_id_invalid), session}

      sub ->
        sub = revise(sub, request)

        response = %Types.ModifySubscriptionResponse{
          response_header: Services.header(request, 0),
          revised_publishing_interval: sub.interval * 1.0,
          revised_lifetime_count: sub.lifetime_count,
          revised_max_keep_alive_count: sub.keep_alive_count
        }

        {response, put_in(session.subscriptions[sub.id], sub)}
    end
  end

  def handle(%Types.SetPublishingModeRequest{} = request, session, _state) do
    {results, session} =
      Enum.map_reduce(request.subscription_ids || [], session, fn id, session ->
        case session.subscriptions[id] do
          nil ->
            {code(:bad_subscription_id_invalid), session}

          sub ->
            {0,
             put_in(session.subscriptions[id], %{sub | publishing: request.publishing_enabled})}
        end
      end)

    {%Types.SetPublishingModeResponse{
       response_header: Services.header(request, 0),
       results: results
     }, session}
  end

  def handle(%Types.DeleteSubscriptionsRequest{} = request, session, _state) do
    {results, session} =
      Enum.map_reduce(request.subscription_ids || [], session, fn id, session ->
        if Map.has_key?(session.subscriptions, id),
          do: {0, %{session | subscriptions: Map.delete(session.subscriptions, id)}},
          else: {code(:bad_subscription_id_invalid), session}
      end)

    response = %Types.DeleteSubscriptionsResponse{
      response_header: Services.header(request, 0),
      results: results
    }

    {response, no_subscriptions(session)}
  end

  ## Monitored items

  def handle(%Types.CreateMonitoredItemsRequest{} = request, session, state) do
    with %{} = sub <- session.subscriptions[request.subscription_id] || :unknown,
         true <-
           request.timestamps_to_return in [:source, :server, :both, :neither] || :timestamps do
      {results, sub} =
        Enum.map_reduce(request.items_to_create || [], sub, fn create, sub ->
          create_item(create, request.timestamps_to_return, sub, state.config.space)
        end)

      response = %Types.CreateMonitoredItemsResponse{
        response_header: Services.header(request, 0),
        results: results
      }

      {response, put_in(session.subscriptions[sub.id], sub)}
    else
      :unknown -> {Services.fault(request, :bad_subscription_id_invalid), session}
      :timestamps -> {Services.fault(request, :bad_timestamps_to_return_invalid), session}
    end
  end

  def handle(%Types.ModifyMonitoredItemsRequest{} = request, session, state) do
    case session.subscriptions[request.subscription_id] do
      nil ->
        {Services.fault(request, :bad_subscription_id_invalid), session}

      sub ->
        {results, sub} =
          Enum.map_reduce(request.items_to_modify || [], sub, fn modify, sub ->
            case sub.items[modify.monitored_item_id] do
              nil ->
                {%Types.MonitoredItemModifyResult{
                   status_code: code(:bad_monitored_item_id_invalid)
                 }, sub}

              item ->
                case modify(item, modify.requested_parameters, sub, state.config.space) do
                  {:ok, item} ->
                    result = %Types.MonitoredItemModifyResult{
                      status_code: 0,
                      revised_sampling_interval: item.sampling * 1.0,
                      revised_queue_size: item.queue_size
                    }

                    {result, put_in(sub.items[item.id], item)}

                  {:error, status} ->
                    {%Types.MonitoredItemModifyResult{status_code: code(status)}, sub}
                end
            end
          end)

        response = %Types.ModifyMonitoredItemsResponse{
          response_header: Services.header(request, 0),
          results: results
        }

        {response, put_in(session.subscriptions[sub.id], sub)}
    end
  end

  def handle(%Types.SetMonitoringModeRequest{} = request, session, _state) do
    case session.subscriptions[request.subscription_id] do
      nil ->
        {Services.fault(request, :bad_subscription_id_invalid), session}

      sub ->
        {results, sub} =
          Enum.map_reduce(request.monitored_item_ids || [], sub, fn id, sub ->
            case sub.items[id] do
              nil ->
                {code(:bad_monitored_item_id_invalid), sub}

              item ->
                item = %{item | mode: request.monitoring_mode}
                item = if item.mode == :disabled, do: clear(item), else: item
                {0, put_in(sub.items[id], item)}
            end
          end)

        {%Types.SetMonitoringModeResponse{
           response_header: Services.header(request, 0),
           results: results
         }, put_in(session.subscriptions[sub.id], sub)}
    end
  end

  def handle(%Types.DeleteMonitoredItemsRequest{} = request, session, _state) do
    case session.subscriptions[request.subscription_id] do
      nil ->
        {Services.fault(request, :bad_subscription_id_invalid), session}

      sub ->
        {results, sub} =
          Enum.map_reduce(request.monitored_item_ids || [], sub, fn id, sub ->
            if Map.has_key?(sub.items, id),
              do: {0, %{sub | items: Map.delete(sub.items, id)}},
              else: {code(:bad_monitored_item_id_invalid), sub}
          end)

        {%Types.DeleteMonitoredItemsResponse{
           response_header: Services.header(request, 0),
           results: results
         }, put_in(session.subscriptions[sub.id], sub)}
    end
  end

  ## Publishing

  def handle(%Types.PublishRequest{} = request, session, state) do
    {acks, session} = acknowledge(request.subscription_acknowledgements || [], session)
    publish = %{id: state.request_id, request: request, acks: acks}

    cond do
      session.status_changes != [] ->
        [{sub_id, status} | rest] = session.status_changes
        message = notification(0, [%Types.StatusChangeNotification{status: code(status)}])
        {response(publish, sub_id, message, []), %{session | status_changes: rest}}

      session.subscriptions == %{} ->
        {Services.fault(request, :bad_no_subscription), session}

      late = Enum.find(Map.values(session.subscriptions), & &1.late) ->
        {sub, publish_response} = send_cycle(late, publish)
        {publish_response, put_in(session.subscriptions[sub.id], sub)}

      true ->
        session = queue_publish(session, publish, request)
        {:noreply, session}
    end
  end

  def handle(%Types.RepublishRequest{} = request, session, _state) do
    with %{} = sub <-
           session.subscriptions[request.subscription_id] ||
             {:error, :bad_subscription_id_invalid},
         %{} = message <-
           sub.retransmit[request.retransmit_sequence_number] ||
             {:error, :bad_message_not_available} do
      {%Types.RepublishResponse{
         response_header: Services.header(request, 0),
         notification_message: message
       }, session}
    else
      {:error, status} -> {Services.fault(request, status), session}
    end
  end

  def handle(request, session, _state),
    do: {Services.fault(request, :bad_service_unsupported), session}

  defp queue_publish(session, publish, request) do
    hint = request.request_header.timeout_hint

    timer =
      if hint > 0,
        do: Process.send_after(self(), {:publish_timeout, session.auth, publish.id}, hint)

    publishes = session.publishes ++ [Map.put(publish, :timer, timer)]

    if length(publishes) > @max_publishes do
      [oldest | publishes] = publishes
      cancel(oldest)

      %{
        session
        | publishes: publishes,
          outbox: [
            {oldest.id, Services.fault(oldest.request, :bad_too_many_publish_requests)}
            | session.outbox
          ]
      }
    else
      %{session | publishes: publishes}
    end
  end

  @doc false
  # A Publish request that waited longer than its timeout hint.
  def publish_timeout(session, id) do
    case Enum.split_with(session.publishes, &(&1.id == id)) do
      {[publish], rest} ->
        %{
          session
          | publishes: rest,
            outbox: [{id, Services.fault(publish.request, :bad_timeout)} | session.outbox]
        }

      {[], _} ->
        session
    end
  end

  defp acknowledge(acks, session) do
    Enum.map_reduce(acks, session, fn ack, session ->
      case session.subscriptions[ack.subscription_id] do
        nil ->
          {code(:bad_subscription_id_invalid), session}

        sub ->
          if Map.has_key?(sub.retransmit, ack.sequence_number),
            do:
              {0,
               put_in(
                 session.subscriptions[sub.id].retransmit,
                 Map.delete(sub.retransmit, ack.sequence_number)
               )},
            else: {code(:bad_sequence_number_unknown), session}
      end
    end)
  end

  @doc false
  # A publishing cycle of one subscription.
  def publish_cycle(session, sub_id) do
    case session.subscriptions[sub_id] do
      nil ->
        session

      sub ->
        schedule(session.auth, sub, :publish)
        notifications = sub.publishing and has_notifications?(sub)
        keep_alive = not notifications and sub.keep_alive_counter + 1 >= sub.keep_alive_count

        cond do
          (notifications or keep_alive) and session.publishes != [] ->
            [publish | rest] = session.publishes
            cancel(publish)
            {sub, response} = send_cycle(sub, publish)

            %{session | publishes: rest, outbox: [{publish.id, response} | session.outbox]}
            |> put_sub(sub)

          notifications or keep_alive ->
            # Nothing to send it with; the next Publish request gets it.
            lifetime(session, %{sub | late: true, lifetime_counter: sub.lifetime_counter + 1})

          true ->
            counter =
              if session.publishes == [], do: sub.lifetime_counter + 1, else: sub.lifetime_counter

            lifetime(session, %{
              sub
              | keep_alive_counter: sub.keep_alive_counter + 1,
                lifetime_counter: counter
            })
        end
    end
  end

  # A subscription nobody has asked to publish for, for its whole lifetime, ends.
  defp lifetime(session, sub) do
    if sub.lifetime_counter >= sub.lifetime_count do
      session = %{
        session
        | subscriptions: Map.delete(session.subscriptions, sub.id),
          status_changes: session.status_changes ++ [{sub.id, :bad_timeout}]
      }

      no_subscriptions(session)
    else
      put_sub(session, sub)
    end
  end

  defp put_sub(session, sub), do: put_in(session.subscriptions[sub.id], sub)

  # Sends what a subscription has, or a keep-alive, in answer to `publish`.
  defp send_cycle(sub, publish) do
    {data, sub} = take_notifications(sub)

    {message, sub} =
      if data == [] do
        # A keep-alive carries the next sequence number without using it up.
        {notification(sub.sequence, []), sub}
      else
        message = notification(sub.sequence, data)

        retransmit =
          sub.retransmit
          |> Map.put(sub.sequence, message)
          |> Map.drop([sub.sequence - @retransmit])

        {message, %{sub | sequence: sub.sequence + 1, retransmit: retransmit}}
      end

    sub = %{sub | late: false, keep_alive_counter: 0, lifetime_counter: 0}
    {sub, response(publish, sub.id, message, Map.keys(sub.retransmit) |> Enum.sort())}
  end

  defp response(publish, sub_id, message, available) do
    %Types.PublishResponse{
      response_header: Services.header(publish.request, 0),
      subscription_id: sub_id,
      available_sequence_numbers: available,
      more_notifications: false,
      notification_message: message,
      results: publish.acks
    }
  end

  defp notification(sequence, data),
    do: %Types.NotificationMessage{
      sequence_number: sequence,
      publish_time: DateTime.utc_now(),
      notification_data: data
    }

  defp has_notifications?(sub),
    do: Enum.any?(sub.items, fn {_, item} -> item.mode == :reporting and item.queued > 0 end)

  defp take_notifications(%{publishing: false} = sub), do: {[], sub}

  # Value changes go in a DataChangeNotification, events in an
  # EventNotificationList; the queues are emptied.
  defp take_notifications(sub) do
    reporting =
      for {id, %{mode: :reporting} = item} <- sub.items, item.queued > 0, do: {id, item}

    changes =
      for {_, %{kind: :value} = item} <- reporting,
          value <- :queue.to_list(item.queue),
          do: %Types.MonitoredItemNotification{client_handle: item.handle, value: value}

    events =
      for {_, %{kind: :events} = item} <- reporting,
          fields <- :queue.to_list(item.queue),
          do: fields

    items =
      Enum.reduce(reporting, sub.items, fn {id, item}, items ->
        Map.put(items, id, clear(item))
      end)

    data =
      if(changes == [], do: [], else: [%Types.DataChangeNotification{monitored_items: changes}]) ++
        if(events == [], do: [], else: [%Types.EventNotificationList{events: events}])

    {data, %{sub | items: items}}
  end

  ## Events

  @doc false
  # Queues an event for every event item of the session that reports it.
  def event(session, event, space) do
    subscriptions =
      Map.new(session.subscriptions, fn {id, sub} ->
        items =
          Map.new(sub.items, fn
            {item_id, %{kind: :events, mode: :reporting} = item} ->
              {item_id,
               if(Events.reported_by?(event, item.read.node_id, space),
                 do: queue_event(item, event, space, true),
                 else: item
               )}

            other ->
              other
          end)

        {id, %{sub | items: items}}
      end)

    %{session | subscriptions: subscriptions}
  end

  defp queue_event(item, event, space, where) do
    fields =
      if where,
        do: Events.filter(event, item.filter, space),
        else: Events.select(event, item.filter, space)

    if fields,
      do: enqueue(item, %Types.EventFieldList{client_handle: item.handle, event_fields: fields}),
      else: item
  end

  @doc false
  # ConditionRefresh: sends `events` (the refresh markers and the retained
  # conditions) to the event items of one subscription, or just one item.
  def refresh(session, sub_id, item_id, events, space) do
    case session.subscriptions[sub_id] do
      nil ->
        {:error, :bad_subscription_id_invalid}

      sub ->
        targets =
          for {id, %{kind: :events} = item} <- sub.items, item_id in [nil, id], do: {id, item}

        if targets == [] and item_id != nil do
          {:error, :bad_monitored_item_id_invalid}
        else
          items =
            Enum.reduce(targets, sub.items, fn {id, item}, items ->
              # The markers get through whatever the where clause says.
              item =
                Enum.reduce(events, item, &queue_event(&2, &1, space, not Conditions.marker?(&1)))

              Map.put(items, id, item)
            end)

          {:ok, put_sub(session, %{sub | items: items})}
        end
    end
  end

  # When the last subscription goes, waiting Publish requests have nothing to wait for.
  defp no_subscriptions(%{subscriptions: subs} = session) when map_size(subs) > 0, do: session
  defp no_subscriptions(%{status_changes: [_ | _]} = session), do: session

  defp no_subscriptions(session) do
    outbox =
      for publish <- session.publishes do
        cancel(publish)
        {publish.id, Services.fault(publish.request, :bad_no_subscription)}
      end

    %{session | publishes: [], outbox: outbox ++ session.outbox}
  end

  defp cancel(%{timer: nil}), do: :ok
  defp cancel(%{timer: timer}), do: Process.cancel_timer(timer)

  ## Sampling

  @doc false
  # A sampling cycle of one subscription: each item that's due is read, and
  # queued if it changed.
  def sample(session, sub_id, space) do
    case session.subscriptions[sub_id] do
      nil ->
        session

      sub ->
        now = System.monotonic_time(:millisecond)

        items =
          Map.new(sub.items, fn {id, item} ->
            if item.kind == :value and item.mode != :disabled and now >= item.due,
              do: {id, sample_item(%{item | due: now + item.sampling}, space)},
              else: {id, item}
          end)

        sub = %{sub | items: items}
        schedule(session.auth, sub, :sample)
        put_sub(session, sub)
    end
  end

  defp sample_item(item, space) do
    value = AddressSpace.read(space, item.read, item.timestamps)
    if changed?(item, value), do: enqueue(%{item | last: value}, value), else: item
  end

  defp changed?(%{last: nil}, _), do: true

  defp changed?(%{last: last, filter: filter}, value) do
    trigger = if filter, do: filter.trigger, else: :status_value

    cond do
      last.status != value.status -> true
      trigger == :status -> false
      value_changed?(last.value, value.value, filter) -> true
      trigger == :status_value_timestamp -> last.source_timestamp != value.source_timestamp
      true -> false
    end
  end

  defp value_changed?(%Variant{value: a}, %Variant{value: b}, %Types.DataChangeFilter{
         deadband_type: @absolute_deadband,
         deadband_value: band
       }) do
    exceeds?(a, b, band)
  end

  defp value_changed?(a, b, _), do: a != b

  defp exceeds?(a, b, band) when is_number(a) and is_number(b), do: abs(a - b) > band

  defp exceeds?(a, b, band) when is_list(a) and is_list(b) and length(a) == length(b),
    do: Enum.zip(a, b) |> Enum.any?(fn {x, y} -> exceeds?(x, y, band) end)

  defp exceeds?(a, b, _), do: a != b

  # A full queue drops its oldest notification, or replaces its newest.
  defp enqueue(%{queued: n} = item, value) when n < item.queue_size,
    do: %{item | queue: :queue.in(value, item.queue), queued: n + 1}

  defp enqueue(%{discard_oldest: true} = item, value),
    do: %{item | queue: :queue.in(value, :queue.drop(item.queue))}

  defp enqueue(item, value), do: %{item | queue: :queue.in(value, :queue.drop_r(item.queue))}

  defp clear(item), do: %{item | queue: :queue.new(), queued: 0}

  defp create_item(%Types.MonitoredItemCreateRequest{} = create, timestamps, sub, space) do
    read = create.item_to_monitor

    if OPCUA.AttributeId.name(read.attribute_id) == :event_notifier,
      do: create_event_item(create, sub, space),
      else: create_value_item(create, timestamps, sub, space)
  end

  defp create_event_item(create, sub, space) do
    read = create.item_to_monitor

    with %Node{} = node <-
           AddressSpace.get(space, read.node_id) || {:error, :bad_node_id_unknown},
         true <- AddressSpace.notifier?(node) || {:error, :bad_attribute_id_invalid},
         {:ok, filter_result, item} <-
           event_parameters(
             %MonitoredItem{
               id: sub.next_item + 1,
               kind: :events,
               read: read,
               mode: create.monitoring_mode
             },
             create.requested_parameters,
             space
           ) do
      result = %Types.MonitoredItemCreateResult{
        status_code: 0,
        monitored_item_id: item.id,
        revised_sampling_interval: 0.0,
        revised_queue_size: item.queue_size,
        filter_result: filter_result
      }

      {result, %{sub | next_item: item.id, items: Map.put(sub.items, item.id, item)}}
    else
      {:error, status} ->
        {%Types.MonitoredItemCreateResult{status_code: code(status)}, sub}

      {:error, status, result} ->
        {%Types.MonitoredItemCreateResult{status_code: code(status), filter_result: result}, sub}
    end
  end

  defp modify(%{kind: :events} = item, parameters, _sub, space) do
    case event_parameters(item, parameters, space) do
      {:ok, _, item} -> {:ok, item}
      {:error, status, _} -> {:error, status}
    end
  end

  defp modify(item, parameters, sub, _space), do: parameters(item, parameters, sub)

  defp event_parameters(item, %Types.MonitoringParameters{} = p, space) do
    with {:ok, result} <- Events.check(p.filter, space) do
      queue = if p.queue_size in [0, 1], do: @max_queue, else: min(p.queue_size, @max_queue * 10)

      {:ok, result,
       %{
         item
         | handle: p.client_handle,
           queue_size: queue,
           discard_oldest: p.discard_oldest,
           filter: p.filter
       }}
    end
  end

  defp create_value_item(create, timestamps, sub, space) do
    read = create.item_to_monitor

    with :ok <- monitorable(space, read),
         {:ok, item} <-
           parameters(
             %MonitoredItem{
               id: sub.next_item + 1,
               kind: :value,
               read: read,
               timestamps: timestamps,
               mode: create.monitoring_mode
             },
             create.requested_parameters,
             sub
           ) do
      item =
        if item.mode == :disabled,
          do: item,
          else:
            sample_item(%{item | due: System.monotonic_time(:millisecond) + item.sampling}, space)

      result = %Types.MonitoredItemCreateResult{
        status_code: 0,
        monitored_item_id: item.id,
        revised_sampling_interval: item.sampling * 1.0,
        revised_queue_size: item.queue_size
      }

      {result, %{sub | next_item: item.id, items: Map.put(sub.items, item.id, item)}}
    else
      {:error, status} -> {%Types.MonitoredItemCreateResult{status_code: code(status)}, sub}
    end
  end

  defp monitorable(space, read) do
    case AddressSpace.read(space, %{read | index_range: nil}, :neither) do
      %DataValue{status: 0} ->
        :ok

      %DataValue{status: status} ->
        {:error, StatusCode.name(status)}
    end
  end

  defp parameters(item, %Types.MonitoringParameters{} = p, sub) do
    filter =
      case p.filter do
        nil ->
          {:ok, nil}

        %Types.DataChangeFilter{deadband_type: type} = filter
        when type in [@no_deadband, @absolute_deadband] ->
          {:ok, filter}

        %Types.DataChangeFilter{} ->
          {:error, :bad_monitored_item_filter_unsupported}

        _ ->
          {:error, :bad_monitored_item_filter_unsupported}
      end

    with {:ok, filter} <- filter do
      sampling =
        if p.sampling_interval < 0,
          do: sub.interval,
          else: p.sampling_interval |> max(@min_interval) |> min(@max_interval)

      {:ok,
       %{
         item
         | handle: p.client_handle,
           sampling: trunc(sampling),
           queue_size: p.queue_size |> max(1) |> min(@max_queue),
           discard_oldest: p.discard_oldest,
           filter: filter
       }}
    end
  end

  ## Helpers

  # max_notifications and priority are kept but not used: every queued
  # notification goes in one PublishResponse, and subscriptions are served in
  # no particular order. The overflow bit of a full queue isn't set either.
  defp revise(sub, request) do
    interval =
      request.requested_publishing_interval |> max(@min_interval) |> min(@max_interval) |> trunc()

    keep_alive = max(request.requested_max_keep_alive_count, 1)

    %{
      sub
      | interval: interval,
        keep_alive_count: keep_alive,
        lifetime_count: max(request.requested_lifetime_count, 3 * keep_alive),
        max_notifications: request.max_notifications_per_publish,
        priority: request.priority
    }
  end

  # Sampling runs at the fastest interval of the subscription's items.
  defp schedule(auth, sub, :publish),
    do: Process.send_after(self(), {:publish_cycle, auth, sub.id}, sub.interval)

  defp schedule(auth, sub, :sample) do
    # Event items aren't sampled.
    fastest =
      Enum.min(for({_, %{kind: :value, sampling: s}} <- sub.items, do: s), fn -> sub.interval end)

    Process.send_after(self(), {:sample, auth, sub.id}, min(fastest, sub.interval))
  end

  defp code(status), do: StatusCode.code(status)
end
