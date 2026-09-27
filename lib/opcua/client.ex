defmodule OPCUA.Client do
  @moduledoc """
  An OPC UA client: one TCP connection, one secure channel, one session.

      {:ok, client} = OPCUA.Client.start_link(url: "opc.tcp://10.0.0.5:4840")

      {:ok, 1500} = OPCUA.Client.read(client, "ns=2;s=Pump1.Speed")
      :ok = OPCUA.Client.write(client, "ns=2;s=Pump1.Speed", 1600)
      {:ok, refs} = OPCUA.Client.browse(client, "ns=2;s=Plant")
      {:ok, [42]} = OPCUA.Client.call(client, "ns=2;s=Plant", "ns=2;s=Multiply", [6, 7])

      {:ok, sub} = OPCUA.Client.subscribe(client, ["ns=2;s=Pump1.Speed"])
      # the caller then gets
      {OPCUA.Client, ^sub, {:value, "ns=2;s=Pump1.Speed", %OPCUA.DataValue{}}}

  Node ids are `OPCUA.NodeId` structs or their text form. Errors are the
  status code's name, such as `{:error, :bad_node_id_unknown}`.

  `start_link/1` returns once the session is active, or with the reason it
  couldn't get there. When the connection drops the client stops with
  `{:shutdown, reason}`, so run it under a supervisor to reconnect.

  Only the None security policy is supported so far, with anonymous or
  username login.

  ## Options

    * `:url` - the endpoint, `opc.tcp://host:port/path` (required)
    * `:user` - `{username, password}`, or `:anonymous` (the default)
    * `:timeout` - how long a request may take, in ms (default 5000)
    * `:session_timeout` - how long the server keeps an idle session, in ms
      (default 60000); the client keeps it alive
    * `:channel_lifetime` - how long a secure channel token lasts before the
      client renews it, in ms (default one hour)
    * `:session_name`, `:application_uri` - how the client presents itself
    * `:name` - to register the process
  """

  use GenServer

  require Logger

  import OPCUA.Client.Connection, only: [with_header: 3, result: 1, status_name: 1]

  alias OPCUA.{DataValue, NodeId, QualifiedName, SecureChannel, StatusCode, Transport, Variant}
  alias OPCUA.Client.Connection
  alias OPCUA.Types

  # ServerStatus.State, read to keep the session alive
  @keep_alive 2259
  @session_lost [:bad_session_id_invalid, :bad_session_closed, :bad_session_not_activated]

  @base_event_type %NodeId{id: 2041}
  @condition_type %NodeId{id: 2782}
  @server_object "i=2253"
  @event_fields ~w(EventId EventType SourceNode SourceName Time Message Severity)

  @type client :: GenServer.server()
  @type node_ref :: NodeId.t() | String.t()
  @type subscription :: non_neg_integer
  @type error :: {:error, atom | non_neg_integer}

  @doc "Connects and activates a session. See the module doc for the options."
  @spec start_link(keyword) :: GenServer.on_start()
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, Keyword.take(opts, [:name]))

  @doc "Like `start_link/1`, without linking to the caller."
  @spec start(keyword) :: GenServer.on_start()
  def start(opts), do: GenServer.start(__MODULE__, opts, Keyword.take(opts, [:name]))

  @doc "Closes the session and the connection."
  @spec close(client) :: :ok
  def close(client), do: GenServer.stop(client)

  @doc """
  Reads one attribute of one node; the value by default. Returns the plain
  value: a number, a string, a list for an array, a struct for a structure.

  A Good or Uncertain result is `{:ok, value}`; use `read_many/3` to see the
  status and timestamps.
  """
  @spec read(client, node_ref, atom) :: {:ok, term} | error
  def read(client, node, attribute \\ :value) do
    with {:ok, [result]} <- read_many(client, [node], attribute) do
      value(result)
    end
  end

  @doc "Reads the same attribute of several nodes, returning a `OPCUA.DataValue` for each."
  @spec read_many(client, [node_ref], atom) :: {:ok, [DataValue.t()]} | error
  def read_many(client, nodes, attribute \\ :value) do
    id = OPCUA.AttributeId.id(attribute)
    reads = for node <- nodes, do: %Types.ReadValueId{node_id: node_id(node), attribute_id: id}
    request = %Types.ReadRequest{timestamps_to_return: :both, nodes_to_read: reads}

    with {:ok, %{results: results}} <- request(client, request) do
      {:ok, results}
    end
  end

  defp value(%DataValue{status: status, value: value}) do
    if StatusCode.bad?(status), do: {:error, status_name(status)}, else: {:ok, unwrap(value)}
  end

  defp unwrap(nil), do: nil
  defp unwrap(%Variant{value: value}), do: value

  @doc """
  Writes the value of a node.

  `value` is either an `OPCUA.Variant`, sent as is, or a plain value. For a
  plain value the client reads the node once to learn its type, and remembers
  it for later writes.
  """
  @spec write(client, node_ref, term) :: :ok | error
  def write(client, node, value) do
    with {:ok, [status]} <- write_many(client, [{node, value}]) do
      if StatusCode.bad?(status), do: {:error, status_name(status)}, else: :ok
    end
  end

  @doc "Writes several values, returning the status code of each write."
  @spec write_many(client, [{node_ref, term}]) :: {:ok, [StatusCode.t()]} | error
  def write_many(client, writes) do
    with {:ok, variants} <- variants(client, writes) do
      value = OPCUA.AttributeId.id(:value)

      items =
        for {{node, _}, variant} <- Enum.zip(writes, variants) do
          %Types.WriteValue{
            node_id: node_id(node),
            attribute_id: value,
            value: %DataValue{value: variant}
          }
        end

      with {:ok, %{results: results}} <-
             request(client, %Types.WriteRequest{nodes_to_write: items}) do
        {:ok, results}
      end
    end
  end

  defp variants(client, writes) do
    writes
    |> Enum.reduce_while({:ok, []}, fn {node, value}, {:ok, acc} ->
      case variant(client, node_id(node), value) do
        {:ok, variant} -> {:cont, {:ok, [variant | acc]}}
        error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, acc} -> {:ok, Enum.reverse(acc)}
      error -> error
    end
  end

  defp variant(_, _, %Variant{} = variant), do: {:ok, variant}

  defp variant(client, node, value) do
    case GenServer.call(client, {:type, node}) do
      nil ->
        case read_many(client, [node]) do
          {:ok, [%DataValue{value: %Variant{type: type}}]} ->
            GenServer.cast(client, {:type, node, type})
            {:ok, %Variant{type: type, value: value}}

          {:ok, [%DataValue{status: status}]} when status != 0 ->
            {:error, status_name(status)}

          {:ok, _} ->
            {:error, :bad_type_mismatch}

          error ->
            error
        end

      type ->
        {:ok, %Variant{type: type, value: value}}
    end
  end

  @doc """
  Lists the references of a node, following continuation points until the
  server has sent them all.

  ## Options

    * `:direction` - `:forward` (the default), `:inverse` or `:both`
    * `:reference_type` - the reference type to follow, with its subtypes
      (default `i=33`, HierarchicalReferences)
    * `:max_references` - how many references to ask for at a time (default 0,
      leaving it to the server)
  """
  @spec browse(client, node_ref, keyword) :: {:ok, [Types.ReferenceDescription.t()]} | error
  def browse(client, node, opts \\ []) do
    description = %Types.BrowseDescription{
      node_id: node_id(node),
      browse_direction: Keyword.get(opts, :direction, :forward),
      reference_type_id: node_id(Keyword.get(opts, :reference_type, "i=33")),
      include_subtypes: true,
      node_class_mask: 0,
      result_mask: 63
    }

    request = %Types.BrowseRequest{
      requested_max_references_per_node: Keyword.get(opts, :max_references, 0),
      nodes_to_browse: [description]
    }

    with {:ok, %{results: [result]}} <- request(client, request) do
      browse_rest(client, result, [])
    end
  end

  defp browse_rest(client, %Types.BrowseResult{status_code: status} = result, acc) do
    cond do
      StatusCode.bad?(status) ->
        {:error, status_name(status)}

      result.continuation_point in [nil, ""] ->
        {:ok, Enum.concat(Enum.reverse([result.references || [] | acc]))}

      true ->
        request = %Types.BrowseNextRequest{
          release_continuation_points: false,
          continuation_points: [result.continuation_point]
        }

        with {:ok, %{results: [next]}} <- request(client, request) do
          browse_rest(client, next, [result.references || [] | acc])
        end
    end
  end

  @doc """
  Calls a method on an object, returning its output arguments.

  Arguments are `OPCUA.Variant`s, or plain values: integers go as Int32,
  floats as Double, and strings, booleans and `DateTime`s as themselves. Use a
  variant when the method wants another type.
  """
  @spec call(client, node_ref, node_ref, [term]) :: {:ok, [term]} | error
  def call(client, object, method, args \\ []) do
    call = %Types.CallMethodRequest{
      object_id: node_id(object),
      method_id: node_id(method),
      input_arguments: Enum.map(args, &infer/1)
    }

    with {:ok, %{results: [result]}} <-
           request(client, %Types.CallRequest{methods_to_call: [call]}) do
      if StatusCode.bad?(result.status_code),
        do: {:error, status_name(result.status_code)},
        else: {:ok, Enum.map(result.output_arguments || [], &unwrap/1)}
    end
  end

  defp infer(%Variant{} = v), do: v
  defp infer(v) when is_boolean(v), do: %Variant{type: :boolean, value: v}

  defp infer(v) when is_integer(v) and v in -0x8000_0000..0x7FFF_FFFF,
    do: %Variant{type: :int32, value: v}

  defp infer(v) when is_integer(v), do: %Variant{type: :int64, value: v}
  defp infer(v) when is_float(v), do: %Variant{type: :double, value: v}
  defp infer(v) when is_binary(v), do: %Variant{type: :string, value: v}
  defp infer(%DateTime{} = v), do: %Variant{type: :date_time, value: v}
  defp infer(%NodeId{} = v), do: %Variant{type: :node_id, value: v}
  defp infer(%OPCUA.LocalizedText{} = v), do: %Variant{type: :localized_text, value: v}

  @doc """
  Subscribes to changes in the values of `nodes`. The subscriber gets

      {OPCUA.Client, subscription, {:value, node, %OPCUA.DataValue{}}}

  for each change, with `node` as given here. The first message for each node
  comes right away, with its current value. A node the server can't monitor,
  such as one that doesn't exist, gets a single message with its Bad status.

  If the server drops the subscription, the subscriber gets
  `{OPCUA.Client, subscription, {:status, status}}`.

  ## Options

    * `:to` - the subscriber, the caller by default. The subscription is
      deleted when it exits.
    * `:interval` - how often the server sends changes, in ms (default 1000)
    * `:sampling` - how often the server samples the values, in ms (default
      the interval)
    * `:deadband` - `{:absolute, 0.5}` or `{:percent, 2.0}` to leave out small
      changes of analog values
    * `:queue` - how many changes the server keeps per node between sends
      (default 1: only the latest)
    * `:keep_alive` - how long the server may go without sending anything,
      in ms (default 10000). If the client doesn't ask for notifications for
      six times this, the server deletes the subscription.
  """
  @spec subscribe(client, [node_ref], keyword) :: {:ok, subscription} | error
  def subscribe(client, nodes, opts \\ []) do
    parameters = %Types.MonitoringParameters{
      sampling_interval: Keyword.get(opts, :sampling, -1) * 1.0,
      queue_size: Keyword.get(opts, :queue, 1),
      discard_oldest: true,
      filter: deadband(Keyword.get(opts, :deadband))
    }

    value = OPCUA.AttributeId.id(:value)

    items =
      for node <- nodes do
        {{:value, node}, %Types.ReadValueId{node_id: node_id(node), attribute_id: value},
         parameters}
      end

    create(client, items, opts)
  end

  defp deadband(nil), do: nil

  defp deadband({type, value}) when type in [:absolute, :percent] do
    %Types.DataChangeFilter{
      trigger: :status_value,
      deadband_type: if(type == :absolute, do: 1, else: 2),
      deadband_value: value * 1.0
    }
  end

  @doc """
  Subscribes to the events a node reports, such as alarms. The subscriber gets

      {OPCUA.Client, subscription, {:event, %{"Message" => ..., "Severity" => ...}}}

  with the fields asked for, by name.

  ## Options

    * `:source` - the node whose events to get (default `i=2253`, the Server
      object, which reports all events)
    * `:fields` - the event fields to get, as browse paths from the event:
      `"Message"`, `"ActiveState/Id"`, or `"2:MyField"` for a field in
      namespace 2. `"ConditionId"` is the node id of an alarm's condition.
      The default is #{Enum.map_join(@event_fields, ", ", &"`#{&1}`")}.
    * `:of_type` - only events of this type and its subtypes, such as
      `"i=2915"` for alarms (AlarmConditionType)
    * `:where` - an `OPCUA.Types.ContentFilter` for anything else
    * `:to`, `:interval`, `:keep_alive` - as for `subscribe/3`
    * `:queue` - how many events the server keeps between sends (default 1000)

  For alarms, ask for `"ConditionId"` and `"EventId"` to be able to
  `acknowledge/4` them, and `refresh/2` to get the ones already standing.
  """
  @spec subscribe_events(client, keyword) :: {:ok, subscription} | error
  def subscribe_events(client, opts \\ []) do
    fields = Keyword.get(opts, :fields, @event_fields)

    parameters = %Types.MonitoringParameters{
      sampling_interval: 0.0,
      queue_size: Keyword.get(opts, :queue, 1000),
      discard_oldest: true,
      filter: %Types.EventFilter{
        select_clauses: Enum.map(fields, &operand/1),
        where_clause: where(opts)
      }
    }

    source = node_id(Keyword.get(opts, :source, @server_object))

    item = %Types.ReadValueId{
      node_id: source,
      attribute_id: OPCUA.AttributeId.id(:event_notifier)
    }

    create(client, [{{:events, fields}, item, parameters}], opts)
  end

  defp where(opts) do
    case {opts[:where], opts[:of_type]} do
      {nil, nil} ->
        nil

      {nil, type} ->
        literal = %Types.LiteralOperand{value: %Variant{type: :node_id, value: node_id(type)}}

        %Types.ContentFilter{
          elements: [
            %Types.ContentFilterElement{filter_operator: :of_type, filter_operands: [literal]}
          ]
        }

      {%Types.ContentFilter{} = where, _} ->
        where
    end
  end

  @doc """
  Acknowledges an alarm, given the `"ConditionId"` and `"EventId"` of its
  latest event, with an optional comment.
  """
  @spec acknowledge(client, node_ref, binary, String.t() | nil) :: :ok | error
  def acknowledge(client, condition, event_id, comment \\ nil) do
    args = [
      %Variant{type: :byte_string, value: event_id},
      %Variant{type: :localized_text, value: comment && %OPCUA.LocalizedText{text: comment}}
    ]

    # AcknowledgeableConditionType.Acknowledge
    with {:ok, _} <- call(client, condition, "i=9111", args), do: :ok
  end

  @doc """
  Asks the server to send the alarms that are active or unacknowledged again,
  to an event subscription (ConditionRefresh). They arrive between a
  RefreshStartEvent and a RefreshEndEvent.
  """
  @spec refresh(client, subscription) :: :ok | error
  def refresh(client, subscription) do
    # ConditionType.ConditionRefresh
    with {:ok, _} <-
           call(client, "i=2782", "i=3875", [%Variant{type: :uint32, value: subscription}]),
         do: :ok
  end

  defp operand("ConditionId") do
    %Types.SimpleAttributeOperand{
      type_definition_id: @condition_type,
      attribute_id: OPCUA.AttributeId.id(:node_id)
    }
  end

  # With BaseEventType as the type, the server resolves the path on whatever
  # event it has (Part 4, SimpleAttributeOperand).
  defp operand(path) do
    %Types.SimpleAttributeOperand{
      type_definition_id: @base_event_type,
      browse_path: path |> String.split("/") |> Enum.map(&qualified_name/1),
      attribute_id: OPCUA.AttributeId.id(:value)
    }
  end

  defp qualified_name(name) do
    case Integer.parse(name) do
      {ns, ":" <> name} -> %QualifiedName{ns: ns, name: name}
      _ -> %QualifiedName{ns: 0, name: name}
    end
  end

  defp create(client, items, opts) do
    pid = Keyword.get(opts, :to, self())
    interval = Keyword.get(opts, :interval, 1000)
    # A keep-alive at least every :keep_alive ms, and a lifetime six times that.
    keep_alive = max(1, ceil(Keyword.get(opts, :keep_alive, 10_000) / interval))

    request = %Types.CreateSubscriptionRequest{
      requested_publishing_interval: interval * 1.0,
      requested_lifetime_count: keep_alive * 6,
      requested_max_keep_alive_count: keep_alive,
      publishing_enabled: true
    }

    with {:ok, created} <- request(client, request) do
      sub = created.subscription_id
      # Registered before the items exist, so their first values aren't missed.
      handles = GenServer.call(client, {:register, created, pid, Enum.map(items, &elem(&1, 0))})

      creates =
        for {{_, item, parameters}, handle} <- Enum.zip(items, handles) do
          %Types.MonitoredItemCreateRequest{
            item_to_monitor: item,
            monitoring_mode: :reporting,
            requested_parameters: %{parameters | client_handle: handle}
          }
        end

      monitored = %Types.CreateMonitoredItemsRequest{
        subscription_id: sub,
        timestamps_to_return: :both,
        items_to_create: creates
      }

      case request(client, monitored) do
        {:ok, %{results: results}} ->
          failed =
            for {handle, %{status_code: status}} <- Enum.zip(handles, results),
                StatusCode.bad?(status),
                do: {handle, status}

          if failed != [], do: GenServer.cast(client, {:failed, sub, failed})
          {:ok, sub}

        error ->
          unsubscribe(client, sub)
          error
      end
    end
  end

  @doc "Deletes a subscription. The subscriber gets no more messages from it."
  @spec unsubscribe(client, subscription) :: :ok | error
  def unsubscribe(client, subscription) do
    :ok = GenServer.call(client, {:unregister, subscription})
    request = %Types.DeleteSubscriptionsRequest{subscription_ids: [subscription]}

    with {:ok, %{results: [status]}} <- request(client, request) do
      if StatusCode.bad?(status), do: {:error, status_name(status)}, else: :ok
    end
  end

  @doc """
  Sends any service request from `OPCUA.Types` and returns its response. The
  client fills in the request header.

  A response whose service result is Bad, or a ServiceFault, is
  `{:error, status}`.
  """
  @spec request(client, struct, timeout) :: {:ok, struct} | error
  def request(client, request, timeout \\ nil) do
    unless is_map_key(request, :request_header) do
      raise ArgumentError, "not a service request: #{inspect(request)}"
    end

    case GenServer.call(client, {:request, request, timeout}, :infinity) do
      # A value that doesn't fit its type raises here, not in the client.
      {:raise, exception} -> raise exception
      reply -> reply
    end
  end

  @doc """
  Asks a server for its endpoints, without opening a session: the security
  policies and login methods it offers.
  """
  @spec endpoints(String.t(), keyword) :: {:ok, [Types.EndpointDescription.t()]} | error
  def endpoints(url, opts \\ []) do
    timeout = Keyword.get(opts, :timeout, 5000)

    with {:ok, state} <- Connection.connect(url, timeout, 60_000) do
      case Connection.exchange(state, %Types.GetEndpointsRequest{endpoint_url: url}) do
        {:ok, %{endpoints: endpoints}, state} ->
          Connection.disconnect(state)
          {:ok, endpoints}

        error ->
          :gen_tcp.close(state.socket)
          error
      end
    end
  end

  defp node_id(%NodeId{} = node), do: node
  defp node_id(text) when is_binary(text), do: NodeId.parse!(text)

  ## The process

  @impl true
  def init(opts) do
    Process.flag(:trap_exit, true)
    url = Keyword.fetch!(opts, :url)
    timeout = Keyword.get(opts, :timeout, 5000)
    lifetime = Keyword.get(opts, :channel_lifetime, 3_600_000)

    with {:ok, state} <- Connection.connect(url, timeout, lifetime),
         {:ok, state} <- Connection.session(state, opts),
         # Chunks that came with the last handshake reply still go through the channel.
         {:noreply, state} <- chunks(state.chunks, %{state | chunks: []}) do
      :ok = :inet.setopts(state.socket, active: true)
      {:ok, state |> schedule_renew() |> schedule_keep_alive()}
    else
      {:error, reason} -> {:stop, reason}
      {:stop, reason, _} -> {:stop, reason}
    end
  end

  @impl true
  def handle_call({:request, request, timeout}, from, state) do
    timeout = timeout || state.timeout

    try do
      send_request(state, request, timeout, from, timeout)
    rescue
      exception in ArgumentError -> {:raise, exception}
    end
    |> case do
      {:ok, state} -> {:noreply, state}
      {:raise, exception} -> {:reply, {:raise, exception}, state}
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:type, node}, _from, state), do: {:reply, Map.get(state.types, node), state}

  def handle_call({:register, created, pid, keys}, _from, state) do
    sub = created.subscription_id
    first = state.next_handle + 1
    handles = Enum.to_list(first..(first + length(keys) - 1)//1)

    items =
      for {handle, key} <- Enum.zip(handles, keys), into: state.items, do: {handle, {sub, key}}

    subscription = %{
      pid: pid,
      monitor: Process.monitor(pid),
      handles: handles,
      keep_alive: created.revised_publishing_interval * created.revised_max_keep_alive_count
    }

    state = %{
      state
      | subscriptions: Map.put(state.subscriptions, sub, subscription),
        items: items,
        next_handle: first + length(keys) - 1
    }

    {:reply, handles, publish(state)}
  end

  def handle_call({:unregister, sub}, _from, state), do: {:reply, :ok, drop(state, sub)}

  @impl true
  def handle_cast({:type, node, type}, state),
    do: {:noreply, %{state | types: Map.put(state.types, node, type)}}

  def handle_cast({:failed, sub, failed}, state) do
    case state.subscriptions do
      %{^sub => %{pid: pid}} ->
        items =
          Enum.reduce(failed, state.items, fn {handle, status}, items ->
            case Map.pop(items, handle) do
              {{^sub, {:value, node}}, items} ->
                send(pid, {__MODULE__, sub, {:value, node, %DataValue{status: status}}})
                items

              {{^sub, {:events, _}}, items} ->
                send(pid, {__MODULE__, sub, {:status, status_name(status)}})
                items

              {_, items} ->
                items
            end
          end)

        {:noreply, %{state | items: items}}

      _ ->
        {:noreply, state}
    end
  end

  @impl true
  def handle_info({:tcp, _, data}, state) do
    case Transport.split(state.buffer <> data, Connection.receive_buffer()) do
      {:ok, chunks, rest} -> chunks(chunks, %{state | buffer: rest})
      {:error, reason} -> {:stop, {:shutdown, reason}, state}
    end
  end

  def handle_info({:tcp_closed, _}, state),
    do: {:stop, {:shutdown, :bad_connection_closed}, state}

  def handle_info({:tcp_error, _, reason}, state), do: {:stop, {:shutdown, reason}, state}

  def handle_info({:timeout, id}, state),
    do: {:noreply, respond(state, id, {:error, :bad_timeout})}

  def handle_info(:keep_alive, state) do
    read = %Types.ReadValueId{
      node_id: %NodeId{id: @keep_alive},
      attribute_id: OPCUA.AttributeId.id(:value)
    }

    request = %Types.ReadRequest{nodes_to_read: [read]}

    case send_request(state, request, state.timeout, :keep_alive, state.timeout) do
      {:ok, state} -> {:noreply, schedule_keep_alive(state)}
      {:error, reason} -> {:stop, {:shutdown, reason}, state}
    end
  end

  def handle_info(:renew, state) do
    {id, channel} = SecureChannel.next_request_id(state.channel)
    request = Connection.open_request(state, :renew)

    case send_message(%{state | channel: channel}, :open, id, request) do
      {:ok, state} -> {:noreply, put_pending(state, id, :renew, nil)}
      {:error, reason} -> {:stop, {:shutdown, reason}, state}
    end
  end

  def handle_info({:DOWN, ref, :process, _, _}, state) do
    case Enum.find(state.subscriptions, fn {_, s} -> s.monitor == ref end) do
      {sub, _} ->
        state = drop(state, sub)
        request = %Types.DeleteSubscriptionsRequest{subscription_ids: [sub]}

        case send_request(state, request, state.timeout, :ignore, state.timeout) do
          {:ok, state} -> {:noreply, state}
          {:error, reason} -> {:stop, {:shutdown, reason}, state}
        end

      nil ->
        {:noreply, state}
    end
  end

  def handle_info({:session_lost, status}, state), do: {:stop, {:shutdown, status}, state}
  def handle_info({:EXIT, _, reason}, state), do: {:stop, reason, state}

  defp chunks(chunks, state), do: Enum.reduce_while(chunks, {:noreply, state}, &chunk/2)

  defp chunk({:error, _, body}, {:noreply, state}) do
    {:halt, {:stop, {:shutdown, Connection.remote_error(body)}, state}}
  end

  defp chunk(chunk, {:noreply, state}) do
    case SecureChannel.receive(state.channel, chunk) do
      {:ok, channel} ->
        {:cont, {:noreply, %{state | channel: channel}}}

      {:ok, {_kind, id, response}, channel} ->
        {:cont, {:noreply, respond(%{state | channel: channel}, id, {:ok, response})}}

      {:abort, id, status, _reason, channel} ->
        {:cont,
         {:noreply, respond(%{state | channel: channel}, id, {:error, status_name(status)})}}

      {:error, reason} ->
        {:halt, {:stop, {:shutdown, reason}, state}}
    end
  end

  # A response, or a timeout, for a request we sent.
  defp respond(state, id, reply) do
    case Map.pop(state.pending, id) do
      {nil, _} ->
        state

      {{tag, timer}, pending} ->
        if timer, do: Process.cancel_timer(timer)
        reply = with {:ok, response} <- reply, do: result(response)
        handle_reply(%{state | pending: pending}, tag, reply)
    end
  end

  defp handle_reply(state, :renew, {:ok, %Types.OpenSecureChannelResponse{security_token: token}}) do
    schedule_renew(%{state | channel: SecureChannel.token(state.channel, token), token: token})
  end

  defp handle_reply(state, :renew, reply) do
    Logger.warning("OPC UA secure channel renewal failed: #{inspect(reply)}")
    state
  end

  defp handle_reply(state, :keep_alive, {:error, status}) when status in @session_lost do
    send(self(), {:session_lost, status})
    state
  end

  defp handle_reply(state, :publish, reply) do
    state = %{state | publishing: state.publishing - 1}

    case reply do
      {:ok, response} ->
        state |> published(response) |> publish()

      {:error, :bad_no_subscription} ->
        state

      {:error, :bad_too_many_publish_requests} ->
        %{state | publish_target: max(1, state.publishing)}

      {:error, status} when status in @session_lost ->
        send(self(), {:session_lost, status})
        state

      {:error, _} ->
        publish(state)
    end
  end

  defp handle_reply(state, tag, _) when tag in [:keep_alive, :ignore], do: state

  defp handle_reply(state, from, reply) do
    GenServer.reply(from, reply)
    state
  end

  # Keeps a few publish requests at the server while there are subscriptions,
  # so it always has one to answer with notifications.
  defp publish(%{subscriptions: subs} = state) when map_size(subs) == 0, do: state
  defp publish(%{publishing: n, publish_target: target} = state) when n >= target, do: state

  defp publish(state) do
    # The server answers at least every keep-alive period, with nothing if it must.
    keep_alive = state.subscriptions |> Map.values() |> Enum.map(& &1.keep_alive) |> Enum.max()
    hint = trunc(keep_alive * 2)
    request = %Types.PublishRequest{subscription_acknowledgements: Enum.reverse(state.acks)}

    case send_request(%{state | acks: []}, request, hint, :publish, hint + state.timeout) do
      {:ok, state} -> publish(%{state | publishing: state.publishing + 1})
      {:error, _} -> state
    end
  end

  defp published(state, %Types.PublishResponse{
         subscription_id: sub,
         notification_message: message
       }) do
    notifications = message.notification_data || []

    state =
      if notifications == [],
        do: state,
        else: %{
          state
          | acks: [
              %Types.SubscriptionAcknowledgement{
                subscription_id: sub,
                sequence_number: message.sequence_number
              }
              | state.acks
            ]
        }

    case state.subscriptions do
      %{^sub => %{pid: pid}} -> Enum.reduce(notifications, state, &notify(&2, pid, sub, &1))
      _ -> state
    end
  end

  defp notify(state, pid, sub, %Types.DataChangeNotification{monitored_items: items}) do
    for %{client_handle: handle, value: value} <- items || [],
        {^sub, {:value, node}} <- [state.items[handle]],
        do: send(pid, {__MODULE__, sub, {:value, node, value}})

    state
  end

  defp notify(state, pid, sub, %Types.EventNotificationList{events: events}) do
    for %{client_handle: handle, event_fields: fields} <- events || [],
        {^sub, {:events, names}} <- [state.items[handle]] do
      event = names |> Enum.zip(Enum.map(fields || [], &unwrap/1)) |> Map.new()
      send(pid, {__MODULE__, sub, {:event, event}})
    end

    state
  end

  defp notify(state, pid, sub, %Types.StatusChangeNotification{status: status}) do
    send(pid, {__MODULE__, sub, {:status, status_name(status)}})
    if StatusCode.bad?(status), do: drop(state, sub), else: state
  end

  defp notify(state, _, _, _), do: state

  defp drop(state, sub) do
    case Map.pop(state.subscriptions, sub) do
      {nil, _} ->
        state

      {subscription, subscriptions} ->
        Process.demonitor(subscription.monitor, [:flush])

        %{
          state
          | subscriptions: subscriptions,
            items: Map.drop(state.items, subscription.handles)
        }
    end
  end

  # Sends a request and remembers what to do with its response: reply to a
  # caller (`tag` is its `from`), or handle it here.
  defp send_request(state, request, hint, tag, timeout) do
    {id, channel} = SecureChannel.next_request_id(state.channel)
    {request, state} = with_header(%{state | channel: channel}, request, hint)

    with {:ok, state} <- send_message(state, :message, id, request) do
      {:ok, put_pending(state, id, tag, Process.send_after(self(), {:timeout, id}, timeout))}
    end
  end

  defp put_pending(state, id, tag, timer),
    do: %{state | pending: Map.put(state.pending, id, {tag, timer})}

  defp send_message(state, kind, id, message) do
    with {:ok, frames, channel} <- SecureChannel.encode(state.channel, kind, id, message),
         :ok <- :gen_tcp.send(state.socket, frames) do
      {:ok, %{state | channel: channel}}
    else
      {:error, :closed} -> {:error, :bad_connection_closed}
      error -> error
    end
  end

  # Renew at 75% of the token's lifetime, as the spec recommends.
  defp schedule_renew(state) do
    Process.send_after(self(), :renew, trunc(state.token.revised_lifetime * 0.75))
    state
  end

  defp schedule_keep_alive(state) do
    Process.send_after(self(), :keep_alive, trunc(state.session_timeout / 3))
    state
  end

  @impl true
  def terminate(reason, state) do
    for {_, {from, _}} <- state.pending,
        is_tuple(from),
        do: GenServer.reply(from, {:error, :bad_connection_closed})

    # {:shutdown, reason} means the connection is already broken.
    if reason in [:normal, :shutdown], do: close_session(state)

    :gen_tcp.close(state.socket)
  end

  defp close_session(state) do
    {id, channel} = SecureChannel.next_request_id(state.channel)

    {request, state} =
      with_header(
        %{state | channel: channel},
        %Types.CloseSessionRequest{delete_subscriptions: true},
        state.timeout
      )

    with {:ok, state} <- send_message(state, :message, id, request) do
      # Give the server a moment to answer before the channel goes away.
      receive do
        {:tcp, _, _} -> :ok
      after
        1000 -> :ok
      end

      Connection.disconnect(state)
    end
  end
end
