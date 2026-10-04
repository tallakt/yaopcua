defmodule OPCUA.Server.Conditions do
  @moduledoc false
  # Alarms (Part 9): each condition is an object in the address space, with
  # its state kept next to the variable values under {:condition, node_id}.
  # Its children (ActiveState, AckedState, ...) read that state, and every
  # change produces an event carrying the whole state, which is what alarm
  # clients mostly look at.
  #
  # A condition is retained, and reported by ConditionRefresh, while it's
  # enabled and either active or not yet acknowledged. A disabled one
  # reports no events, but the one saying it's disabled, until it's enabled
  # again (Part 9, 4.4).
  #
  # Suppression is the application's: it sets `suppressed:`, which
  # SuppressedState and SuppressedOrShelved show.
  #
  # Not supported: Confirm, shelving, silencing, latching, branches, the
  # fields of specific alarm types (such as limits), and Acknowledge method
  # nodes on each condition; clients call the type's.

  alias OPCUA.{LocalizedText, NodeId, NodeIds, QualifiedName, Variant}
  alias OPCUA.Server.{AddressSpace, Events, Node}
  alias OPCUA.Types

  @has_condition NodeIds.node_id!("HasCondition")
  @has_component NodeIds.node_id!("HasComponent")
  @has_property NodeIds.node_id!("HasProperty")
  @two_state_variable NodeIds.node_id!("TwoStateVariableType")
  @property NodeIds.node_id!("PropertyType")
  @base_condition_class NodeIds.node_id!("BaseConditionClassType")
  @refresh_start NodeIds.node_id!("RefreshStartEventType")
  @refresh_end NodeIds.node_id!("RefreshEndEventType")
  @server NodeIds.node_id!("Server")

  @types %{
    off_normal: NodeIds.node_id!("OffNormalAlarmType"),
    alarm: NodeIds.node_id!("AlarmConditionType"),
    discrete: NodeIds.node_id!("DiscreteAlarmType")
  }

  # The TwoStateVariables of a condition: the state they show, and what they
  # say when it's true and false.
  @two_states [
    {"EnabledState", :enabled, "Enabled", "Disabled"},
    {"ActiveState", :active, "Active", "Inactive"},
    {"AckedState", :acked, "Acknowledged", "Unacknowledged"},
    {"SuppressedState", :suppressed, "Suppressed", "Unsuppressed"}
  ]

  @doc false
  def add(space, %NodeId{} = id, name, opts) do
    source = Keyword.fetch!(opts, :source)
    type = Keyword.get(opts, :type, :off_normal)
    type = Map.get(@types, type, type)

    node = %Node{
      node_id: id,
      class: :object,
      browse_name: %QualifiedName{ns: id.ns, name: name},
      display_name: %LocalizedText{text: name},
      attributes: %{event_notifier: 0}
    }

    severity = Keyword.get(opts, :severity, 500)

    state = %{
      id: id,
      name: name,
      type: type,
      source: source,
      enabled: true,
      active: false,
      acked: true,
      suppressed: false,
      severity: severity,
      last_severity: severity,
      message: Keyword.get(opts, :message, name),
      comment: nil,
      user: nil,
      event_id: nil,
      acknowledge: Keyword.get(opts, :acknowledge),
      enable: Keyword.get(opts, :enable)
    }

    with %Node{} = source_node <-
           AddressSpace.get(space, source) || {:error, :bad_parent_node_id_invalid},
         :ok <- AddressSpace.add(space, node, nil, source, @has_condition, type) do
      # The source reports its conditions' events.
      if source_node.class == :object, do: AddressSpace.notify_events(space, source)

      put(space, state)
      _ = children(space, id)
      :ok
    end
  end

  # Readable children, for clients that look at the condition itself. Each
  # reads the condition's state with `read`.
  defp children(space, id) do
    for {name, key, yes, no} <- @two_states do
      node = child(space, id, id, {name, :two_state, :localized_text, &text(&1[key], yes, no)})
      _ = child(space, id, node, {"Id", :property, :boolean, & &1[key]})
    end

    properties = [
      {"Retain", :boolean, &retain?/1},
      {"Severity", :uint16, & &1.severity},
      {"Message", :localized_text, &%LocalizedText{text: &1.message}},
      {"Comment", :localized_text, &(&1.comment && %LocalizedText{text: &1.comment})}
    ]

    for {name, type, read} <- properties,
        do: child(space, id, id, {name, :property, type, read})
  end

  defp text(on, yes, no), do: %LocalizedText{locale: "en", text: if(on, do: yes, else: no)}

  defp child(space, id, parent, {name, kind, type, read}) do
    child_id = %NodeId{ns: parent.ns, id: label(parent) <> "." <> name}

    {reference, type_definition} =
      case kind do
        :two_state -> {@has_component, @two_state_variable}
        :property -> {@has_property, @property}
      end

    node = %Node{
      node_id: child_id,
      class: :variable,
      browse_name: %QualifiedName{ns: 0, name: name},
      display_name: %LocalizedText{text: name},
      attributes: %{
        data_type: %NodeId{id: OPCUA.Binary.type_id(type)},
        value_rank: -1,
        array_dimensions: nil,
        access_level: Types.AccessLevelType.mask([:current_read]),
        user_access_level: Types.AccessLevelType.mask([:current_read]),
        minimum_sampling_interval: 0.0,
        historizing: false
      }
    }

    :ok =
      AddressSpace.add(
        space,
        node,
        {:read, fn -> read.(state(space, id)) end, type},
        parent,
        reference,
        type_definition
      )

    child_id
  end

  defp label(%NodeId{id: id}) when is_binary(id), do: id
  defp label(%NodeId{id: id}), do: inspect(id)

  @doc false
  def state(space, id) do
    case :ets.lookup(space.values, {:condition, id}) do
      [{_, state}] -> state
      [] -> nil
    end
  end

  defp put(space, state), do: :ets.insert(space.values, {{:condition, state.id}, state})

  @doc false
  def retain?(state), do: state.enabled and (state.active or not state.acked)

  @doc false
  # Applies changes from the application or a client. Returns the event
  # announcing them, or :unchanged.
  def update(space, id, changes) do
    case state(space, id) do
      nil ->
        {:error, :bad_node_id_unknown}

      old ->
        new = changed(old, Map.new(changes))

        cond do
          new == old ->
            :unchanged

          # Kept quietly, and reported when the condition is enabled again.
          not old.enabled and not new.enabled ->
            put(space, new)
            :unchanged

          true ->
            event = event(space, new)
            put(space, %{new | event_id: Events.id(event)})
            {:ok, event}
        end
    end
  end

  # A condition that becomes active needs acknowledging, unless told otherwise.
  defp changed(old, changes) do
    changes =
      if changes[:active] == true and not old.active,
        do: Map.put_new(changes, :acked, false),
        else: changes

    changed = [:enabled, :active, :acked, :suppressed, :severity, :message, :comment, :user]
    new = Map.merge(old, Map.take(changes, changed))
    if new.severity != old.severity, do: %{new | last_severity: old.severity}, else: new
  end

  @doc false
  # Checks an Acknowledge from a client, before the application hears of it.
  def acknowledgeable(space, id, event_id) do
    case state(space, id) do
      nil -> {:error, :bad_node_id_unknown}
      %{enabled: false} -> {:error, :bad_condition_disabled}
      %{event_id: ^event_id, acked: true} -> {:error, :bad_condition_branch_already_acked}
      %{event_id: ^event_id} = state -> {:ok, state}
      _ -> {:error, :bad_event_id_unknown}
    end
  end

  @doc false
  # The event that announces a condition's state.
  def event(space, state, event_id \\ nil) do
    two_states =
      for {name, key, yes, no} <- @two_states,
          field <- [
            {name, %Variant{type: :localized_text, value: text(state[key], yes, no)}},
            {name <> "/Id", %Variant{type: :boolean, value: state[key]}}
          ],
          do: field

    fields =
      [
        {"ConditionClassId", %Variant{type: :node_id, value: @base_condition_class}},
        {"ConditionClassName",
         %Variant{type: :localized_text, value: %LocalizedText{text: "BaseConditionClass"}}},
        {"ConditionName", %Variant{type: :string, value: state.name}},
        {"BranchId", %Variant{type: :node_id, value: nil}},
        {"Retain", %Variant{type: :boolean, value: retain?(state)}},
        {"Quality", %Variant{type: :status_code, value: 0}},
        {"LastSeverity", %Variant{type: :uint16, value: state.last_severity}},
        {"Comment",
         %Variant{
           type: :localized_text,
           value: state.comment && %LocalizedText{text: state.comment}
         }},
        {"ClientUserId", %Variant{type: :string, value: state.user}},
        {"SuppressedOrShelved", %Variant{type: :boolean, value: state.suppressed}}
      ] ++ two_states

    event = Events.new(space, state.type, state.source, state.message, state.severity, fields)
    event = %{event | condition: state.id}

    # A refresh repeats the last event, with its EventId.
    if event_id,
      do:
        put_in(event.fields[Events.path("EventId")], %Variant{type: :byte_string, value: event_id}),
      else: event
  end

  @doc false
  # What ConditionRefresh sends: a start marker, the last event of every
  # retained condition, and an end marker.
  def refresh(space) do
    retained =
      for {{:condition, _}, state} <- :ets.match_object(space.values, {{:condition, :_}, :_}),
          retain?(state),
          do: event(space, state, state.event_id)

    [marker(space, @refresh_start)] ++ retained ++ [marker(space, @refresh_end)]
  end

  defp marker(space, type), do: Events.new(space, type, @server, nil, 100)

  @doc false
  def marker?(%{type: type}), do: type in [@refresh_start, @refresh_end]
end
