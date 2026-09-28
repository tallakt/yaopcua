defmodule OPCUA.Server.Conditions do
  @moduledoc false
  # Alarms (Part 9): each condition is an object in the address space, with
  # its state kept next to the variable values under {:condition, node_id}.
  # Its children (ActiveState, AckedState, ...) read that state, and every
  # change produces an event carrying the whole state, which is what alarm
  # clients mostly look at.
  #
  # A condition is retained, and reported by ConditionRefresh, while it's
  # enabled and either active or not yet acknowledged.
  #
  # Not supported: Confirm, shelving, suppression, silencing, latching,
  # branches, the fields of specific alarm types (such as limits), and
  # Acknowledge method nodes on each condition; clients call the type's.

  alias OPCUA.{LocalizedText, NodeId, QualifiedName, StatusCode, Variant}
  alias OPCUA.Server.{AddressSpace, Events, Node}

  @has_condition %NodeId{id: 9006}
  @has_component %NodeId{id: 47}
  @has_property %NodeId{id: 46}
  @two_state_variable %NodeId{id: 8995}
  @property %NodeId{id: 68}
  @base_condition_class %NodeId{id: 11163}
  @refresh_start %NodeId{id: 2787}
  @refresh_end %NodeId{id: 2788}
  @server %NodeId{id: 2253}

  @types %{off_normal: %NodeId{id: 10637}, alarm: %NodeId{id: 2915}, discrete: %NodeId{id: 10523}}

  @doc false
  def add(space, %NodeId{} = id, name, opts) do
    source = Keyword.fetch!(opts, :source)
    type = Map.get(@types, Keyword.get(opts, :type, :off_normal), Keyword.get(opts, :type))

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
      severity: severity,
      last_severity: severity,
      message: Keyword.get(opts, :message, name),
      comment: nil,
      user: nil,
      event_id: nil,
      acknowledge: Keyword.get(opts, :acknowledge)
    }

    with %Node{} = source_node <-
           AddressSpace.get(space, source) || {:error, :bad_parent_node_id_invalid},
         :ok <- AddressSpace.add(space, node, nil, source, @has_condition, type) do
      # The source reports its conditions' events.
      if source_node.class == :object do
        notifier = Bitwise.bor(source_node.attributes[:event_notifier] || 0, 1)

        :ets.insert(
          space.nodes,
          {source, put_in(AddressSpace.get(space, source).attributes[:event_notifier], notifier)}
        )
      end

      put(space, state)
      children(space, id)
      :ok
    end
  end

  # Readable children, for clients that look at the condition itself.
  defp children(space, id) do
    two_states = [
      {"EnabledState", :enabled, "Enabled", "Disabled"},
      {"ActiveState", :active, "Active", "Inactive"},
      {"AckedState", :acked, "Acknowledged", "Unacknowledged"}
    ]

    for {name, key, yes, no} <- two_states do
      node =
        child(space, id, id, name, @has_component, @two_state_variable, :localized_text, fn s ->
          %LocalizedText{locale: "en", text: if(s[key], do: yes, else: no)}
        end)

      child(space, id, node, "Id", @has_property, @property, :boolean, & &1[key])
    end

    child(space, id, id, "Retain", @has_property, @property, :boolean, &retain?/1)
    child(space, id, id, "Severity", @has_property, @property, :uint16, & &1.severity)

    child(
      space,
      id,
      id,
      "Message",
      @has_property,
      @property,
      :localized_text,
      &%LocalizedText{text: &1.message}
    )

    child(
      space,
      id,
      id,
      "Comment",
      @has_property,
      @property,
      :localized_text,
      &(&1.comment && %LocalizedText{text: &1.comment})
    )
  end

  defp child(space, id, parent, name, reference, type_definition, type, read) do
    child_id = %NodeId{ns: parent.ns, id: label(parent) <> "." <> name}

    node = %Node{
      node_id: child_id,
      class: :variable,
      browse_name: %QualifiedName{ns: 0, name: name},
      display_name: %LocalizedText{text: name},
      attributes: %{
        data_type: %NodeId{id: OPCUA.Binary.type_id(type)},
        value_rank: -1,
        array_dimensions: nil,
        access_level: 1,
        user_access_level: 1,
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
        changes = Map.new(changes)
        # A condition that becomes active needs acknowledging, unless told otherwise.
        changes =
          if changes[:active] == true and not old.active,
            do: Map.put_new(changes, :acked, false),
            else: changes

        new =
          Map.merge(
            old,
            Map.take(changes, [:enabled, :active, :acked, :severity, :message, :comment, :user])
          )

        new = if new.severity != old.severity, do: %{new | last_severity: old.severity}, else: new

        if new == old do
          :unchanged
        else
          event = event(space, new)
          put(space, %{new | event_id: Events.id(event)})
          {:ok, event}
        end
    end
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
    two_state = fn name, on, yes, no ->
      [
        {name,
         %Variant{
           type: :localized_text,
           value: %LocalizedText{locale: "en", text: if(on, do: yes, else: no)}
         }},
        {name <> "/Id", %Variant{type: :boolean, value: on}}
      ]
    end

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
        {"SuppressedOrShelved", %Variant{type: :boolean, value: false}}
      ] ++
        two_state.("EnabledState", state.enabled, "Enabled", "Disabled") ++
        two_state.("ActiveState", state.active, "Active", "Inactive") ++
        two_state.("AckedState", state.acked, "Acknowledged", "Unacknowledged")

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

  @doc false
  def status(status), do: StatusCode.code(status)
end
