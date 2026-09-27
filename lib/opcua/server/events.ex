defmodule OPCUA.Server.Events do
  @moduledoc false
  # Events inside the server (Part 4, 7.22.3, and Part 5, BaseEventType).
  #
  # An event is a map of its type, its source, the condition it belongs to
  # (if any), and its fields, each under its browse path from the event:
  #
  #     %{type: %NodeId{id: 2041}, source: node_id, condition: nil,
  #       fields: %{[%QualifiedName{name: "Message"}] => %Variant{...}, ...}}
  #
  # A client's EventFilter picks fields with select clauses and events with a
  # where clause; both are evaluated here.

  alias OPCUA.{LocalizedText, NodeId, QualifiedName, StatusCode, Variant}
  alias OPCUA.Server.AddressSpace
  alias OPCUA.Types

  @base_event_type %NodeId{id: 2041}
  @condition_type %NodeId{id: 2782}
  @server %NodeId{id: 2253}
  @has_event_source %NodeId{id: 36}
  @has_notifier %NodeId{id: 48}

  @operators [
    :equals,
    :is_null,
    :greater_than,
    :less_than,
    :greater_than_or_equal,
    :less_than_or_equal,
    :not,
    :between,
    :in_list,
    :and,
    :or,
    :of_type
  ]

  @doc false
  # A new event with the fields every event has. `fields` adds or replaces
  # fields by path, such as `"Severity"` or `"ActiveState/Id"`.
  def new(space, type, source, message, severity, fields \\ []) do
    now = DateTime.utc_now()
    source_name = if node = AddressSpace.get(space, source), do: node.browse_name.name

    base = [
      {"EventId", %Variant{type: :byte_string, value: :crypto.strong_rand_bytes(16)}},
      {"EventType", %Variant{type: :node_id, value: type}},
      {"SourceNode", %Variant{type: :node_id, value: source}},
      {"SourceName", %Variant{type: :string, value: source_name}},
      {"Time", %Variant{type: :date_time, value: now}},
      {"ReceiveTime", %Variant{type: :date_time, value: now}},
      {"Message", %Variant{type: :localized_text, value: text(message)}},
      {"Severity", %Variant{type: :uint16, value: severity}}
    ]

    %{
      type: type,
      source: source,
      condition: nil,
      fields: Map.new(base ++ fields, fn {path, value} -> {path(path), value} end)
    }
  end

  defp text(%LocalizedText{} = text), do: text
  defp text(nil), do: nil
  defp text(message), do: %LocalizedText{text: message}

  @doc false
  # "ActiveState/Id" as a browse path.
  def path(path) when is_list(path), do: path

  def path(path) do
    for name <- String.split(path, "/") do
      case Integer.parse(name) do
        {ns, ":" <> name} -> %QualifiedName{ns: ns, name: name}
        _ -> %QualifiedName{ns: 0, name: name}
      end
    end
  end

  @doc false
  # The event's EventId.
  def id(event), do: event.fields[path("EventId")].value

  @doc false
  # Whether a monitored item on `notifier` reports this event: the Server
  # object reports all of them, and a node reports the events of its own and
  # of the sources below it.
  def reported_by?(_event, @server, _space), do: true
  def reported_by?(%{source: source}, source, _space), do: true
  def reported_by?(event, notifier, space), do: below?(space, event.source, notifier, 8)

  defp below?(_, _, _, 0), do: false

  defp below?(space, node_id, notifier, depth) do
    case AddressSpace.get(space, node_id) do
      nil ->
        false

      node ->
        parents =
          for {type, parent, false} <- node.references,
              type in [@has_event_source, @has_notifier],
              do: parent

        notifier in parents or Enum.any?(parents, &below?(space, &1, notifier, depth - 1))
    end
  end

  ## Filters

  @doc false
  # Checks an EventFilter when a monitored item is made: every select clause
  # must name a field from an event type, and the where clause may only use
  # the operators implemented here.
  def check(%Types.EventFilter{} = filter, space) do
    selects =
      for clause <- filter.select_clauses || [] do
        if event_type?(space, clause.type_definition_id),
          do: 0,
          else: StatusCode.code(:bad_type_definition_invalid)
      end

    elements = (filter.where_clause && filter.where_clause.elements) || []

    wheres =
      for element <- elements do
        code =
          if element.filter_operator in @operators,
            do: 0,
            else: StatusCode.code(:bad_filter_operator_unsupported)

        %Types.ContentFilterElementResult{status_code: code}
      end

    result = %Types.EventFilterResult{
      select_clause_results: selects,
      where_clause_result: %Types.ContentFilterResult{element_results: wheres}
    }

    cond do
      selects == [] ->
        {:error, :bad_event_filter_invalid, result}

      Enum.any?(wheres, &(&1.status_code != 0)) ->
        {:error, :bad_monitored_item_filter_unsupported, result}

      true ->
        {:ok, result}
    end
  end

  def check(_, _), do: {:error, :bad_event_filter_invalid, nil}

  defp event_type?(_, nil), do: true
  defp event_type?(space, type), do: AddressSpace.subtype?(space, type, @base_event_type)

  @doc false
  # The fields a filter selects from an event, or nil if its where clause
  # leaves the event out.
  def filter(event, %Types.EventFilter{} = filter, space) do
    if where?(event, filter.where_clause, space),
      do: Enum.map(filter.select_clauses || [], &select(event, &1, space))
  end

  @doc false
  # The fields a filter selects, whatever its where clause says.
  def select(event, %Types.EventFilter{} = filter, space),
    do: Enum.map(filter.select_clauses || [], &select(event, &1, space))

  def select(event, %Types.SimpleAttributeOperand{} = operand, space) do
    cond do
      # ConditionId: the condition's node id, asked for with an empty path.
      operand.type_definition_id == @condition_type and operand.browse_path in [nil, []] ->
        if event.condition, do: %Variant{type: :node_id, value: event.condition}

      # A field of a type this event isn't doesn't apply to it.
      operand.type_definition_id not in [nil, @base_event_type] and
          not AddressSpace.subtype?(space, event.type, operand.type_definition_id) ->
        nil

      true ->
        event.fields[operand.browse_path || []]
    end
  end

  def select(_, _, _), do: nil

  defp where?(_, nil, _), do: true
  defp where?(_, %Types.ContentFilter{elements: elements}, _) when elements in [nil, []], do: true

  defp where?(event, %Types.ContentFilter{elements: elements}, space),
    do: evaluate(elements, 0, event, space) == true

  defp evaluate(elements, index, event, space) do
    %Types.ContentFilterElement{filter_operator: operator, filter_operands: operands} =
      Enum.at(elements, index)

    value = &operand(&1, elements, event, space)
    operands = operands || []

    case {operator, operands} do
      {:of_type, [%Types.LiteralOperand{value: %Variant{value: type}}]} ->
        AddressSpace.subtype?(space, event.type, type)

      {:is_null, [a]} ->
        value.(a) == nil

      {:not, [a]} ->
        value.(a) == false

      {:and, [a, b]} ->
        value.(a) == true and value.(b) == true

      {:or, [a, b]} ->
        value.(a) == true or value.(b) == true

      {:equals, [a, b]} ->
        equal?(value.(a), value.(b))

      {:greater_than, [a, b]} ->
        compare(value.(a), value.(b)) == :gt

      {:less_than, [a, b]} ->
        compare(value.(a), value.(b)) == :lt

      {:greater_than_or_equal, [a, b]} ->
        compare(value.(a), value.(b)) in [:gt, :eq]

      {:less_than_or_equal, [a, b]} ->
        compare(value.(a), value.(b)) in [:lt, :eq]

      {:between, [a, low, high]} ->
        compare(value.(a), value.(low)) in [:gt, :eq] and
          compare(value.(a), value.(high)) in [:lt, :eq]

      {:in_list, [a | list]} ->
        Enum.any?(list, &equal?(value.(a), value.(&1)))

      _ ->
        false
    end
  end

  defp operand(%Types.LiteralOperand{value: variant}, _, _, _), do: unwrap(variant)

  defp operand(%Types.SimpleAttributeOperand{} = operand, _, event, space),
    do: event |> select(operand, space) |> unwrap()

  defp operand(%Types.ElementOperand{index: index}, elements, event, space),
    do: evaluate(elements, index, event, space)

  defp operand(_, _, _, _), do: nil

  defp unwrap(nil), do: nil
  defp unwrap(%Variant{value: value}), do: value

  defp equal?(a, b) when is_number(a) and is_number(b), do: a == b
  defp equal?(a, b), do: a == b and a != nil

  defp compare(a, b) when is_number(a) and is_number(b),
    do: if(a > b, do: :gt, else: if(a < b, do: :lt, else: :eq))

  defp compare(%DateTime{} = a, %DateTime{} = b), do: DateTime.compare(a, b)

  defp compare(a, b) when is_binary(a) and is_binary(b),
    do: if(a > b, do: :gt, else: if(a < b, do: :lt, else: :eq))

  defp compare(_, _), do: nil
end
