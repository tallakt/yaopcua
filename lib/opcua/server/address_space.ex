defmodule OPCUA.Server.AddressSpace do
  @moduledoc false
  # A server's nodes in two ETS tables: the nodes, and the values of the
  # variables, so a value can change without rewriting its node. The tables
  # are public: connections read them directly, and the application sets
  # values without going through the server process.
  #
  # A value is an OPCUA.DataValue, or `{:read, fun, type}` for a variable
  # whose value comes from a function each time it's read.

  require Logger

  alias OPCUA.{Binary, DataValue, ExpandedNodeId, NodeId, NodeIds, QualifiedName, Variant}
  alias OPCUA.Server.Node
  alias OPCUA.Types

  defstruct [:nodes, :values]

  @type t :: %__MODULE__{nodes: :ets.tid(), values: :ets.tid()}

  @has_subtype NodeIds.node_id!("HasSubtype")
  @has_property NodeIds.node_id!("HasProperty")
  @has_type_definition NodeIds.node_id!("HasTypeDefinition")
  @hierarchical NodeIds.node_id!("HierarchicalReferences")

  # Abstract data types, whose values are of any of their subtypes.
  @number NodeIds.node_id!("Number")
  @integer NodeIds.node_id!("Integer")
  @unsigned NodeIds.node_id!("UInteger")
  @enumeration NodeIds.node_id!("Enumeration")

  @current_read Types.AccessLevelType.mask([:current_read])
  @current_write Types.AccessLevelType.mask([:current_write])
  @subscribe_to_events Types.EventNotifierType.mask([:subscribe_to_events])

  @classes %{
    object: 1,
    variable: 2,
    method: 4,
    object_type: 8,
    variable_type: 16,
    reference_type: 32,
    data_type: 64,
    view: 128
  }

  @doc false
  def new do
    space = %__MODULE__{
      nodes: :ets.new(:opcua_nodes, [:public, read_concurrency: true]),
      values: :ets.new(:opcua_values, [:public, read_concurrency: true])
    }

    for {node, value} <- OPCUA.Server.Namespace0.nodes() do
      :ets.insert(space.nodes, {node.node_id, node})
      if value, do: :ets.insert(space.values, {node.node_id, %DataValue{value: value}})
    end

    space
  end

  @doc false
  def get(space, node_id) do
    case :ets.lookup(space.nodes, node_id) do
      [{_, node}] -> node
      [] -> nil
    end
  end

  @doc false
  # Adds a node, with a reference from its parent, and its type definition.
  def add(space, %Node{} = node, value, parent, reference_type, type_definition) do
    cond do
      get(space, node.node_id) ->
        {:error, :bad_node_id_exists}

      get(space, parent) == nil ->
        {:error, :bad_parent_node_id_invalid}

      true ->
        refs = [
          {reference_type, parent, false}
          | if(type_definition, do: [{@has_type_definition, type_definition, true}], else: [])
        ]

        :ets.insert(space.nodes, {node.node_id, %{node | references: refs ++ node.references}})
        if value, do: :ets.insert(space.values, {node.node_id, value})
        # The inverse HasTypeDefinition on the type is left out: a type used
        # by thousands of variables would be rewritten for each one.
        link(space, parent, {reference_type, node.node_id, true})
        :ok
    end
  end

  defp link(space, node_id, ref),
    do: update(space, node_id, &%{&1 | references: &1.references ++ [ref]})

  @doc false
  # Changes a node. Only the server process changes nodes, so nothing else
  # changes it in between.
  def update(space, node_id, fun),
    do: :ets.insert(space.nodes, {node_id, fun.(get(space, node_id))})

  @doc false
  # Makes an object report events, so that clients can subscribe to them.
  def notify_events(space, node_id) do
    update(space, node_id, fn node ->
      notifier = Bitwise.bor(node.attributes[:event_notifier] || 0, @subscribe_to_events)
      put_in(node.attributes[:event_notifier], notifier)
    end)
  end

  @doc false
  def notifier?(node),
    do: Bitwise.band(node.attributes[:event_notifier] || 0, @subscribe_to_events) != 0

  @doc false
  def put_value(space, node_id, value), do: :ets.insert(space.values, {node_id, value})

  @doc false
  # Removes a node and the nodes below it by hierarchical references, with
  # their values and the references other nodes have to them.
  def delete(_space, %NodeId{ns: 0}), do: {:error, :bad_no_delete_rights}

  def delete(space, node_id) do
    case get(space, node_id) do
      nil ->
        {:error, :bad_node_id_unknown}

      node ->
        space |> held(node, MapSet.new([node_id])) |> Enum.each(&remove(space, &1))
        :ok
    end
  end

  # The node and what it holds, outside namespace 0.
  defp held(space, node, seen) do
    Enum.reduce(node.references, seen, fn {type, target, forward}, seen ->
      with true <- forward and target.ns != 0 and not MapSet.member?(seen, target),
           true <- subtype?(space, type, @hierarchical),
           %Node{} = child <- get(space, target) do
        held(space, child, MapSet.put(seen, target))
      else
        _ -> seen
      end
    end)
  end

  defp remove(space, node_id) do
    with %Node{references: references} <- get(space, node_id) do
      for {type, target, forward} <- references,
          %Node{references: theirs} <- [get(space, target)],
          {type, node_id, not forward} in theirs,
          do:
            update(
              space,
              target,
              &%{&1 | references: List.delete(&1.references, {type, node_id, not forward})}
            )

      :ets.delete(space.nodes, node_id)
      :ets.delete(space.values, node_id)
      :ets.delete(space.values, {:condition, node_id})
    end
  end

  @doc false
  # The value of a node's property, such as a variable's EURange, or nil.
  def property(space, node_id, name) do
    with %Node{references: references} <- get(space, node_id),
         %Node{} = property <- Enum.find_value(references, &named_property(space, &1, name)),
         %DataValue{value: %Variant{value: value}} <- value(space, property.node_id) do
      value
    else
      _ -> nil
    end
  end

  defp named_property(space, {@has_property, target, true}, name) do
    case get(space, target) do
      %Node{browse_name: %QualifiedName{name: ^name}} = property -> property
      _other -> nil
    end
  end

  defp named_property(_space, _reference, _name), do: nil

  @doc false
  # The current value of a variable, reading its function if it has one.
  def value(space, node_id) do
    case :ets.lookup(space.values, node_id) do
      [{_, %DataValue{} = value}] ->
        value

      [{_, {:read, fun, type}}] ->
        try do
          variant =
            case fun.() do
              %Variant{} = variant -> variant
              value -> %Variant{type: type, value: value}
            end

          # A value that can't be encoded would break the whole response.
          _ = Binary.encode(variant, :variant)
          %DataValue{value: variant, source_timestamp: DateTime.utc_now()}
        rescue
          exception ->
            Logger.error(
              "OPC UA value of #{node_id} failed: " <>
                Exception.format(:error, exception, __STACKTRACE__)
            )

            %DataValue{status: OPCUA.StatusCode.code(:bad_internal_error)}
        end

      [] ->
        %DataValue{}
    end
  end

  ## Read

  @doc false
  def read(space, %Types.ReadValueId{} = read, timestamps) do
    now = DateTime.utc_now()

    result =
      with %Node{} = node <- get(space, read.node_id) || {:error, :bad_node_id_unknown},
           :ok <- encoding(read.data_encoding),
           {:ok, value} <- attribute(space, node, read.attribute_id) do
        range(value, read.index_range)
      end

    case result do
      {:error, status} ->
        %DataValue{status: OPCUA.StatusCode.code(status)}

      %DataValue{} = value ->
        %{
          value
          | source_timestamp: if(timestamps in [:source, :both], do: value.source_timestamp),
            server_timestamp: if(timestamps in [:server, :both], do: now)
        }

      %Variant{} = variant ->
        %DataValue{value: variant, server_timestamp: if(timestamps in [:server, :both], do: now)}
    end
  end

  defp encoding(nil), do: :ok
  defp encoding(%QualifiedName{ns: 0, name: "Default Binary"}), do: :ok
  defp encoding(_), do: {:error, :bad_data_encoding_unsupported}

  defp attribute(space, node, id),
    do: attribute(space, node, OPCUA.AttributeId.name(id), node.class)

  # The attributes every node has, and the value; the rest are in the node's attributes.
  defp attribute(_space, node, :node_id, _class),
    do: {:ok, %Variant{type: :node_id, value: node.node_id}}

  defp attribute(_space, _node, :node_class, class),
    do: {:ok, %Variant{type: :int32, value: @classes[class]}}

  defp attribute(_space, node, :browse_name, _class),
    do: {:ok, %Variant{type: :qualified_name, value: node.browse_name}}

  defp attribute(_space, node, :display_name, _class),
    do: {:ok, %Variant{type: :localized_text, value: node.display_name}}

  defp attribute(_space, node, :description, _class),
    do: {:ok, %Variant{type: :localized_text, value: node.description}}

  defp attribute(_space, _node, mask, _class) when mask in [:write_mask, :user_write_mask],
    do: {:ok, %Variant{type: :uint32, value: 0}}

  defp attribute(space, node, :value, :variable), do: readable(space, node)

  defp attribute(space, node, :value, :variable_type), do: {:ok, value(space, node.node_id)}

  defp attribute(_space, node, name, _class), do: attribute(node, name)

  defp readable(space, node) do
    if Bitwise.band(node.attributes.user_access_level, @current_read) != 0,
      do: {:ok, value(space, node.node_id)},
      else: {:error, :bad_not_readable}
  end

  @types %{
    is_abstract: :boolean,
    symmetric: :boolean,
    inverse_name: :localized_text,
    contains_no_loops: :boolean,
    event_notifier: :byte,
    data_type: :node_id,
    value_rank: :int32,
    array_dimensions: {:array, :uint32},
    access_level: :byte,
    user_access_level: :byte,
    minimum_sampling_interval: :double,
    historizing: :boolean,
    executable: :boolean,
    user_executable: :boolean
  }

  defp attribute(node, :access_level_ex) when node.class == :variable,
    do: {:ok, %Variant{type: :uint32, value: node.attributes.access_level}}

  defp attribute(node, name) do
    case {@types[name], node.attributes} do
      {nil, _} -> {:error, :bad_attribute_id_invalid}
      {{:array, type}, %{^name => value}} -> {:ok, %Variant{type: type, value: value || []}}
      {type, %{^name => value}} -> {:ok, %Variant{type: type, value: value}}
      _ -> {:error, :bad_attribute_id_invalid}
    end
  end

  # A NumericRange ("3" or "1:4") on a one-dimensional array or a string.
  defp range(value, nil), do: value
  defp range(value, ""), do: value

  defp range(%DataValue{value: %Variant{value: data} = variant} = value, text) do
    with {:ok, first, last} <- numeric_range(text) do
      cond do
        is_list(data) and first < length(data) ->
          %{value | value: %{variant | value: Enum.slice(data, first..last//1)}}

        is_binary(data) and first < byte_size(data) ->
          %{
            value
            | value: %{
                variant
                | value: binary_part(data, first, min(last, byte_size(data) - 1) - first + 1)
              }
          }

        is_list(data) or is_binary(data) ->
          {:error, :bad_index_range_no_data}

        true ->
          {:error, :bad_index_range_invalid}
      end
    end
  end

  defp range(_, _), do: {:error, :bad_index_range_invalid}

  # Longer than any index, and a number of a million digits takes a while
  # to parse.
  defp numeric_range(text) when byte_size(text) > 40, do: {:error, :bad_index_range_invalid}

  defp numeric_range(text) do
    case String.split(text, ":") do
      [n] ->
        with {:ok, n} <- index(n), do: {:ok, n, n}

      [a, b] ->
        with {:ok, a} <- index(a),
             {:ok, b} <- index(b),
             true <- a < b || {:error, :bad_index_range_invalid},
             do: {:ok, a, b}

      _ ->
        {:error, :bad_index_range_invalid}
    end
  end

  defp index(text) do
    case Integer.parse(text) do
      {n, ""} when n >= 0 -> {:ok, n}
      _ -> {:error, :bad_index_range_invalid}
    end
  end

  ## Write

  @doc false
  # Writes a value from a client. `write` in the node's attributes, if any,
  # gets the value first and may refuse it.
  def write(space, %Types.WriteValue{} = write) do
    with %Node{class: :variable} = node <-
           get(space, write.node_id) || {:error, :bad_node_id_unknown},
         :ok <-
           if(OPCUA.AttributeId.name(write.attribute_id) == :value,
             do: :ok,
             else: {:error, :bad_not_writable}
           ),
         :ok <-
           if(write.index_range in [nil, ""], do: :ok, else: {:error, :bad_write_not_supported}),
         :ok <-
           if(Bitwise.band(node.attributes.user_access_level, @current_write) != 0,
             do: :ok,
             else: {:error, :bad_not_writable}
           ),
         %DataValue{value: %Variant{} = variant} = value <-
           write.value || {:error, :bad_type_mismatch},
         :ok <- check(space, node, variant),
         :ok <- on_write(node, variant) do
      put_value(space, node.node_id, %{
        value
        | source_timestamp: value.source_timestamp || DateTime.utc_now(),
          server_timestamp: nil
      })

      0
    else
      {:error, status} -> OPCUA.StatusCode.code(status)
      %Node{} -> OPCUA.StatusCode.code(:bad_not_writable)
      %DataValue{} -> OPCUA.StatusCode.code(:bad_type_mismatch)
    end
  end

  defp on_write(%{attributes: %{write: fun}} = node, variant) do
    case fun.(variant.value) do
      :ok -> :ok
      {:error, status} when is_atom(status) -> {:error, status}
    end
  rescue
    exception ->
      Logger.error(
        "OPC UA write to #{node.node_id} failed: " <>
          Exception.format(:error, exception, __STACKTRACE__)
      )

      {:error, :bad_internal_error}
  end

  defp on_write(_, _), do: :ok

  @numbers [:sbyte, :byte, :int16, :uint16, :int32, :uint32, :int64, :uint64, :float, :double]

  @doc false
  # Checks that a variant fits a variable's data type and value rank.
  def check(space, node, %Variant{type: type, value: value}) do
    fits = fits?(builtin(space, node.attributes.data_type), type)

    if fits and shape?(node.attributes.value_rank, value),
      do: :ok,
      else: {:error, :bad_type_mismatch}
  end

  defp fits?(:variant, _type), do: true
  defp fits?(:number, type), do: type in @numbers
  defp fits?(:integer, type), do: type in [:sbyte, :int16, :int32, :int64]
  defp fits?(:unsigned, type), do: type in [:byte, :uint16, :uint32, :uint64]
  defp fits?(builtin, type), do: type == builtin

  # A value rank of -2 or -3 takes a scalar or an array, -1 a scalar, and 0 and up an array.
  defp shape?(rank, _value) when rank in [-2, -3], do: true
  defp shape?(-1, value), do: not is_list(value)
  defp shape?(_rank, value), do: is_list(value)

  # The built-in type a data type is encoded as, following HasSubtype up
  # from types like Duration (a Double) or NodeClass (an enumeration).
  defp builtin(_, %NodeId{ns: 0, id: id}) when id in 1..25, do: Binary.type_name(id)
  defp builtin(_, @number), do: :number
  defp builtin(_, @integer), do: :integer
  defp builtin(_, @unsigned), do: :unsigned
  defp builtin(_, @enumeration), do: :int32

  defp builtin(space, type) do
    case get(space, type) do
      %Node{references: refs} ->
        supertype(space, for({@has_subtype, super, false} <- refs, do: super))

      nil ->
        :variant
    end
  end

  defp supertype(space, [super | _]), do: builtin(space, super)
  defp supertype(_space, []), do: :variant

  ## Browse

  @doc false
  # All references of a node that match a BrowseDescription.
  def browse(space, %Types.BrowseDescription{} = description) do
    with %Node{} = node <- get(space, description.node_id) || {:error, :bad_node_id_unknown},
         :ok <- reference_type(space, description.reference_type_id),
         :ok <-
           if(description.browse_direction in [:forward, :inverse, :both],
             do: :ok,
             else: {:error, :bad_browse_direction_invalid}
           ) do
      refs =
        for {type, target, forward} <- node.references,
            direction?(description.browse_direction, forward),
            type?(space, type, description.reference_type_id, description.include_subtypes),
            target_node = get(space, target),
            class?(target_node, description.node_class_mask) do
          describe(type, forward, target, target_node, description.result_mask)
        end

      {:ok, refs}
    end
  end

  defp reference_type(_, nil), do: :ok

  defp reference_type(space, type) do
    case get(space, type) do
      %Node{class: :reference_type} -> :ok
      _ -> {:error, :bad_reference_type_id_invalid}
    end
  end

  defp direction?(:both, _), do: true
  defp direction?(:forward, forward), do: forward
  defp direction?(:inverse, forward), do: not forward

  defp type?(_, _, nil, _), do: true
  defp type?(_, type, type, _), do: true
  defp type?(space, type, wanted, true), do: subtype?(space, type, wanted)
  defp type?(_, _, _, false), do: false

  @doc false
  # Whether `type` is `super` or one of its subtypes.
  def subtype?(_, type, type), do: true

  def subtype?(space, type, super) do
    case get(space, type) do
      %Node{references: refs} ->
        Enum.any?(
          for({@has_subtype, parent, false} <- refs, do: parent),
          &subtype?(space, &1, super)
        )

      nil ->
        false
    end
  end

  # A target in another server or namespace we don't have is left out.
  defp class?(nil, _), do: false
  defp class?(_, 0), do: true
  defp class?(node, mask), do: Bitwise.band(@classes[node.class], mask) != 0

  defp describe(type, forward, target, node, mask) do
    bit = &(Bitwise.band(mask, &1) != 0)

    %Types.ReferenceDescription{
      reference_type_id: if(bit.(1), do: type),
      is_forward: bit.(2) and forward,
      node_id: expanded(target),
      browse_name: if(bit.(8), do: node.browse_name),
      display_name: if(bit.(16), do: node.display_name),
      node_class: if(bit.(4), do: node.class, else: :unspecified),
      type_definition:
        if(bit.(32) and node.class in [:object, :variable],
          do: type_definition(node) && expanded(type_definition(node))
        )
    }
  end

  defp type_definition(node) do
    Enum.find_value(node.references, fn
      {@has_type_definition, type, true} -> type
      _ -> nil
    end)
  end

  defp expanded(%NodeId{ns: ns, id: id}), do: %ExpandedNodeId{ns: ns, id: id}

  ## TranslateBrowsePathsToNodeIds

  @doc false
  def translate(space, %Types.BrowsePath{starting_node: start, relative_path: path}) do
    elements = (path && path.elements) || []

    cond do
      get(space, start) == nil ->
        %Types.BrowsePathResult{status_code: OPCUA.StatusCode.code(:bad_node_id_unknown)}

      elements == [] ->
        %Types.BrowsePathResult{status_code: OPCUA.StatusCode.code(:bad_nothing_to_do)}

      true ->
        case Enum.reduce(elements, [start], &follow(space, &1, &2)) do
          [] ->
            %Types.BrowsePathResult{status_code: OPCUA.StatusCode.code(:bad_no_match)}

          targets ->
            %Types.BrowsePathResult{
              status_code: 0,
              targets:
                for(
                  t <- targets,
                  do: %Types.BrowsePathTarget{
                    target_id: expanded(t),
                    remaining_path_index: 0xFFFF_FFFF
                  }
                )
            }
        end
    end
  end

  defp follow(space, element, nodes) do
    wanted = element.reference_type_id || @hierarchical

    Enum.uniq(
      for node_id <- nodes,
          {type, target, forward} <- get(space, node_id).references,
          forward != element.is_inverse,
          type?(
            space,
            type,
            wanted,
            element.include_subtypes or element.reference_type_id == nil
          ),
          %Node{browse_name: name} <- [get(space, target)],
          name == element.target_name,
          do: target
    )
  end
end
