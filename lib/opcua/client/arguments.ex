defmodule OPCUA.Client.Arguments do
  @moduledoc false
  # The types a method declares for its input arguments, in its InputArguments
  # property, so that Client.call/4 can send plain values as those types, the
  # way Client.write/3 sends them as the node's.

  alias OPCUA.{NodeId, NodeIds, QualifiedName}
  alias OPCUA.Types

  @has_subtype NodeIds.node_id!("HasSubtype")
  @has_property NodeIds.node_id!("HasProperty")
  @enumeration NodeIds.node_id!("Enumeration")

  # The built-in type each data type of namespace 0 is encoded as, following
  # HasSubtype up: Duration as a Double, UtcTime as a DateTime, an enumeration
  # as an Int32. Abstract types such as Number and BaseDataType, and
  # structures, have none: a value of those says its own type.
  @builtins (
              has_subtype = @has_subtype
              enumeration = @enumeration

              supertypes =
                for {%{class: :data_type} = node, _} <- OPCUA.Server.Namespace0.nodes(),
                    into: %{},
                    do:
                      {node.node_id,
                       for({^has_subtype, super, false} <- node.references, do: super)}

              builtin = fn
                _, %NodeId{ns: 0, id: id} when id in 1..21 or id in [23, 25] ->
                  OPCUA.Binary.type_name(id)

                _, ^enumeration ->
                  :int32

                builtin, type ->
                  case supertypes[type] do
                    [super | _] -> builtin.(builtin, super)
                    _ -> nil
                  end
              end

              for {type, _} <- supertypes,
                  name = builtin.(builtin, type),
                  name != nil,
                  into: %{},
                  do: {type.id, name}
            )

  @doc false
  # The built-in type of a data type, or nil for one that leaves it open.
  def builtin(%NodeId{ns: 0, id: id}), do: Map.get(@builtins, id)
  def builtin(_), do: nil

  @doc false
  # The request that finds a method's InputArguments property.
  def find(method) do
    %Types.TranslateBrowsePathsToNodeIdsRequest{
      browse_paths: [
        %Types.BrowsePath{
          starting_node: method,
          relative_path: %Types.RelativePath{
            elements: [
              %Types.RelativePathElement{
                reference_type_id: @has_property,
                is_inverse: false,
                include_subtypes: false,
                target_name: %QualifiedName{ns: 0, name: "InputArguments"}
              }
            ]
          }
        }
      ]
    }
  end

  @doc false
  # The built-in type of each argument, nil where the method leaves it open.
  def types(arguments) do
    for argument <- List.wrap(arguments) do
      case argument do
        %Types.Argument{data_type: %NodeId{} = type} -> builtin(type)
        _ -> nil
      end
    end
  end
end
