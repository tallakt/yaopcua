defmodule OPCUA.Server.Namespace0 do
  @moduledoc false
  # The standard nodes of namespace 0, read from schema/Opc.Ua.NodeSet2.xml
  # while compiling and kept as one compressed binary: 5,500 nodes compile
  # far faster as a single literal than as terms, and load in about 20 ms.

  @external_resource OPCUA.Schema.path("Opc.Ua.NodeSet2.xml")

  @nodes OPCUA.Schema.path("Opc.Ua.NodeSet2.xml")
         |> OPCUA.Server.NodeSet.read()
         |> :erlang.term_to_binary(compressed: 6)

  @doc false
  # `[{node, value}]` for every node of namespace 0.
  def nodes, do: :erlang.binary_to_term(@nodes)
end
