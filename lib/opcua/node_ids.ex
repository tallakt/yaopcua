defmodule OPCUA.NodeIds do
  @moduledoc """
  The numeric ids of the namespace 0 nodes, by the symbolic names in
  `schema/NodeIds.csv`.

      iex> OPCUA.NodeIds.id("Server_ServerStatus_CurrentTime")
      2258
      iex> OPCUA.NodeIds.name(2258)
      "Server_ServerStatus_CurrentTime"
  """

  @external_resource OPCUA.Schema.path("NodeIds.csv")

  # Maps rather than one function clause per node: 15k string clauses take
  # half a minute to compile, the maps under a second, and lookups are as fast.
  rows = OPCUA.Schema.node_ids()
  @ids Map.new(rows, fn {name, id, _class} -> {name, id} end)
  @names Map.new(rows, fn {name, id, _class} -> {id, name} end)

  @doc "The id of the namespace 0 node with this name, or `nil`."
  @spec id(String.t()) :: non_neg_integer | nil
  def id(name), do: Map.get(@ids, name)

  @doc "Like `id/1`, but raises `ArgumentError` for an unknown name."
  @spec id!(String.t()) :: non_neg_integer
  def id!(name) do
    case @ids do
      %{^name => id} -> id
      _ -> raise ArgumentError, "no node #{inspect(name)} in namespace 0"
    end
  end

  @doc "The name of the namespace 0 node with this id, or `nil`."
  @spec name(non_neg_integer) :: String.t() | nil
  def name(id), do: Map.get(@names, id)
end
