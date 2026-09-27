defmodule OPCUA.ExpandedNodeId do
  @moduledoc """
  A node id that may point into another namespace by URI, or into another
  server by index into the server table.

  When `namespace_uri` is set it takes the place of `ns`. The null value
  decodes as `nil`.
  """

  defstruct ns: 0, id: 0, namespace_uri: nil, server_index: 0

  @type t :: %__MODULE__{
          ns: non_neg_integer,
          id: OPCUA.NodeId.id(),
          namespace_uri: String.t() | nil,
          server_index: non_neg_integer
        }

  defimpl String.Chars do
    def to_string(e) do
      server = if e.server_index != 0, do: "svr=#{e.server_index};", else: ""

      namespace =
        cond do
          e.namespace_uri -> "nsu=#{e.namespace_uri};"
          e.ns != 0 -> "ns=#{e.ns};"
          true -> ""
        end

      server <> namespace <> OPCUA.NodeId.identifier_to_string(e.id)
    end
  end
end
