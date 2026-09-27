defmodule OPCUA.ExtensionObject do
  @moduledoc """
  A structure this library can't decode, kept as its type id and raw body.

  Structures from `OPCUA.Types` are decoded into their own structs instead;
  this is what's left, such as a server's own types. `encoding` is `:binary`
  or `:xml` (an XML body is kept as text, never parsed), or `nil` when there's
  no body. The null value decodes as `nil`.
  """

  defstruct type_id: nil, encoding: nil, body: nil

  @type t :: %__MODULE__{
          type_id: OPCUA.NodeId.t() | nil,
          encoding: :binary | :xml | nil,
          body: binary | nil
        }
end
