defmodule OPCUA.QualifiedName do
  @moduledoc """
  A name qualified by a namespace index, such as a node's browse name.

  A null name in namespace 0 decodes as `nil`.
  """

  defstruct ns: 0, name: nil

  @type t :: %__MODULE__{ns: non_neg_integer, name: String.t() | nil}
end
