defmodule OPCUA.QualifiedName do
  @moduledoc """
  A name qualified by a namespace index, such as a node's browse name.

  A null name in namespace 0 decodes as `nil`.
  """

  defstruct ns: 0, name: nil

  @type t :: %__MODULE__{ns: non_neg_integer, name: String.t() | nil}

  @doc """
  Parses the text form: `"2:Level"` in namespace 2, or `"Level"` in
  namespace 0.

      iex> OPCUA.QualifiedName.parse("2:Level")
      %OPCUA.QualifiedName{ns: 2, name: "Level"}
  """
  @spec parse(String.t()) :: t
  def parse(text) do
    case Integer.parse(text) do
      {ns, ":" <> name} when ns in 0..0xFFFF -> %__MODULE__{ns: ns, name: name}
      _ -> %__MODULE__{ns: 0, name: text}
    end
  end
end
