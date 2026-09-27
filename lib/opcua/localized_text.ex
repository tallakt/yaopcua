defmodule OPCUA.LocalizedText do
  @moduledoc """
  Text meant for people, with an optional locale such as `"en-US"`.

  A value with neither locale nor text decodes as `nil`.
  """

  defstruct locale: nil, text: nil

  @type t :: %__MODULE__{locale: String.t() | nil, text: String.t() | nil}
end
