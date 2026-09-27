defmodule OPCUA.Variant do
  @moduledoc """
  A value tagged with its built-in type.

  `type` is one of the built-in type atoms of `OPCUA.Binary`, such as `:int16`
  or `:double`. An array has a list as `value`; a multi-dimensional array
  keeps the list flat and puts the lengths in `dimensions`. An
  `:extension_object` holds a structure from `OPCUA.Types`, or an
  `OPCUA.ExtensionObject` for one this library doesn't know.

  The null variant decodes as `nil`.

      %OPCUA.Variant{type: :int16, value: 42}
      %OPCUA.Variant{type: :double, value: [1.0, 2.0, 3.0, 4.0], dimensions: [2, 2]}
  """

  defstruct type: nil, value: nil, dimensions: nil

  @type t :: %__MODULE__{
          type: OPCUA.Binary.builtin(),
          value: term,
          dimensions: [non_neg_integer] | nil
        }
end
