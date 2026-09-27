defmodule OPCUA.DiagnosticInfo do
  @moduledoc """
  Extra detail about an error. `symbolic_id`, `namespace_uri`, `locale` and
  `localized_text` are indexes into the string table of the response that
  carried it.

  An empty value decodes as `nil`.
  """

  defstruct symbolic_id: nil,
            namespace_uri: nil,
            locale: nil,
            localized_text: nil,
            additional_info: nil,
            inner_status_code: nil,
            inner_diagnostic_info: nil

  @type t :: %__MODULE__{
          symbolic_id: integer | nil,
          namespace_uri: integer | nil,
          locale: integer | nil,
          localized_text: integer | nil,
          additional_info: String.t() | nil,
          inner_status_code: OPCUA.StatusCode.t() | nil,
          inner_diagnostic_info: t | nil
        }
end
