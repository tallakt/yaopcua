defmodule OPCUA.DataValue do
  @moduledoc """
  A value with its status and timestamps, as read or reported by a server.

  A status of 0 is Good (see `OPCUA.StatusCode`). Picoseconds add precision
  below the 100 ns resolution of OPC UA timestamps; `DateTime` itself keeps
  microseconds.
  """

  defstruct value: nil,
            status: 0,
            source_timestamp: nil,
            source_picoseconds: 0,
            server_timestamp: nil,
            server_picoseconds: 0

  @type t :: %__MODULE__{
          value: OPCUA.Variant.t() | nil,
          status: OPCUA.StatusCode.t(),
          source_timestamp: DateTime.t() | nil,
          source_picoseconds: non_neg_integer,
          server_timestamp: DateTime.t() | nil,
          server_picoseconds: non_neg_integer
        }
end
