defmodule OPCUA.DecodeError do
  @moduledoc "Raised by the decoders on bytes that aren't valid OPC UA binary encoding."
  defexception message: "malformed OPC UA binary encoding"
end
