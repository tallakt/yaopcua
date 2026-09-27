defmodule OPCUA.StatusCode do
  @moduledoc """
  OPC UA status codes, named from `schema/StatusCode.csv`.

  A status code is a 32-bit integer. The top two bits are the severity: Good,
  Uncertain or Bad. The low 16 bits carry flags such as StructureChanged,
  which `name/1` and `description/1` ignore.

      iex> OPCUA.StatusCode.name(0x80340000)
      :bad_node_id_unknown
      iex> OPCUA.StatusCode.code(:bad_node_id_unknown)
      0x80340000
      iex> OPCUA.StatusCode.bad?(0x80340000)
      true
  """

  import Bitwise

  @external_resource OPCUA.Schema.path("StatusCode.csv")

  codes = OPCUA.Schema.status_codes()

  @type t :: non_neg_integer

  @doc "The name of a status code, such as `:bad_timeout`, or `nil` for one this release doesn't know."
  @spec name(t) :: atom | nil
  def name(code) when is_integer(code), do: lookup(code &&& 0xFFFF0000)

  @doc "The status code with this name. Raises `ArgumentError` for an unknown name."
  @spec code(atom) :: t
  def code(name)

  @doc "The spec's one-line description of a status code, or `nil`."
  @spec description(t) :: String.t() | nil
  def description(code) when is_integer(code), do: text(code &&& 0xFFFF0000)

  for {name, code, text} <- codes do
    defp lookup(unquote(code)), do: unquote(name)
    def code(unquote(name)), do: unquote(code)
    defp text(unquote(code)), do: unquote(text)
  end

  defp lookup(_), do: nil
  def code(name), do: raise(ArgumentError, "unknown status code #{inspect(name)}")
  defp text(_), do: nil

  @doc "True for a Good status."
  @spec good?(t) :: boolean
  def good?(code), do: code >>> 30 == 0

  @doc "True for an Uncertain status."
  @spec uncertain?(t) :: boolean
  def uncertain?(code), do: code >>> 30 == 1

  @doc "True for a Bad status."
  @spec bad?(t) :: boolean
  def bad?(code), do: code >>> 31 == 1
end
