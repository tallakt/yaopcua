defmodule OPCUA.AttributeId do
  @moduledoc """
  The ids of node attributes, from `schema/AttributeIds.csv`.

      iex> OPCUA.AttributeId.id(:value)
      13
      iex> OPCUA.AttributeId.name(13)
      :value
  """

  @external_resource OPCUA.Schema.path("AttributeIds.csv")

  ids = OPCUA.Schema.attribute_ids()

  @doc "The id of an attribute. Raises `ArgumentError` for an unknown name."
  @spec id(atom) :: pos_integer
  def id(name)

  @doc "The name of an attribute id, or `nil`."
  @spec name(pos_integer) :: atom | nil
  def name(id)

  for {name, id} <- ids do
    def id(unquote(name)), do: unquote(id)
    def name(unquote(id)), do: unquote(name)
  end

  def id(name), do: raise(ArgumentError, "unknown attribute #{inspect(name)}")
  def name(_), do: nil

  @doc "All attribute names, in id order."
  def names, do: unquote(Enum.map(ids, &elem(&1, 0)))
end
