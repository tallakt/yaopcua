defmodule OPCUA.NodeId do
  @moduledoc """
  Identifies a node in a server's address space.

  `id` is an integer, a string, `{:guid, "72962B91-FA75-4AE6-8D28-B404DC7DAF63"}`
  or `{:opaque, bytes}`. `ns` is the namespace index; 0 is the OPC UA base
  namespace.

  The text form is the one UaExpert and most tools show:

      iex> OPCUA.NodeId.parse!("ns=3;s=Pump1.Speed")
      %OPCUA.NodeId{ns: 3, id: "Pump1.Speed"}
      iex> to_string(%OPCUA.NodeId{ns: 0, id: 2256})
      "i=2256"

  The null node id (`i=0`) decodes as `nil`.
  """

  defstruct ns: 0, id: 0

  @type id :: non_neg_integer | String.t() | {:guid, String.t()} | {:opaque, binary}
  @type t :: %__MODULE__{ns: non_neg_integer, id: id}

  @doc "Parses the text form: `i=85`, `ns=2;s=Tank.Level`, `ns=1;g=<guid>` or `ns=1;b=<base64>`."
  @spec parse(String.t()) :: {:ok, t} | {:error, :invalid_node_id}
  def parse(text) do
    {ns, rest} =
      case text do
        "ns=" <> rest ->
          case Integer.parse(rest) do
            {ns, ";" <> rest} when ns in 0..0xFFFF -> {ns, rest}
            _ -> {nil, rest}
          end

        rest ->
          {0, rest}
      end

    case ns && identifier(rest) do
      {:ok, id} -> {:ok, %__MODULE__{ns: ns, id: id}}
      _ -> {:error, :invalid_node_id}
    end
  end

  @doc "Like `parse/1`, but raises `ArgumentError` on text that isn't a node id."
  @spec parse!(String.t()) :: t
  def parse!(text) do
    case parse(text) do
      {:ok, node_id} -> node_id
      {:error, _} -> raise ArgumentError, "not a node id: #{inspect(text)}"
    end
  end

  @doc false
  def identifier("i=" <> n) do
    case Integer.parse(n) do
      {i, ""} when i in 0..0xFFFFFFFF -> {:ok, i}
      _ -> :error
    end
  end

  def identifier("s=" <> s), do: {:ok, s}
  def identifier("g=" <> g), do: if(guid?(g), do: {:ok, {:guid, String.upcase(g)}}, else: :error)

  def identifier("b=" <> b) do
    case Base.decode64(b) do
      {:ok, bytes} -> {:ok, {:opaque, bytes}}
      :error -> :error
    end
  end

  def identifier(_), do: :error

  defp guid?(g), do: g =~ ~r/\A[[:xdigit:]]{8}(-[[:xdigit:]]{4}){3}-[[:xdigit:]]{12}\z/

  @doc false
  def identifier_to_string(i) when is_integer(i), do: "i=#{i}"
  def identifier_to_string(s) when is_binary(s), do: "s=" <> s
  def identifier_to_string({:guid, g}), do: "g=" <> g
  def identifier_to_string({:opaque, b}), do: "b=" <> Base.encode64(b)

  defimpl String.Chars do
    def to_string(%{ns: 0, id: id}), do: OPCUA.NodeId.identifier_to_string(id)
    def to_string(%{ns: ns, id: id}), do: "ns=#{ns};" <> OPCUA.NodeId.identifier_to_string(id)
  end
end
