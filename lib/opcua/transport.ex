defmodule OPCUA.Transport do
  @moduledoc """
  The UA-TCP framing of OPC UA (Part 6, section 7.1).

  Everything on the wire is a chunk with an 8-byte header: a 3-letter message
  type, a chunk type (`F`inal, `C`ontinued or `A`bort) and the chunk's total
  size. `HEL`, `ACK`, `ERR` and `RHE` set up and tear down the connection;
  `OPN`, `MSG` and `CLO` carry the secure channel (see `OPCUA.SecureChannel`).
  """

  alias OPCUA.Binary

  @types %{
    "HEL" => :hello,
    "ACK" => :acknowledge,
    "ERR" => :error,
    "RHE" => :reverse_hello,
    "OPN" => :open,
    "MSG" => :message,
    "CLO" => :close
  }
  @names Map.new(@types, fn {name, type} -> {type, name} end)
  @chunks %{?F => :final, ?C => :continued, ?A => :abort}
  @chunk_bytes Map.new(@chunks, fn {byte, type} -> {type, byte} end)

  @type type :: :hello | :acknowledge | :error | :reverse_hello | :open | :message | :close
  @type chunk :: :final | :continued | :abort

  @typedoc "The buffer sizes and limits one side can handle; 0 means no limit."
  @type limits :: %{
          protocol_version: non_neg_integer,
          receive_buffer_size: pos_integer,
          send_buffer_size: pos_integer,
          max_message_size: non_neg_integer,
          max_chunk_count: non_neg_integer
        }

  # The spec's minimum buffer size, which a Hello or Acknowledge may not go below.
  @min_buffer 8192

  @doc "Wraps a chunk body in the 8-byte header."
  @spec frame(type, chunk, iodata) :: iodata
  def frame(type, chunk, body) do
    [
      Map.fetch!(@names, type),
      Map.fetch!(@chunk_bytes, chunk),
      <<IO.iodata_length(body) + 8::little-32>>,
      body
    ]
  end

  @doc """
  Splits complete chunks off the front of `buffer`.

  Returns the chunks as `{type, chunk, body}` and the incomplete rest. A chunk
  bigger than `max_size`, or with a header that isn't UA-TCP, is an error.
  """
  @spec split(binary, pos_integer) :: {:ok, [{type, chunk, binary}], binary} | {:error, atom}
  def split(buffer, max_size), do: split(buffer, max_size, [])

  defp split(<<name::binary-3, chunk, size::little-32, rest::binary>> = buffer, max_size, acc) do
    body_size = size - 8

    cond do
      not is_map_key(@types, name) or not is_map_key(@chunks, chunk) ->
        {:error, :bad_tcp_message_type_invalid}

      size > max_size or size < 8 ->
        {:error, :bad_tcp_message_too_large}

      byte_size(rest) < body_size ->
        {:ok, Enum.reverse(acc), buffer}

      true ->
        split(binary_part(rest, body_size, byte_size(rest) - body_size), max_size, [
          {@types[name], @chunks[chunk], binary_part(rest, 0, body_size)} | acc
        ])
    end
  end

  defp split(buffer, _, acc), do: {:ok, Enum.reverse(acc), buffer}

  @doc "The body of a Hello: our limits and the endpoint URL we're connecting to."
  @spec hello(limits, String.t()) :: iodata
  def hello(limits, endpoint_url),
    do: [encode_limits(limits), Binary.encode(endpoint_url, :string)]

  @doc "The body of an Acknowledge: the limits the server settled on."
  @spec acknowledge(limits) :: iodata
  def acknowledge(limits), do: encode_limits(limits)

  @doc "The body of an Error: a status code and a reason."
  @spec error(OPCUA.StatusCode.t() | atom, String.t() | nil) :: iodata
  def error(status, reason),
    do: [Binary.encode(status, :status_code), Binary.encode(reason, :string)]

  defp encode_limits(l) do
    <<l.protocol_version::little-32, l.receive_buffer_size::little-32,
      l.send_buffer_size::little-32, l.max_message_size::little-32, l.max_chunk_count::little-32>>
  end

  @doc "Decodes the body of a Hello, Acknowledge, Error or ReverseHello."
  @spec decode(type, binary) :: {:ok, term} | {:error, atom}
  def decode(:hello, <<limits::binary-20, rest::binary>>) do
    with {:ok, limits} <- decode_limits(limits),
         {:ok, url, _} when byte_size(url) <= 4096 <- Binary.decode(rest, :string) do
      {:ok, {limits, url}}
    else
      _ -> {:error, :bad_tcp_endpoint_url_invalid}
    end
  end

  def decode(:acknowledge, <<limits::binary-20, _::binary>>), do: decode_limits(limits)

  def decode(:error, body) do
    with {:ok, status, rest} <- Binary.decode(body, :status_code),
         {:ok, reason, _} <- Binary.decode(rest, :string) do
      {:ok, {status, reason}}
    end
  end

  def decode(:reverse_hello, body) do
    with {:ok, server_uri, rest} <- Binary.decode(body, :string),
         {:ok, endpoint_url, _} <- Binary.decode(rest, :string) do
      {:ok, {server_uri, endpoint_url}}
    end
  end

  def decode(_, _), do: {:error, :bad_decoding_error}

  defp decode_limits(
         <<version::little-32, receive::little-32, send::little-32, message::little-32,
           chunks::little-32>>
       )
       when receive >= @min_buffer and send >= @min_buffer do
    {:ok,
     %{
       protocol_version: version,
       receive_buffer_size: receive,
       send_buffer_size: send,
       max_message_size: message,
       max_chunk_count: chunks
     }}
  end

  defp decode_limits(_), do: {:error, :bad_tcp_internal_error}

  @doc """
  Parses `opc.tcp://host:port/path` into `{host, port}`, with 4840 as the
  default port.
  """
  @spec endpoint(String.t()) ::
          {:ok, {charlist, :inet.port_number()}} | {:error, :bad_tcp_endpoint_url_invalid}
  def endpoint(url) do
    case URI.parse(url) do
      %URI{scheme: "opc.tcp", host: host, port: port} when is_binary(host) and host != "" ->
        {:ok, {String.to_charlist(host), port || 4840}}

      _ ->
        {:error, :bad_tcp_endpoint_url_invalid}
    end
  end
end
