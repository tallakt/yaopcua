defmodule OPCUA.SecureChannel do
  @moduledoc """
  One side of an OPC UA secure channel (Part 6, section 6.7), as plain data.

  `encode/4` turns a service message into the chunks to send, and `receive/2`
  takes chunks back in and returns whole messages. Neither does any I/O, so a
  client and a server can both build on it, and it can be tested byte by byte.

  Each chunk carries the channel id, a security header, a sequence number and
  the request id. A message bigger than the other side's buffer is split into
  chunks, and reassembled on the way in.

  Only the None security policy is implemented so far: no signing, no
  encryption.
  """

  alias OPCUA.{Binary, NodeId, Transport}

  @none "http://opcfoundation.org/UA/SecurityPolicy#None"

  # Sequence numbers wrap to below 1024 after this (Part 6, 6.7.2.4).
  @wrap 4_294_966_271

  defstruct policy_uri: @none,
            channel_id: 0,
            token_id: 0,
            previous_token_id: nil,
            send_sequence: 0,
            receive_sequence: nil,
            request_id: 0,
            # What we may send: the other side's receive limits.
            send_chunk_size: 8192,
            send_max_message: 0,
            send_max_chunks: 0,
            # What we accept.
            receive_max_message: 16_777_216,
            receive_max_chunks: 4096,
            partial: %{}

  @type t :: %__MODULE__{}
  @type kind :: :open | :message | :close

  @doc "The URI of the None security policy."
  def none, do: @none

  @doc """
  A new channel. `limits` are what the other side said it accepts (from its
  Hello or Acknowledge); `receive_max_message` and `receive_max_chunks` in
  `opts` cap what we accept.
  """
  @spec new(Transport.limits(), keyword) :: t
  def new(limits, opts \\ []) do
    %__MODULE__{
      send_chunk_size: limits.receive_buffer_size,
      send_max_message: limits.max_message_size,
      send_max_chunks: limits.max_chunk_count,
      receive_max_message: Keyword.get(opts, :receive_max_message, 16_777_216),
      receive_max_chunks: Keyword.get(opts, :receive_max_chunks, 4096)
    }
  end

  @doc "Takes the next request id, for a client sending a request."
  @spec next_request_id(t) :: {pos_integer, t}
  def next_request_id(%{request_id: id} = channel) do
    id = if id >= 0xFFFF_FFFF, do: 1, else: id + 1
    {id, %{channel | request_id: id}}
  end

  @doc """
  Records the security token of an OpenSecureChannel response. A client calls
  this with the response it received; a server with the one it sends.
  """
  @spec token(t, OPCUA.Types.ChannelSecurityToken.t()) :: t
  def token(channel, %{channel_id: channel_id, token_id: token_id}) do
    previous = if channel.token_id != 0 and channel.token_id != token_id, do: channel.token_id
    %{channel | channel_id: channel_id, token_id: token_id, previous_token_id: previous}
  end

  @doc """
  Encodes a service message (a request or response struct from
  `OPCUA.Types`) as the chunks of an `:open`, `:message` or `:close`.
  """
  @spec encode(t, kind, pos_integer, struct) :: {:ok, [iodata], t} | {:error, atom}
  def encode(channel, kind, request_id, %module{} = message) do
    body =
      IO.iodata_to_binary([
        Binary.encode(%NodeId{id: module.encoding_id()}, :node_id),
        module.encode(message)
      ])

    header = security_header(channel, kind)
    room = channel.send_chunk_size - 8 - 4 - IO.iodata_length(header) - 8
    count = max(1, div(byte_size(body) + room - 1, room))

    cond do
      channel.send_max_message != 0 and byte_size(body) > channel.send_max_message ->
        {:error, too_large(kind)}

      channel.send_max_chunks != 0 and count > channel.send_max_chunks ->
        {:error, too_large(kind)}

      true ->
        {frames, channel} = chunks(channel, kind, header, request_id, body, room, [])
        {:ok, frames, channel}
    end
  end

  defp too_large(:message), do: :bad_request_too_large
  defp too_large(_), do: :bad_encoding_limits_exceeded

  defp chunks(channel, kind, header, request_id, body, room, acc) do
    {part, rest, chunk} =
      if byte_size(body) > room,
        do:
          {binary_part(body, 0, room), binary_part(body, room, byte_size(body) - room),
           :continued},
        else: {body, <<>>, :final}

    sequence = next_sequence(channel.send_sequence)

    payload = [
      <<channel.channel_id::little-32>>,
      header,
      <<sequence::little-32, request_id::little-32>>,
      part
    ]

    frame = Transport.frame(kind, chunk, payload)
    channel = %{channel | send_sequence: sequence}

    case chunk do
      :final -> {Enum.reverse([frame | acc]), channel}
      :continued -> chunks(channel, kind, header, request_id, rest, room, [frame | acc])
    end
  end

  defp security_header(channel, :open) do
    [
      Binary.encode(channel.policy_uri, :string),
      Binary.encode(nil, :byte_string),
      Binary.encode(nil, :byte_string)
    ]
  end

  defp security_header(channel, _), do: <<channel.token_id::little-32>>

  defp next_sequence(n) when n >= @wrap, do: 1
  defp next_sequence(n), do: n + 1

  @doc """
  Takes in one chunk, as split off by `OPCUA.Transport.split/2`.

  Returns `{:ok, channel}` while a message is incomplete, and
  `{:ok, {kind, request_id, message}, channel}` once it's whole. An aborted
  message gives `{:abort, request_id, status, reason, channel}`. Anything that
  breaks the channel, such as a sequence number out of order, is
  `{:error, status}`, after which the connection should be closed.
  """
  @spec receive(t, {kind, Transport.chunk(), binary}) ::
          {:ok, t}
          | {:ok, {kind, non_neg_integer, struct}, t}
          | {:abort, non_neg_integer, integer, String.t() | nil, t}
          | {:error, atom}
  def receive(channel, {kind, chunk, <<channel_id::little-32, rest::binary>>})
      when kind in [:open, :message, :close] do
    with :ok <- check_channel(channel, kind, channel_id),
         {:ok, rest} <- check_security(channel, kind, rest),
         <<sequence::little-32, request_id::little-32, body::binary>> <- rest,
         :ok <- check_sequence(channel, sequence) do
      channel = %{channel | receive_sequence: sequence}
      assemble(channel, kind, chunk, request_id, body)
    else
      {:error, _} = error -> error
      _ -> {:error, :bad_decoding_error}
    end
  end

  def receive(_, _), do: {:error, :bad_tcp_message_type_invalid}

  # A client learns the channel id from the first OpenSecureChannel response.
  defp check_channel(%{channel_id: 0}, :open, _), do: :ok
  defp check_channel(%{channel_id: id}, _, id), do: :ok
  defp check_channel(_, _, _), do: {:error, :bad_secure_channel_id_invalid}

  defp check_security(channel, :open, rest) do
    with {:ok, uri, rest} <- Binary.decode(rest, :string),
         {:ok, _certificate, rest} <- Binary.decode(rest, :byte_string),
         {:ok, _thumbprint, rest} <- Binary.decode(rest, :byte_string) do
      if uri == channel.policy_uri, do: {:ok, rest}, else: {:error, :bad_security_policy_rejected}
    end
  end

  defp check_security(channel, _, <<token::little-32, rest::binary>>) do
    if token == channel.token_id or token == channel.previous_token_id,
      do: {:ok, rest},
      else: {:error, :bad_secure_channel_token_unknown}
  end

  defp check_security(_, _, _), do: {:error, :bad_decoding_error}

  defp check_sequence(%{receive_sequence: nil}, _), do: :ok

  defp check_sequence(%{receive_sequence: last}, sequence) when last >= @wrap and sequence < 1024,
    do: :ok

  defp check_sequence(%{receive_sequence: last}, sequence) when sequence == last + 1, do: :ok
  defp check_sequence(_, _), do: {:error, :bad_sequence_number_invalid}

  defp assemble(channel, _kind, :abort, request_id, body) do
    channel = %{channel | partial: Map.delete(channel.partial, request_id)}

    case Transport.decode(:error, body) do
      {:ok, {status, reason}} -> {:abort, request_id, status, reason, channel}
      _ -> {:error, :bad_decoding_error}
    end
  end

  defp assemble(channel, kind, chunk, request_id, body) do
    {parts, size, count} = Map.get(channel.partial, request_id, {[], 0, 0})
    parts = [body | parts]
    size = size + byte_size(body)
    count = count + 1

    cond do
      size > channel.receive_max_message or count > channel.receive_max_chunks ->
        {:error, :bad_encoding_limits_exceeded}

      chunk == :continued ->
        {:ok, %{channel | partial: Map.put(channel.partial, request_id, {parts, size, count})}}

      true ->
        channel = %{channel | partial: Map.delete(channel.partial, request_id)}

        case decode_message(parts |> Enum.reverse() |> IO.iodata_to_binary()) do
          {:ok, message} -> {:ok, {kind, request_id, message}, channel}
          {:error, _} = error -> error
        end
    end
  end

  @doc false
  # A service message is the node id of its binary encoding followed by the structure.
  def decode_message(body) do
    with {:ok, %NodeId{ns: 0, id: id}, rest} <- Binary.decode(body, :node_id),
         module when module != nil <- OPCUA.Types.by_encoding(id),
         {:ok, message, _} <- Binary.decode(rest, module) do
      {:ok, message}
    else
      _ -> {:error, :bad_decoding_error}
    end
  end
end
