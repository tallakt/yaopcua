defmodule OPCUA.SecureChannel do
  @moduledoc """
  One side of an OPC UA secure channel (Part 6, section 6.7), as plain data.

  `encode/4` turns a service message into the chunks to send, and `receive/2`
  takes chunks back in and returns whole messages. Neither does any I/O, so a
  client and a server can both build on it, and it can be tested byte by byte.

  Each chunk carries the channel id, a security header, a sequence number and
  the request id. A message bigger than the other side's buffer is split into
  chunks, and reassembled on the way in.

  With a security policy other than None (see `OPCUA.SecurityPolicy`):

    * OpenSecureChannel chunks are signed with the sender's private key and
      encrypted with the receiver's public key, whatever the mode.
    * Other chunks are signed with HMAC-SHA256 in the `:sign` mode, and also
      encrypted with AES-CBC in `:sign_and_encrypt`, with keys derived from the
      nonces the two sides exchanged when they opened or renewed the channel.

  Not supported: the ECC policies, the deprecated Basic128Rsa15 and
  Basic256, and a chain of certificates in the OpenSecureChannel header.
  """

  alias OPCUA.{Binary, Certificate, NodeId, SecurityPolicy, Transport}

  # Sequence numbers wrap to below 1024 after this (Part 6, 6.7.2.4).
  @wrap 4_294_966_271

  # What a chunk starts with: the 8-byte UA-TCP header and the channel id,
  # then the token id in a symmetric one; and the sequence header of
  # sequence number and request id.
  @header 12
  @symmetric_header 16
  @sequence_header 8

  @receive_max_message 16_777_216
  @receive_max_chunks 4096

  defstruct policy: :none,
            mode: :none,
            # The policies a server lets a client open a channel with.
            policies: [:none],
            certificate: nil,
            private_key: nil,
            remote_certificate: nil,
            # The certificates a server trusts, checked before any RSA.
            trust: nil,
            channel_id: 0,
            token_id: 0,
            previous_token_id: nil,
            # The derived keys, by token id: %{send: keys, receive: keys}.
            keys: %{},
            send_sequence: 0,
            receive_sequence: nil,
            request_id: 0,
            # What we may send: the other side's receive limits.
            send_chunk_size: 8192,
            send_max_message: 0,
            send_max_chunks: 0,
            # What we accept.
            receive_max_message: @receive_max_message,
            receive_max_chunks: @receive_max_chunks,
            # Unfinished messages by request id, as {chunks, bytes, count},
            # and the bytes and chunks of all of them together.
            partial: %{},
            held_bytes: 0,
            held_chunks: 0

  @type t :: %__MODULE__{}
  @type kind :: :open | :message | :close

  @doc "The URI of the None security policy."
  def none, do: SecurityPolicy.uri(:none)

  @doc """
  A new channel. `limits` are what the other side said it accepts (from its
  Hello or Acknowledge).

  ## Options

    * `:policy`, `:mode` - the security a client asks for
    * `:policies` - the policies a server accepts; the client's choice is
      learned from its first OpenSecureChannel
    * `:certificate`, `:private_key` - our own
    * `:remote_certificate` - the other side's, which a client knows before
      it opens the channel
    * `:trust` - the certificates a server trusts (see
      `OPCUA.Certificate.trusted?/2`). An OpenSecureChannel with another is
      refused before any costly decryption or signature check.
    * `:receive_max_message`, `:receive_max_chunks` - what we accept
  """
  @spec new(Transport.limits(), keyword) :: t
  def new(limits, opts \\ []) do
    policy = Keyword.get(opts, :policy, :none)

    %__MODULE__{
      policy: policy,
      mode: Keyword.get(opts, :mode, :none),
      policies: Keyword.get(opts, :policies, [policy]),
      certificate: opts[:certificate],
      private_key: opts[:private_key],
      remote_certificate: opts[:remote_certificate],
      trust: opts[:trust],
      send_chunk_size: limits.receive_buffer_size,
      send_max_message: limits.max_message_size,
      send_max_chunks: limits.max_chunk_count,
      receive_max_message: Keyword.get(opts, :receive_max_message, @receive_max_message),
      receive_max_chunks: Keyword.get(opts, :receive_max_chunks, @receive_max_chunks)
    }
  end

  @doc "Takes the next request id, for a client sending a request."
  @spec next_request_id(t) :: {pos_integer, t}
  def next_request_id(%{request_id: id} = channel) do
    id = if id >= 0xFFFF_FFFF, do: 1, else: id + 1
    {id, %{channel | request_id: id}}
  end

  @doc """
  Records the security token of an OpenSecureChannel response, and derives
  its keys from the two nonces. A client calls this with the response it
  received; a server with the one it sends.
  """
  @spec token(t, OPCUA.Types.ChannelSecurityToken.t(), binary | nil, binary | nil) :: t
  def token(
        channel,
        %{channel_id: channel_id, token_id: token_id},
        local_nonce \\ nil,
        remote_nonce \\ nil
      ) do
    previous = if channel.token_id != 0 and channel.token_id != token_id, do: channel.token_id

    keys =
      if channel.policy == :none do
        %{}
      else
        # Each side sends with keys from P_SHA256(other nonce, own nonce).
        current = %{
          send: SecurityPolicy.derive(channel.policy, remote_nonce, local_nonce),
          receive: SecurityPolicy.derive(channel.policy, local_nonce, remote_nonce)
        }

        channel.keys |> Map.take([channel.token_id]) |> Map.put(token_id, current)
      end

    %{
      channel
      | channel_id: channel_id,
        token_id: token_id,
        previous_token_id: previous,
        keys: keys
    }
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

    security = security(channel, kind)
    room = room(channel, kind, security)
    count = max(1, div(byte_size(body) + room - 1, room))

    cond do
      channel.send_max_message != 0 and byte_size(body) > channel.send_max_message ->
        {:error, too_large(kind)}

      channel.send_max_chunks != 0 and count > channel.send_max_chunks ->
        {:error, too_large(kind)}

      true ->
        {frames, channel} = chunks(channel, kind, security, request_id, body, room, [])
        {:ok, frames, channel}
    end
  end

  defp too_large(:message), do: :bad_request_too_large
  defp too_large(_), do: :bad_encoding_limits_exceeded

  defp security(%{policy: policy}, :open) when policy != :none, do: :asymmetric
  defp security(%{mode: mode}, kind) when kind != :open and mode != :none, do: :symmetric
  defp security(_, _), do: :plain

  # How much of a message fits in one chunk, after the headers, padding and
  # signature, and rounded to the cipher's blocks.
  defp room(channel, kind, :plain) do
    channel.send_chunk_size - @header - IO.iodata_length(plain_header(channel, kind)) -
      @sequence_header
  end

  defp room(channel, _, :asymmetric) do
    remote = Certificate.public_key(channel.remote_certificate)
    cipher = SecurityPolicy.key_size(remote)
    plain = SecurityPolicy.plain_block(channel.policy, remote)

    blocks =
      div(channel.send_chunk_size - @header - byte_size(asymmetric_header(channel)), cipher)

    blocks * plain - @sequence_header - SecurityPolicy.key_size(channel.private_key) -
      padding_bytes(plain)
  end

  defp room(%{mode: :sign} = channel, _, :symmetric) do
    channel.send_chunk_size - @symmetric_header - @sequence_header -
      SecurityPolicy.symmetric_signature_size()
  end

  # The padding takes at least its PaddingSize byte.
  defp room(channel, _, :symmetric) do
    block = SecurityPolicy.block_size()

    div(channel.send_chunk_size - @symmetric_header, block) * block - @sequence_header -
      SecurityPolicy.symmetric_signature_size() - 1
  end

  # The PaddingSize byte, and ExtraPaddingSize when a block can hold more
  # than 256 bytes (keys over 2048 bits).
  defp padding_bytes(plain_block) when plain_block > 256, do: 2
  defp padding_bytes(_), do: 1

  defp chunks(channel, kind, security, request_id, body, room, acc) do
    {part, rest, chunk} =
      if byte_size(body) > room,
        do:
          {binary_part(body, 0, room), binary_part(body, room, byte_size(body) - room),
           :continued},
        else: {body, <<>>, :final}

    sequence = next_sequence(channel.send_sequence)
    plain = <<sequence::little-32, request_id::little-32, part::binary>>
    frame = frame(channel, kind, chunk, security, plain)
    channel = %{channel | send_sequence: sequence}

    case chunk do
      :final -> {Enum.reverse([frame | acc]), channel}
      :continued -> chunks(channel, kind, security, request_id, rest, room, [frame | acc])
    end
  end

  defp frame(channel, kind, chunk, :plain, plain) do
    Transport.frame(kind, chunk, [
      <<channel.channel_id::little-32>>,
      plain_header(channel, kind),
      plain
    ])
  end

  defp frame(channel, kind, chunk, :asymmetric, plain) do
    remote = Certificate.public_key(channel.remote_certificate)
    block = SecurityPolicy.plain_block(channel.policy, remote)
    signature_size = SecurityPolicy.key_size(channel.private_key)
    padded = pad(plain, signature_size, block)
    security = asymmetric_header(channel)

    body_size =
      4 + byte_size(security) +
        div(byte_size(padded) + signature_size, block) * SecurityPolicy.key_size(remote)

    signed =
      Transport.header(kind, chunk, body_size) <>
        <<channel.channel_id::little-32>> <> security <> padded

    signature = SecurityPolicy.sign(channel.policy, signed, channel.private_key)

    [
      binary_part(signed, 0, @header + byte_size(security)),
      SecurityPolicy.encrypt(channel.policy, padded <> signature, remote)
    ]
  end

  defp frame(channel, kind, chunk, :symmetric, plain) do
    keys = channel.keys[channel.token_id].send
    signature_size = SecurityPolicy.symmetric_signature_size()
    encrypt = channel.mode == :sign_and_encrypt
    padded = if encrypt, do: pad(plain, signature_size, SecurityPolicy.block_size()), else: plain

    prefix =
      Transport.header(kind, chunk, 8 + byte_size(padded) + signature_size) <>
        <<channel.channel_id::little-32, channel.token_id::little-32>>

    signed = padded <> SecurityPolicy.mac(keys, prefix <> padded)

    [
      prefix,
      if(encrypt,
        do: SecurityPolicy.encrypt_symmetric(channel.policy, keys, signed),
        else: signed
      )
    ]
  end

  # Padding so that the plain text and the signature fill whole blocks: a
  # PaddingSize byte, that many bytes of it, and the high byte after them
  # when blocks are bigger than 256 bytes.
  defp pad(plain, signature_size, block) do
    extra = padding_bytes(block) - 1
    count = rem(block - rem(byte_size(plain) + 1 + extra + signature_size, block), block)
    low = Bitwise.band(count, 0xFF)
    high = if extra == 1, do: <<Bitwise.bsr(count, 8)>>, else: <<>>
    plain <> <<low>> <> :binary.copy(<<low>>, count) <> high
  end

  defp unpad(data, block) do
    size = byte_size(data)

    count =
      if padding_bytes(block) == 2,
        do: :binary.at(data, size - 1) * 256 + :binary.at(data, size - 2),
        else: :binary.at(data, size - 1)

    keep = size - count - padding_bytes(block)

    if keep >= @sequence_header,
      do: {:ok, binary_part(data, 0, keep)},
      else: {:error, :bad_security_checks_failed}
  end

  defp plain_header(_channel, :open),
    do: [
      Binary.encode(none(), :string),
      Binary.encode(nil, :byte_string),
      Binary.encode(nil, :byte_string)
    ]

  defp plain_header(channel, _), do: <<channel.token_id::little-32>>

  defp asymmetric_header(channel) do
    IO.iodata_to_binary([
      Binary.encode(SecurityPolicy.uri(channel.policy), :string),
      Binary.encode(channel.certificate, :byte_string),
      Binary.encode(Certificate.thumbprint(channel.remote_certificate), :byte_string)
    ])
  end

  defp next_sequence(n) when n >= @wrap, do: 1
  defp next_sequence(n), do: n + 1

  @doc """
  Takes in one chunk, as split off by `OPCUA.Transport.split/2`.

  Returns `{:ok, channel}` while a message is incomplete, and
  `{:ok, {kind, request_id, message}, channel}` once it's whole. An aborted
  message gives `{:abort, request_id, status, reason, channel}`. Anything that
  breaks the channel, such as a sequence number out of order or a signature
  that doesn't verify, is `{:error, status}`, after which the connection
  should be closed.

  A server learns the client's security policy and certificate from its first
  OpenSecureChannel; they're in `channel.policy` and
  `channel.remote_certificate` for it to check.
  """
  @spec receive(t, {kind, Transport.chunk(), binary}) ::
          {:ok, t}
          | {:ok, {kind, non_neg_integer, struct}, t}
          | {:abort, non_neg_integer, integer, String.t() | nil, t}
          | {:error, atom}
  def receive(channel, {kind, chunk, <<channel_id::little-32, rest::binary>> = body})
      when kind in [:open, :message, :close] do
    prefix = Transport.header(kind, chunk, byte_size(body)) <> <<channel_id::little-32>>

    with :ok <- check_channel(channel, kind, channel_id),
         {:ok, channel, plain} <- unsecure(channel, kind, prefix, rest),
         <<sequence::little-32, request_id::little-32, body::binary>> <- plain,
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

  defp unsecure(channel, :open, prefix, rest) do
    with {:ok, uri, after_uri} <- Binary.decode(rest, :string),
         {:ok, certificate, after_certificate} <- Binary.decode(after_uri, :byte_string),
         {:ok, thumbprint, encrypted} <- Binary.decode(after_certificate, :byte_string),
         {:ok, channel} <- accept_policy(channel, SecurityPolicy.from_uri(uri), certificate) do
      header = binary_part(rest, 0, byte_size(rest) - byte_size(encrypted))

      if channel.policy == :none,
        do: {:ok, channel, encrypted},
        else: open_secured(channel, prefix <> header, thumbprint, encrypted)
    end
  end

  defp unsecure(channel, _, prefix, <<token::little-32, rest::binary>>) do
    cond do
      token != channel.token_id and token != channel.previous_token_id ->
        {:error, :bad_secure_channel_token_unknown}

      channel.mode == :none ->
        {:ok, channel, rest}

      true ->
        symmetric_secured(
          channel,
          channel.keys[token].receive,
          prefix <> <<token::little-32>>,
          rest
        )
    end
  end

  defp unsecure(_, _, _, _), do: {:error, :bad_decoding_error}

  # The policy must be one we accept, and stay the same when the channel is renewed.
  defp accept_policy(channel, policy, certificate) do
    cond do
      policy not in channel.policies ->
        {:error, :bad_security_policy_rejected}

      channel.token_id != 0 and policy != channel.policy ->
        {:error, :bad_security_policy_rejected}

      policy == :none ->
        {:ok, %{channel | policy: :none}}

      certificate in [nil, ""] ->
        {:error, :bad_certificate_invalid}

      channel.remote_certificate not in [nil, certificate] ->
        {:error, :bad_certificate_invalid}

      not SecurityPolicy.key_bits?(policy, Certificate.key_bits(certificate)) ->
        {:error, :bad_certificate_policy_check_failed}

      channel.trust != nil and not Certificate.trusted?(certificate, channel.trust) ->
        {:error, :bad_certificate_untrusted}

      true ->
        {:ok, %{channel | policy: policy, remote_certificate: certificate}}
    end
  end

  defp open_secured(channel, signed_prefix, thumbprint, encrypted) do
    public_key = SecurityPolicy.public_key(channel.private_key)
    sender = Certificate.public_key(channel.remote_certificate)
    signature_size = SecurityPolicy.key_size(sender)

    with true <-
           thumbprint == Certificate.thumbprint(channel.certificate) ||
             {:error, :bad_certificate_invalid},
         {:ok, plain} <- SecurityPolicy.decrypt(channel.policy, encrypted, channel.private_key),
         true <- byte_size(plain) > signature_size || {:error, :bad_security_checks_failed},
         data = binary_part(plain, 0, byte_size(plain) - signature_size),
         signature = binary_part(plain, byte_size(data), signature_size),
         true <-
           SecurityPolicy.verify(channel.policy, signed_prefix <> data, signature, sender) ||
             {:error, :bad_security_checks_failed},
         {:ok, plain} <- unpad(data, SecurityPolicy.plain_block(channel.policy, public_key)) do
      {:ok, channel, plain}
    end
  rescue
    # The other side's certificate and ciphertext are whatever it sent, and
    # :public_key raises on what it can't parse.
    _ -> {:error, :bad_security_checks_failed}
  end

  defp symmetric_secured(channel, keys, prefix, rest) do
    signature_size = SecurityPolicy.symmetric_signature_size()
    encrypted = channel.mode == :sign_and_encrypt

    with {:ok, plain} <-
           if(encrypted,
             do: SecurityPolicy.decrypt_symmetric(channel.policy, keys, rest),
             else: {:ok, rest}
           ),
         true <- byte_size(plain) > signature_size || {:error, :bad_security_checks_failed},
         data = binary_part(plain, 0, byte_size(plain) - signature_size),
         signature = binary_part(plain, byte_size(data), signature_size),
         true <-
           :crypto.hash_equals(SecurityPolicy.mac(keys, prefix <> data), signature) ||
             {:error, :bad_security_checks_failed} do
      if encrypted,
        do:
          with({:ok, data} <- unpad(data, SecurityPolicy.block_size()), do: {:ok, channel, data}),
        else: {:ok, channel, data}
    end
  end

  defp check_sequence(%{receive_sequence: nil}, _), do: :ok

  defp check_sequence(%{receive_sequence: last}, sequence) when last >= @wrap and sequence < 1024,
    do: :ok

  defp check_sequence(%{receive_sequence: last}, sequence) when sequence == last + 1, do: :ok
  defp check_sequence(_, _), do: {:error, :bad_sequence_number_invalid}

  defp assemble(channel, _kind, :abort, request_id, body) do
    {_, channel} = pop_partial(channel, request_id)

    case Transport.decode(:error, body) do
      {:ok, {status, reason}} -> {:abort, request_id, status, reason, channel}
      _ -> {:error, :bad_decoding_error}
    end
  end

  defp assemble(channel, kind, chunk, request_id, body) do
    {parts, size, count} = Map.get(channel.partial, request_id, {[], 0, 0})
    partial = {[body | parts], size + byte_size(body), count + 1}

    channel = %{
      channel
      | partial: Map.put(channel.partial, request_id, partial),
        held_bytes: channel.held_bytes + byte_size(body),
        held_chunks: channel.held_chunks + 1
    }

    cond do
      # Unfinished messages, however many, together stay within the limits
      # of one.
      channel.held_bytes > channel.receive_max_message or
          channel.held_chunks > channel.receive_max_chunks ->
        {:error, :bad_encoding_limits_exceeded}

      chunk == :continued ->
        {:ok, channel}

      true ->
        {{parts, _, _}, channel} = pop_partial(channel, request_id)

        case decode_message(parts |> Enum.reverse() |> IO.iodata_to_binary()) do
          {:ok, message} -> {:ok, {kind, request_id, message}, channel}
          {:error, _} = error -> error
        end
    end
  end

  defp pop_partial(channel, request_id) do
    {{_, size, count} = partial, rest} = Map.pop(channel.partial, request_id, {[], 0, 0})

    {partial,
     %{
       channel
       | partial: rest,
         held_bytes: channel.held_bytes - size,
         held_chunks: channel.held_chunks - count
     }}
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
