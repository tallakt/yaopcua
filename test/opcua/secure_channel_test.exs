defmodule OPCUA.SecureChannelTest do
  use ExUnit.Case, async: true

  alias OPCUA.{SecureChannel, Transport, Types}

  @limits %{
    protocol_version: 0,
    receive_buffer_size: 8192,
    send_buffer_size: 8192,
    max_message_size: 0,
    max_chunk_count: 0
  }
  @token %Types.ChannelSecurityToken{channel_id: 7, token_id: 3, revised_lifetime: 60_000}

  # Certificates for the security tests.
  setup_all do
    {client_cert, client_key} = OPCUA.Certificate.self_signed("urn:client")
    {server_cert, server_key} = OPCUA.Certificate.self_signed("urn:server")

    %{
      client_cert: client_cert,
      client_key: client_key,
      server_cert: server_cert,
      server_key: server_key
    }
  end

  # A client and a server that have exchanged an OpenSecureChannel.
  defp pair do
    client = SecureChannel.new(@limits) |> SecureChannel.token(@token)
    server = SecureChannel.new(@limits) |> SecureChannel.token(@token)
    {client, server}
  end

  defp chunks(frames), do: frames |> IO.iodata_to_binary() |> Transport.split(100_000) |> elem(1)

  defp deliver(channel, chunks) do
    Enum.reduce(chunks, {channel, nil}, fn chunk, {channel, _} ->
      case SecureChannel.receive(channel, chunk) do
        {:ok, channel} -> {channel, nil}
        {:ok, message, channel} -> {channel, message}
        other -> throw(other)
      end
    end)
  end

  defp read(n),
    do: %Types.ReadRequest{
      nodes_to_read:
        for(
          i <- 1..n,
          do: %Types.ReadValueId{node_id: %OPCUA.NodeId{ns: 2, id: i}, attribute_id: 13}
        )
    }

  test "a message goes through as one chunk" do
    {client, server} = pair()
    {1, client} = SecureChannel.next_request_id(client)
    {:ok, frames, _client} = SecureChannel.encode(client, :message, 1, read(1))

    assert [
             {:message, :final,
              <<7::little-32, 3::little-32, 1::little-32, 1::little-32, _::binary>>}
           ] = chunks(frames)

    assert {_, {:message, 1, %Types.ReadRequest{}}} = deliver(server, chunks(frames))
  end

  test "a message bigger than the other side's buffer is split into chunks, and put back together" do
    {client, server} = pair()
    request = read(2000)
    {:ok, frames, client} = SecureChannel.encode(client, :message, 1, request)
    parts = chunks(frames)

    assert length(parts) > 3
    assert Enum.all?(parts, fn {_, _, body} -> byte_size(body) + 8 <= 8192 end)

    assert Enum.map(parts, &elem(&1, 1)) ==
             List.duplicate(:continued, length(parts) - 1) ++ [:final]

    assert client.send_sequence == length(parts)

    {server, {:message, 1, received}} = deliver(server, parts)
    assert %{received | request_header: nil} == %{request | request_header: nil}
    assert server.partial == %{}
  end

  test "an open carries the security policy instead of a token id" do
    client = SecureChannel.new(@limits)

    {:ok, frames, _} =
      SecureChannel.encode(client, :open, 1, %Types.OpenSecureChannelRequest{request_type: :issue})

    none = SecureChannel.none()
    size = byte_size(none)

    assert [
             {:open, :final,
              <<0::32, ^size::little-32, ^none::binary-size(size), -1::little-signed-32,
                -1::little-signed-32, 1::little-32, 1::little-32, _::binary>>}
           ] = chunks(frames)
  end

  test "sequence numbers must follow each other" do
    {client, server} = pair()
    {:ok, first, client} = SecureChannel.encode(client, :message, 1, read(1))
    {:ok, _skipped, client} = SecureChannel.encode(client, :message, 2, read(1))
    {:ok, third, _} = SecureChannel.encode(client, :message, 3, read(1))

    {server, _} = deliver(server, chunks(first))

    assert SecureChannel.receive(server, hd(chunks(third))) ==
             {:error, :bad_sequence_number_invalid}
  end

  test "sequence numbers wrap to below 1024" do
    {client, server} = pair()
    client = %{client | send_sequence: 4_294_966_271}
    server = %{server | receive_sequence: 4_294_966_271}
    {:ok, frames, client} = SecureChannel.encode(client, :message, 1, read(1))
    assert client.send_sequence == 1
    assert {_, {:message, 1, _}} = deliver(server, chunks(frames))
  end

  test "a chunk for another channel or an unknown token is refused" do
    {client, server} = pair()
    {:ok, frames, _} = SecureChannel.encode(%{client | channel_id: 8}, :message, 1, read(1))

    assert SecureChannel.receive(server, hd(chunks(frames))) ==
             {:error, :bad_secure_channel_id_invalid}

    {:ok, frames, _} = SecureChannel.encode(%{client | token_id: 4}, :message, 1, read(1))

    assert SecureChannel.receive(server, hd(chunks(frames))) ==
             {:error, :bad_secure_channel_token_unknown}
  end

  test "after a renewal the old token is still accepted" do
    {client, server} = pair()
    server = SecureChannel.token(server, %{@token | token_id: 4})
    {:ok, old, client} = SecureChannel.encode(client, :message, 1, read(1))

    {:ok, new, _} =
      SecureChannel.encode(
        SecureChannel.token(client, %{@token | token_id: 4}),
        :message,
        2,
        read(1)
      )

    {server, {:message, 1, _}} = deliver(server, chunks(old))
    assert {_, {:message, 2, _}} = deliver(server, chunks(new))
  end

  test "an aborted message drops what came before and reports the status" do
    {client, server} = pair()
    {:ok, frames, _} = SecureChannel.encode(client, :message, 5, read(2000))
    [first | _] = chunks(frames)
    {server, nil} = deliver(server, [first])
    assert map_size(server.partial) == 1

    # the next chunk after the one delivered aborts the message
    abort =
      Transport.frame(:message, :abort, [
        <<7::little-32, 3::little-32, 2::little-32, 5::little-32>>,
        Transport.error(:bad_request_too_large, "too big")
      ])

    [chunk] = chunks(abort)
    assert {:abort, 5, 0x80B80000, "too big", server} = SecureChannel.receive(server, chunk)
    assert server.partial == %{}
  end

  test "refuses to receive more than its message limit" do
    {client, server} = pair()
    server = %{server | receive_max_message: 10_000}
    {:ok, frames, _} = SecureChannel.encode(client, :message, 1, read(2000))
    assert catch_throw(deliver(server, chunks(frames))) == {:error, :bad_encoding_limits_exceeded}
  end

  test "refuses to send more than the other side's limits" do
    {client, _} = pair()

    assert SecureChannel.encode(%{client | send_max_message: 1000}, :message, 1, read(2000)) ==
             {:error, :bad_request_too_large}

    assert SecureChannel.encode(%{client | send_max_chunks: 2}, :message, 1, read(2000)) ==
             {:error, :bad_request_too_large}
  end

  describe "security" do
    # A client and a server that have opened a channel with this policy and
    # mode, the way the client and server modules do it.
    defp secure_pair(keys, policy, mode) do
      client =
        SecureChannel.new(@limits,
          policy: policy,
          mode: mode,
          certificate: keys.client_cert,
          private_key: keys.client_key,
          remote_certificate: keys.server_cert
        )

      server =
        SecureChannel.new(@limits,
          policies: [:none, policy],
          certificate: keys.server_cert,
          private_key: keys.server_key
        )

      client_nonce = :crypto.strong_rand_bytes(32)
      server_nonce = :crypto.strong_rand_bytes(32)

      request = %Types.OpenSecureChannelRequest{
        request_type: :issue,
        security_mode: mode,
        client_nonce: client_nonce
      }

      {:ok, frames, client} = SecureChannel.encode(client, :open, 1, request)
      {server, {:open, 1, %{client_nonce: ^client_nonce}}} = deliver(server, chunks(frames))
      assert server.policy == policy
      assert server.remote_certificate == keys.client_cert

      server = %{SecureChannel.token(server, @token, server_nonce, client_nonce) | mode: mode}

      response = %Types.OpenSecureChannelResponse{
        security_token: @token,
        server_nonce: server_nonce
      }

      {:ok, frames, server} = SecureChannel.encode(server, :open, 1, response)
      {client, {:open, 1, %{server_nonce: ^server_nonce}}} = deliver(client, chunks(frames))
      {SecureChannel.token(client, @token, client_nonce, server_nonce), server}
    end

    for policy <- [:basic256sha256, :aes128_sha256_rsa_oaep, :aes256_sha256_rsa_pss],
        mode <- [:sign, :sign_and_encrypt] do
      test "#{policy} #{mode}: messages in chunks both ways", keys do
        {client, server} = secure_pair(keys, unquote(policy), unquote(mode))
        request = read(1500)
        {:ok, frames, client} = SecureChannel.encode(client, :message, 2, request)
        parts = chunks(frames)
        assert length(parts) > 1
        assert Enum.all?(parts, fn {_, _, body} -> byte_size(body) + 8 <= 8192 end)

        {server, {:message, 2, received}} = deliver(server, parts)
        assert received.nodes_to_read == request.nodes_to_read

        {:ok, frames, _} =
          SecureChannel.encode(server, :message, 2, %Types.ReadResponse{results: []})

        assert {_, {:message, 2, %Types.ReadResponse{}}} = deliver(client, chunks(frames))
        _ = client
      end
    end

    test "encryption hides the body, signing alone doesn't", keys do
      secret = "Pump1.SecretSpeed"

      message = %Types.ReadRequest{
        nodes_to_read: [
          %Types.ReadValueId{node_id: %OPCUA.NodeId{ns: 2, id: secret}, attribute_id: 13}
        ]
      }

      {client, _} = secure_pair(keys, :basic256sha256, :sign)
      {:ok, frames, _} = SecureChannel.encode(client, :message, 2, message)
      assert IO.iodata_to_binary(frames) =~ secret

      {client, _} = secure_pair(keys, :basic256sha256, :sign_and_encrypt)
      {:ok, frames, _} = SecureChannel.encode(client, :message, 2, message)
      refute IO.iodata_to_binary(frames) =~ secret
    end

    test "a changed byte fails the signature", keys do
      for mode <- [:sign, :sign_and_encrypt] do
        {client, server} = secure_pair(keys, :aes256_sha256_rsa_pss, mode)
        {:ok, frames, _} = SecureChannel.encode(client, :message, 2, read(1))
        [{kind, chunk, body}] = chunks(frames)

        flipped =
          binary_part(body, 0, 20) <>
            <<Bitwise.bxor(:binary.at(body, 20), 1)>> <>
            binary_part(body, 21, byte_size(body) - 21)

        assert SecureChannel.receive(server, {kind, chunk, flipped}) ==
                 {:error, :bad_security_checks_failed}
      end
    end

    test "an open for another certificate, or with a policy not offered, is refused", keys do
      {other, _} = OPCUA.Certificate.self_signed("urn:other")

      client =
        SecureChannel.new(@limits,
          policy: :basic256sha256,
          mode: :sign,
          certificate: keys.client_cert,
          private_key: keys.client_key,
          remote_certificate: other
        )

      {:ok, frames, _} =
        SecureChannel.encode(client, :open, 1, %Types.OpenSecureChannelRequest{
          client_nonce: :crypto.strong_rand_bytes(32)
        })

      server =
        SecureChannel.new(@limits,
          policies: [:basic256sha256],
          certificate: keys.server_cert,
          private_key: keys.server_key
        )

      assert SecureChannel.receive(server, hd(chunks(frames))) ==
               {:error, :bad_certificate_invalid}

      strict =
        SecureChannel.new(@limits,
          policies: [:none, :aes256_sha256_rsa_pss],
          certificate: keys.server_cert,
          private_key: keys.server_key
        )

      client = %{client | remote_certificate: keys.server_cert}

      {:ok, frames, _} =
        SecureChannel.encode(client, :open, 1, %Types.OpenSecureChannelRequest{
          client_nonce: :crypto.strong_rand_bytes(32)
        })

      assert SecureChannel.receive(strict, hd(chunks(frames))) ==
               {:error, :bad_security_policy_rejected}
    end

    test "a renewed token brings new keys, and the old ones still work until then", keys do
      {client, server} = secure_pair(keys, :basic256sha256, :sign_and_encrypt)
      {:ok, old, client} = SecureChannel.encode(client, :message, 2, read(1))

      renewed = %{@token | token_id: 4}
      [client_nonce, server_nonce] = for _ <- 1..2, do: :crypto.strong_rand_bytes(32)
      server = SecureChannel.token(server, renewed, server_nonce, client_nonce)
      client = SecureChannel.token(client, renewed, client_nonce, server_nonce)
      assert client.keys[4] != client.keys[3]
      {:ok, new, _} = SecureChannel.encode(client, :message, 3, read(1))

      {server, {:message, 2, _}} = deliver(server, chunks(old))
      assert {_, {:message, 3, _}} = deliver(server, chunks(new))
    end
  end
end
