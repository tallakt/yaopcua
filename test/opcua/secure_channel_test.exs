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
  @token %Types.ChannelSecurityToken{channel_id: 7, token_id: 3, revised_lifetime: 60_000.0}

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
end
