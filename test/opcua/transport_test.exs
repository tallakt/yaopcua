defmodule OPCUA.TransportTest do
  use ExUnit.Case, async: true

  alias OPCUA.Transport

  @limits %{
    protocol_version: 0,
    receive_buffer_size: 65_535,
    send_buffer_size: 65_535,
    max_message_size: 0,
    max_chunk_count: 0
  }

  test "a chunk is a 3-letter type, a chunk type and the total size" do
    assert Transport.frame(:message, :final, "abc") |> IO.iodata_to_binary() ==
             <<"MSGF", 11::little-32, "abc">>

    assert Transport.frame(:open, :continued, "") |> IO.iodata_to_binary() ==
             <<"OPNC", 8::little-32>>
  end

  test "splits whole chunks off a buffer and keeps the rest" do
    one = Transport.frame(:message, :final, "abc") |> IO.iodata_to_binary()
    two = Transport.frame(:close, :abort, "de") |> IO.iodata_to_binary()
    buffer = one <> two <> binary_part(one, 0, 5)

    assert Transport.split(buffer, 1000) ==
             {:ok, [{:message, :final, "abc"}, {:close, :abort, "de"}], binary_part(one, 0, 5)}

    assert Transport.split(<<"MSG">>, 1000) == {:ok, [], "MSG"}
  end

  test "rejects chunks that are too big or aren't UA-TCP" do
    assert Transport.split(<<"MSGF", 2000::little-32>>, 1000) ==
             {:error, :bad_tcp_message_too_large}

    assert Transport.split(<<"GET / HTTP/1.1\r\n">>, 1000) ==
             {:error, :bad_tcp_message_type_invalid}

    assert Transport.split(<<"MSGX", 8::little-32>>, 1000) ==
             {:error, :bad_tcp_message_type_invalid}
  end

  test "hello and acknowledge carry the buffer sizes and limits" do
    hello = Transport.hello(@limits, "opc.tcp://plc:4840") |> IO.iodata_to_binary()

    assert <<0::32, 65_535::little-32, 65_535::little-32, 0::32, 0::32, 18::little-32,
             "opc.tcp://plc:4840">> = hello

    assert Transport.decode(:hello, hello) == {:ok, {@limits, "opc.tcp://plc:4840"}}

    assert Transport.decode(:acknowledge, Transport.acknowledge(@limits) |> IO.iodata_to_binary()) ==
             {:ok, @limits}
  end

  test "buffers below the spec's 8192 bytes are refused" do
    small = Transport.acknowledge(%{@limits | receive_buffer_size: 1024}) |> IO.iodata_to_binary()
    assert {:error, _} = Transport.decode(:acknowledge, small)
  end

  test "an error carries a status and a reason" do
    body =
      Transport.error(:bad_tcp_endpoint_url_invalid, "no such endpoint") |> IO.iodata_to_binary()

    assert Transport.decode(:error, body) == {:ok, {0x80830000, "no such endpoint"}}
  end

  test "parses endpoint URLs" do
    assert Transport.endpoint("opc.tcp://10.0.0.5:4841/plc") == {:ok, {~c"10.0.0.5", 4841}}
    assert Transport.endpoint("opc.tcp://plc") == {:ok, {~c"plc", 4840}}
    assert Transport.endpoint("http://plc:80") == {:error, :bad_tcp_endpoint_url_invalid}
  end
end
