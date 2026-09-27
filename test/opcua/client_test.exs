defmodule OPCUA.ClientTest do
  use ExUnit.Case, async: false

  alias OPCUA.Client

  test "a server that isn't there is an error from start" do
    {:ok, listener} = :gen_tcp.listen(0, [])
    {:ok, port} = :inet.port(listener)
    :gen_tcp.close(listener)
    assert Client.start(url: "opc.tcp://127.0.0.1:#{port}") == {:error, :econnrefused}
    assert Client.start(url: "http://127.0.0.1") == {:error, :bad_tcp_endpoint_url_invalid}
  end
end
