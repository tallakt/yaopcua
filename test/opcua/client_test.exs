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

  test "the session's server certificate must be the channel's" do
    {cert, _} = OPCUA.Certificate.self_signed("urn:a")
    {other, _} = OPCUA.Certificate.self_signed("urn:b")
    security = %{policy: :basic256sha256, server_certificate: cert}
    check = &OPCUA.Client.Connection.session_certificate/2

    assert check.(security, cert) == :ok
    assert check.(security, cert <> other) == :ok
    assert check.(%{security | server_certificate: cert <> other}, cert) == :ok
    assert check.(security, nil) == :ok
    assert check.(security, other) == {:error, :bad_certificate_invalid}
    assert check.(security, other <> cert) == {:error, :bad_certificate_invalid}
    assert check.(%{policy: :none}, other) == :ok
  end

  test "method arguments of namespace 0's data types go as the built-in types they're encoded as" do
    builtin = &OPCUA.Client.Arguments.builtin(OPCUA.NodeIds.node_id!(&1))

    assert builtin.("UInt16") == :uint16
    assert builtin.("Duration") == :double
    assert builtin.("UtcTime") == :date_time
    assert builtin.("LocaleId") == :string
    assert builtin.("Counter") == :uint32
    assert builtin.("NodeClass") == :int32
    assert builtin.("Image") == :byte_string

    # Types that leave it open, and those of other namespaces.
    for open <- ~w(BaseDataType Number Integer UInteger Structure Range),
        do: assert(builtin.(open) == nil)

    assert OPCUA.Client.Arguments.builtin(%OPCUA.NodeId{ns: 2, id: 5}) == nil
  end
end
