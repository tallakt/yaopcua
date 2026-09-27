defmodule OPCUA.ClientInteropTest do
  # Runs the client against asyncua, an independent OPC UA server written in
  # Python, started as a separate process. See test_helper.exs.
  use ExUnit.Case, async: false

  @moduletag :interop

  alias OPCUA.{Client, DataValue, Variant}

  setup_all do
    {:ok, listener} = :gen_tcp.listen(0, [])
    {:ok, port} = :inet.port(listener)
    :gen_tcp.close(listener)

    python = System.fetch_env!("ASYNCUA_PYTHON")
    script = Path.expand("../support/asyncua_server.py", __DIR__)

    server =
      Port.open({:spawn_executable, python}, [
        :binary,
        :exit_status,
        :stderr_to_stdout,
        line: 4096,
        args: [script, to_string(port)]
      ])

    # The port closes when the setup_all process exits after the last test,
    # which closes the server's stdin and stops it.
    ready(server)
    %{url: "opc.tcp://127.0.0.1:#{port}/yaopcua/"}
  end

  defp ready(server) do
    receive do
      {^server, {:data, {:eol, "ready"}}} -> :ok
      {^server, {:data, _}} -> ready(server)
      {^server, {:exit_status, status}} -> flunk("asyncua server exited with #{status}")
    after
      15_000 -> flunk("asyncua server didn't start")
    end
  end

  setup %{url: url} do
    %{client: start_supervised!({Client, url: url})}
  end

  test "lists the server's endpoints without a session", %{url: url} do
    assert {:ok, [endpoint]} = Client.endpoints(url)
    assert endpoint.security_mode == :none
    assert Enum.map(endpoint.user_identity_tokens, & &1.token_type) == [:anonymous, :user_name]
  end

  test "reads scalars, arrays and structures", %{client: client} do
    assert Client.read(client, "ns=2;s=Pump1.Running") == {:ok, true}
    assert Client.read(client, "ns=2;s=Pump1.Name") == {:ok, "Pump 1"}
    assert Client.read(client, "ns=2;s=Tank.Setpoints") == {:ok, [1.0, 2.0, 3.0]}

    assert {:ok, %OPCUA.Types.ServerStatusDataType{state: :running}} =
             Client.read(client, "i=2256")

    assert Client.read(client, "ns=2;s=Pump1.Name", :browse_name) ==
             {:ok, %OPCUA.QualifiedName{ns: 2, name: "Pump1.Name"}}
  end

  test "an unknown node is an error", %{client: client} do
    assert Client.read(client, "ns=2;s=Nope") == {:error, :bad_node_id_unknown}
  end

  test "reads several nodes with their status and timestamps", %{client: client} do
    assert {:ok, [level, missing]} =
             Client.read_many(client, ["ns=2;s=Tank.Level", "ns=2;s=Nope"])

    assert %DataValue{value: %Variant{type: :double}, status: 0, server_timestamp: %DateTime{}} =
             level

    assert OPCUA.StatusCode.name(missing.status) == :bad_node_id_unknown
  end

  test "writes a plain value as the node's own type", %{client: client} do
    assert :ok = Client.write(client, "ns=2;s=Scratch.Int16", 1600)

    assert {:ok, [%DataValue{value: %Variant{type: :int16, value: 1600}}]} =
             Client.read_many(client, ["ns=2;s=Scratch.Int16"])

    assert :ok = Client.write(client, "ns=2;s=Scratch.UInt32", 8)
    assert Client.read(client, "ns=2;s=Scratch.UInt32") == {:ok, 8}
  end

  test "writes a variant as given", %{client: client} do
    assert :ok =
             Client.write(client, "ns=2;s=Scratch.Double", %Variant{type: :double, value: 3.25})

    assert Client.read(client, "ns=2;s=Scratch.Double") == {:ok, 3.25}

    assert Client.write(client, "ns=2;s=Scratch.Double", %Variant{type: :string, value: "high"}) ==
             {:error, :bad_type_mismatch}
  end

  test "writes several values at once", %{client: client} do
    assert {:ok, [0, 0]} =
             Client.write_many(client, [
               {"ns=2;s=Scratch.Boolean", false},
               {"ns=2;s=Scratch.String", "P1"}
             ])

    assert Client.read(client, "ns=2;s=Scratch.String") == {:ok, "P1"}
  end

  test "a value that doesn't fit its type raises in the caller, and the client carries on", %{
    client: client
  } do
    assert_raise ArgumentError, fn ->
      Client.write(client, "ns=2;s=Scratch.Int16", %Variant{type: :int16, value: "x"})
    end

    assert_raise ArgumentError, fn -> Client.request(client, %OPCUA.Types.ReadValueId{}) end
    assert {:ok, _} = Client.read(client, "ns=2;s=Pump1.Speed")
  end

  test "a node that isn't writable says so", %{client: client} do
    assert {:error, status} = Client.write(client, "ns=2;s=ReadOnly", 2)
    assert status in [:bad_not_writable, :bad_user_access_denied]
  end

  test "browses, following continuation points", %{client: client} do
    assert {:ok, refs} = Client.browse(client, "ns=2;s=Plant")
    assert "Pump1.Speed" in Enum.map(refs, & &1.browse_name.name)

    assert {:ok, many} = Client.browse(client, "ns=2;s=Many", max_references: 100)
    assert length(many) == 250
    assert many |> Enum.map(& &1.browse_name.name) |> Enum.uniq() |> length() == 250
  end

  test "calls methods", %{client: client} do
    assert Client.call(client, "ns=2;s=Plant", "ns=2;s=Multiply", [6, 7]) == {:ok, [42]}
    assert {:error, _} = Client.call(client, "ns=2;s=Plant", "ns=2;s=Multiply", [6])
    assert Client.call(client, "ns=2;s=Plant", "ns=2;s=Nope", []) |> elem(0) == :error
  end

  test "a message bigger than a chunk goes both ways", %{client: client} do
    big = for i <- 1..100_000, do: i * 0.5

    assert :ok =
             Client.write(client, "ns=2;s=Scratch.Array", %Variant{type: :double, value: big})

    assert Client.read(client, "ns=2;s=Scratch.Array") == {:ok, big}
  end

  test "logs in with a username and password", %{url: url} do
    client = start_supervised!({Client, url: url, user: {"operator", "secret"}}, id: :operator)
    assert {:ok, _} = Client.read(client, "ns=2;s=Pump1.Speed")
    assert {:error, _} = Client.start(url: url, user: {"operator", "wrong"})
  end

  test "renews the secure channel before it runs out", %{url: url} do
    client = start_supervised!({Client, url: url, channel_lifetime: 1000}, id: :short)
    %{token: first} = :sys.get_state(client)
    Process.sleep(trunc(first.revised_lifetime) + 500)
    assert {:ok, _} = Client.read(client, "ns=2;s=Pump1.Speed")
    assert :sys.get_state(client).token.token_id != first.token_id
  end
end
