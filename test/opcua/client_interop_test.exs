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

  describe "subscriptions" do
    # Waits for the next message from a subscription, skipping others.
    defp next(sub, timeout \\ 3000) do
      receive do
        {Client, ^sub, message} -> message
      after
        timeout -> flunk("no message from subscription #{sub}")
      end
    end

    defp none(sub, timeout \\ 500) do
      receive do
        {Client, ^sub, message} -> flunk("unexpected #{inspect(message)}")
      after
        timeout -> :ok
      end
    end

    test "sends the current values, then each change", %{client: client} do
      :ok = Client.write(client, "ns=2;s=Scratch.UInt32", 5)
      {:ok, sub} = Client.subscribe(client, ["ns=2;s=Scratch.UInt32"], interval: 50)

      assert {:value, "ns=2;s=Scratch.UInt32", %DataValue{value: %Variant{value: 5}, status: 0}} =
               next(sub)

      :ok = Client.write(client, "ns=2;s=Scratch.UInt32", 6)
      assert {:value, "ns=2;s=Scratch.UInt32", %DataValue{value: %Variant{value: 6}}} = next(sub)
      none(sub)
    end

    test "a deadband leaves out small changes", %{client: client} do
      :ok = Client.write(client, "ns=2;s=Scratch.Double", 0.0)

      {:ok, sub} =
        Client.subscribe(client, ["ns=2;s=Scratch.Double"],
          interval: 50,
          deadband: {:absolute, 1.0}
        )

      assert {:value, _, %DataValue{value: %Variant{value: +0.0}}} = next(sub)

      # One write at a time: with a queue of 1, changes within an interval merge.
      :ok = Client.write(client, "ns=2;s=Scratch.Double", 10.0)
      assert {:value, _, %DataValue{value: %Variant{value: 10.0}}} = next(sub)
      :ok = Client.write(client, "ns=2;s=Scratch.Double", 10.5)
      none(sub, 300)
      :ok = Client.write(client, "ns=2;s=Scratch.Double", 12.0)
      assert {:value, _, %DataValue{value: %Variant{value: 12.0}}} = next(sub)
    end

    test "a node that can't be monitored gets one message with its status", %{client: client} do
      {:ok, sub} = Client.subscribe(client, ["ns=2;s=Nope", "ns=2;s=Pump1.Speed"], interval: 50)
      messages = [next(sub), next(sub)]

      assert {:value, "ns=2;s=Nope", %DataValue{status: status, value: nil}} =
               List.keyfind(messages, "ns=2;s=Nope", 1)

      assert OPCUA.StatusCode.name(status) == :bad_node_id_unknown

      assert {:value, "ns=2;s=Pump1.Speed", %DataValue{value: %Variant{value: 1500}}} =
               List.keyfind(messages, "ns=2;s=Pump1.Speed", 1)
    end

    test "sends to another process, and stops when it exits", %{client: client} do
      test = self()

      subscriber =
        spawn(fn ->
          receive do
            {Client, sub, message} -> send(test, {:got, sub, message})
          end
        end)

      {:ok, sub} = Client.subscribe(client, ["ns=2;s=Pump1.Speed"], to: subscriber, interval: 50)
      assert_receive {:got, ^sub, {:value, "ns=2;s=Pump1.Speed", _}}, 3000
      refute Process.alive?(subscriber)

      Process.sleep(100)
      refute Map.has_key?(:sys.get_state(client).subscriptions, sub)
    end

    test "unsubscribing stops the messages", %{client: client} do
      {:ok, sub} = Client.subscribe(client, ["ns=2;s=Scratch.Int16"], interval: 50)
      assert {:value, _, _} = next(sub)
      assert :ok = Client.unsubscribe(client, sub)
      :ok = Client.write(client, "ns=2;s=Scratch.Int16", 99)
      none(sub)
      assert Client.unsubscribe(client, sub) == {:error, :bad_subscription_id_invalid}
    end

    test "several subscriptions share the publish requests", %{client: client} do
      {:ok, one} = Client.subscribe(client, ["ns=2;s=Pump1.Speed"], interval: 50)
      {:ok, two} = Client.subscribe(client, ["ns=2;s=Tank.Level"], interval: 200)
      assert {:value, "ns=2;s=Pump1.Speed", _} = next(one)
      assert {:value, "ns=2;s=Tank.Level", _} = next(two)
      assert :sys.get_state(client).publishing == 2
    end

    test "events arrive with the fields asked for", %{client: client} do
      {:ok, sub} =
        Client.subscribe_events(client,
          fields: ["Message", "Severity", "SourceNode"],
          interval: 50
        )

      {:ok, []} = Client.call(client, "ns=2;s=Plant", "ns=2;s=Fire", ["Pump tripped", 700])

      assert {:event,
              %{
                "Message" => %OPCUA.LocalizedText{text: "Pump tripped"},
                "Severity" => 700,
                "SourceNode" => %OPCUA.NodeId{id: 2253}
              }} =
               next(sub)
    end

    test "events have the common fields by default", %{client: client} do
      {:ok, sub} = Client.subscribe_events(client, interval: 50)
      {:ok, []} = Client.call(client, "ns=2;s=Plant", "ns=2;s=Fire", ["Level high", 400])
      assert {:event, event} = next(sub)

      assert Map.keys(event) |> Enum.sort() ==
               ~w(EventId EventType Message Severity SourceName SourceNode Time)

      assert %DateTime{} = event["Time"]
      assert is_binary(event["EventId"])
    end
  end
end
