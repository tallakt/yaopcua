defmodule OPCUA.Open62541InteropTest do
  # Against open62541, the C stack much OPC UA equipment is built on, through
  # test/support/open62541_peer.c in a process of its own. Runs where
  # open62541's library is found; see test_helper.exs.
  use ExUnit.Case, async: false

  @moduletag :open62541

  alias OPCUA.{Certificate, Client, DataValue, Plant, Server, Variant}

  setup_all do
    %{peer: OPCUA.Open62541.build!()}
  end

  defp free_port do
    {:ok, listener} = :gen_tcp.listen(0, [])
    {:ok, port} = :inet.port(listener)
    :gen_tcp.close(listener)
    port
  end

  describe "yaopcua's client, open62541's server" do
    setup %{peer: peer} do
      port = free_port()

      server =
        Port.open({:spawn_executable, peer}, [
          :binary,
          :exit_status,
          :stderr_to_stdout,
          line: 4096,
          args: ["server", to_string(port)]
        ])

      {:os_pid, os_pid} = Port.info(server, :os_pid)
      on_exit(fn -> System.cmd("kill", ["#{os_pid}"]) end)
      ready(server)

      url = "opc.tcp://127.0.0.1:#{port}"
      %{url: url, client: start_supervised!({Client, url: url})}
    end

    defp ready(server) do
      receive do
        {^server, {:data, {:eol, "ready"}}} -> :ok
        {^server, {:data, _}} -> ready(server)
        {^server, {:exit_status, status}} -> flunk("open62541 server exited with #{status}")
      after
        5000 -> flunk("open62541 server didn't start")
      end
    end

    test "lists the server's endpoints", %{url: url} do
      assert {:ok, [endpoint]} = Client.endpoints(url)
      assert endpoint.security_mode == :none

      tokens = Enum.map(endpoint.user_identity_tokens, & &1.token_type)
      assert :anonymous in tokens and :user_name in tokens
    end

    test "reads scalars, arrays and structures", %{client: client} do
      assert Client.read(client, "ns=2;s=Pump1.Speed") == {:ok, 1500}
      assert Client.read(client, "ns=2;s=Pump1.Running") == {:ok, true}
      assert Client.read(client, "ns=2;s=Pump1.Name") == {:ok, "Pump 1"}
      assert Client.read(client, "ns=2;s=Tank.Setpoints") == {:ok, [1.0, 2.0, 3.0]}

      assert {:ok, %OPCUA.Types.ServerStatusDataType{state: :running}} =
               Client.read(client, "i=2256")

      assert Client.read(client, "ns=2;s=Nope") == {:error, :bad_node_id_unknown}

      assert {:ok, [level, missing]} =
               Client.read_many(client, ["ns=2;s=Tank.Level", "ns=2;s=Nope"])

      assert %DataValue{value: %Variant{type: :double, value: 2.5}, status: 0} = level
      assert OPCUA.StatusCode.name(missing.status) == :bad_node_id_unknown
    end

    test "writes plain values as the node's type, and variants as given", %{client: client} do
      assert :ok = Client.write(client, "ns=2;s=Scratch.Int16", 1600)
      assert Client.read(client, "ns=2;s=Scratch.Int16") == {:ok, 1600}

      assert {:ok, [0, 0]} =
               Client.write_many(client, [
                 {"ns=2;s=Scratch.UInt32", 8},
                 {"ns=2;s=Scratch.String", "P1"}
               ])

      assert Client.read(client, "ns=2;s=Scratch.String") == {:ok, "P1"}

      assert Client.write(client, "ns=2;s=Scratch.Double", %Variant{type: :string, value: "x"}) ==
               {:error, :bad_type_mismatch}

      assert {:error, status} = Client.write(client, "ns=2;s=ReadOnly", 2)
      assert status in [:bad_not_writable, :bad_user_access_denied]
    end

    test "a message bigger than a chunk goes both ways", %{client: client} do
      big = for i <- 1..100_000, do: i * 0.5

      assert :ok =
               Client.write(client, "ns=2;s=Scratch.Array", %Variant{type: :double, value: big})

      assert Client.read(client, "ns=2;s=Scratch.Array") == {:ok, big}
    end

    test "browses, following continuation points", %{client: client} do
      assert {:ok, refs} = Client.browse(client, "ns=2;s=Plant")
      assert "Pump1.Speed" in Enum.map(refs, & &1.browse_name.name)

      assert {:ok, many} = Client.browse(client, "ns=2;s=Many", max_references: 100)
      assert many |> Enum.map(& &1.browse_name.name) |> Enum.uniq() |> length() == 250
    end

    test "calls methods", %{client: client} do
      assert Client.call(client, "ns=2;s=Plant", "ns=2;s=Multiply", [6, 7]) == {:ok, [42]}
      assert {:error, _} = Client.call(client, "ns=2;s=Plant", "ns=2;s=Multiply", [6])
      assert {:error, _} = Client.call(client, "ns=2;s=Plant", "ns=2;s=Nope", [])
    end

    test "logs in with a username and password", %{url: url} do
      client = start_supervised!({Client, url: url, user: {"operator", "secret"}}, id: :operator)
      assert {:ok, _} = Client.read(client, "ns=2;s=Pump1.Speed")

      assert Client.start(url: url, user: {"operator", "wrong"}) ==
               {:error, :bad_user_access_denied}
    end

    test "a subscription sends the current value, then each change", %{client: client} do
      {:ok, sub} = Client.subscribe(client, ["ns=2;s=Scratch.Int16"], interval: 50)
      assert {:value, _, %DataValue{value: %Variant{value: 0}}} = next(sub)
      :ok = Client.write(client, "ns=2;s=Scratch.Int16", 6)
      assert {:value, _, %DataValue{value: %Variant{value: 6}}} = next(sub)

      # The server changes this one itself.
      {:ok, counter} = Client.subscribe(client, ["ns=2;s=Counter"], interval: 50)
      assert {:value, _, %DataValue{value: %Variant{value: first}}} = next(counter)
      assert {:value, _, %DataValue{value: %Variant{value: second}}} = next(counter)
      assert second > first
    end

    test "events arrive with the fields asked for", %{client: client} do
      {:ok, sub} =
        Client.subscribe_events(client,
          fields: ["Message", "Severity", "SourceNode"],
          interval: 50
        )

      # open62541 holds arguments to the method's types: 700 goes as the UInt16
      # that Fire declares.
      {:ok, []} = Client.call(client, "ns=2;s=Plant", "ns=2;s=Fire", ["Pump tripped", 700])

      assert {:event,
              %{
                "Message" => %OPCUA.LocalizedText{text: "Pump tripped"},
                "Severity" => 700,
                "SourceNode" => %OPCUA.NodeId{id: 2253}
              }} = next(sub)
    end

    defp next(sub) do
      receive do
        {Client, ^sub, message} -> message
      after
        3000 -> flunk("no message from subscription #{sub}")
      end
    end
  end

  test "open62541's client, yaopcua's server", %{peer: peer} do
    server = start_supervised!({Server, port: 0, users: %{"operator" => "secret"}})
    :ok = Plant.add(server, self())
    url = "opc.tcp://127.0.0.1:#{Server.port(server)}"
    {output, 0} = System.cmd(peer, ["client", url], stderr_to_stdout: true)

    seen =
      for line <- String.split(output, "\n", trim: true), into: %{} do
        [key | values] = String.split(line, " ")
        {key, values}
      end

    assert Map.update!(seen, "objects", &Enum.sort/1) == %{
             "namespaces" => ["http://opcfoundation.org/UA/", "urn:yaopcua:server", "urn:plant"],
             "objects" => ["Aliases", "Levels", "Locations", "Many", "Pump1", "Server"],
             "speed" => ["1500"],
             "speed_after" => ["1234"],
             "display_name" => ["Speed"],
             "data_type" => ["i=4"],
             "levels" => ["1", "2.5"],
             "read_only" => ["BadNotWritable"],
             "multiply" => ["42"],
             "path" => ["ns=2;s=Pump1.Speed"],
             # Running
             "state" => ["0"],
             "many" => ["1500"],
             "subscription" => ["1234", "777"],
             "alarm_condition" => ["ns=2;s=Pump1.Overload"],
             "alarm_message" => ["Pump", "1", "overload"],
             "alarm_severity" => ["700"],
             "alarm_active" => ["true"],
             "alarm_acked" => ["false"],
             "alarm_acked_after" => ["true"],
             "alarm_comment" => ["from", "open62541"],
             "user_read" => ["21.5"]
           }

    assert Server.get(server, "ns=2;s=Pump1.Speed").value.value == 777
    assert_received {:acknowledged, "from open62541"}
  end

  describe "secure channels" do
    @describetag :open62541_secure

    # open62541 checks that a certificate names the URI its application
    # presents, as yaopcua's server does; the peer's are fixed.
    @uris %{
      "open62541_server" => "urn:open62541.server.application",
      "yaopcua_server" => "urn:yaopcua:server",
      "client" => "urn:open62541.client.application",
      "user" => "urn:open62541.client.application",
      "stranger" => "urn:open62541.client.application"
    }

    setup do
      dir = Path.join(System.tmp_dir!(), "yaopcua-#{System.unique_integer([:positive])}")
      File.mkdir_p!(dir)
      on_exit(fn -> File.rm_rf!(dir) end)

      keys =
        for {name, uri} <- @uris, into: %{} do
          {cert, key} = Certificate.self_signed(uri, hostnames: ["127.0.0.1", "localhost"])
          :ok = Certificate.write(Path.join(dir, "#{name}.der"), cert)
          :ok = Certificate.write_key(Path.join(dir, "#{name}.pem"), key)
          {name, {cert, key}}
        end

      %{cert_file: &Path.join(dir, &1), keys: keys}
    end

    test "yaopcua's client with every policy, mode and login, against open62541's server", %{
      peer: peer,
      cert_file: cert_file,
      keys: keys
    } do
      port = free_port()

      trusted =
        Enum.map(~w(open62541_server.der open62541_server.pem client.der user.der), cert_file)

      server =
        Port.open({:spawn_executable, peer}, [
          :binary,
          :exit_status,
          :stderr_to_stdout,
          line: 4096,
          args: ["server", to_string(port) | trusted]
        ])

      {:os_pid, os_pid} = Port.info(server, :os_pid)
      on_exit(fn -> System.cmd("kill", ["#{os_pid}"]) end)
      ready(server)

      url = "opc.tcp://127.0.0.1:#{port}"
      {server_cert, _} = keys["open62541_server"]
      {user_cert, user_key} = keys["user"]

      connect = fn name, opts ->
        {cert, key} = keys[name]

        Client.start(
          [
            url: url,
            trust: [server_cert],
            certificate: cert,
            private_key: key,
            application_uri: @uris[name]
          ] ++ opts
        )
      end

      results =
        for policy <- [:basic256sha256, :aes128_sha256_rsa_oaep, :aes256_sha256_rsa_pss],
            mode <- [:sign, :sign_and_encrypt],
            user <- [:anonymous, {"operator", "secret"}, {:certificate, user_cert, user_key}] do
          case connect.("client", security: {policy, mode}, user: user) do
            {:ok, client} ->
              result =
                {Client.write(client, "ns=2;s=Pump1.Speed", 1700),
                 Client.read(client, "ns=2;s=Pump1.Speed")}

              Client.close(client)
              result

            error ->
              {policy, mode, user, error}
          end
        end

      assert Enum.uniq(results) == [{:ok, {:ok, 1700}}]

      assert connect.("stranger", security: {:basic256sha256, :sign_and_encrypt}) ==
               {:error, :bad_security_checks_failed}
    end

    test "open62541's client with every policy, mode and login, against yaopcua's server", %{
      peer: peer,
      cert_file: cert_file,
      keys: keys
    } do
      {server_cert, server_key} = keys["yaopcua_server"]
      {client_cert, _} = keys["client"]
      {user_cert, _} = keys["user"]

      server =
        start_supervised!(
          {Server,
           port: 0,
           security: [:none, :basic256sha256, :aes128_sha256_rsa_oaep, :aes256_sha256_rsa_pss],
           certificate: server_cert,
           private_key: server_key,
           trust: [client_cert],
           users: %{"operator" => "secret"},
           user_certificates: [user_cert]}
        )

      :ok = Plant.add(server, self())
      url = "opc.tcp://127.0.0.1:#{Server.port(server)}"

      files =
        Enum.map(
          ~w(yaopcua_server.der client.der client.pem user.der user.pem stranger.der stranger.pem),
          cert_file
        )

      {output, 0} = System.cmd(peer, ["secure", url | files], stderr_to_stdout: true)

      {refused, allowed} =
        output |> String.split("\n", trim: true) |> Enum.split_with(&(&1 =~ "untrusted"))

      assert length(allowed) == 18

      assert allowed |> Enum.map(&(&1 |> String.split() |> List.last())) |> Enum.uniq() == [
               "1700"
             ]

      assert refused == [
               "untrusted basic256sha256 sign_and_encrypt anonymous BadCertificateUntrusted"
             ]
    end
  end
end
