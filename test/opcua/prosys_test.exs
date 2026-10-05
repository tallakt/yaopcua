defmodule OPCUA.ProsysTest do
  # Against the Prosys OPC UA Simulation Server, a commercial Java stack, with
  # its address space as it comes out of the box. Not part of `mix test`: start
  # the server, then
  #
  #     mix test --only prosys
  #
  # PROSYS_URL is the server's endpoint (default the simulation server's own on
  # this machine). The secure tests use a client certificate kept in
  # PROSYS_PKI (default _build/test/prosys), which Prosys rejects on the first
  # run: trust it on Prosys's Certificates tab, then run again. To leave them
  # out, add `--exclude prosys_secure`. PROSYS_USER=name:password, a user
  # added on Prosys's Users tab, adds the username logins.
  use ExUnit.Case, async: false

  @moduletag :prosys

  alias OPCUA.{Certificate, Client, DataValue, NodeId, Variant}
  alias OPCUA.Types

  @url System.get_env("PROSYS_URL", "opc.tcp://127.0.0.1:53530/OPCUA/SimulationServer")
  @policies [:basic256sha256, :aes128_sha256_rsa_oaep, :aes256_sha256_rsa_pss]
  @application_uri "urn:yaopcua:prosys-test"

  setup_all do
    case Client.endpoints(@url) do
      {:ok, endpoints} ->
        secure = Enum.find(endpoints, &(&1.security_policy_uri != OPCUA.SecureChannel.none()))
        %{endpoints: endpoints, server_cert: secure.server_certificate}

      error ->
        flunk("""
        no Prosys server at #{@url} (#{inspect(error)}): start the Prosys OPC UA
        Simulation Server, or set PROSYS_URL
        """)
    end
  end

  setup do
    %{client: start_supervised!({Client, url: @url})}
  end

  defp next(sub) do
    receive do
      {Client, ^sub, message} -> message
    after
      5000 -> flunk("no message from subscription #{sub}")
    end
  end

  describe "without security" do
    test "offers the policies yaopcua has, with a certificate naming the server", %{
      endpoints: endpoints
    } do
      offered = for e <- endpoints, do: OPCUA.SecurityPolicy.from_uri(e.security_policy_uri)
      assert Enum.all?([:none | @policies], &(&1 in offered))

      for e <- endpoints, e.server_certificate not in [nil, ""] do
        assert Certificate.application_uri(e.server_certificate) == e.server.application_uri
      end
    end

    test "reads every built-in type", %{client: client} do
      types = [
        Boolean: :boolean,
        SByte: :sbyte,
        Byte: :byte,
        Int16: :int16,
        UInt16: :uint16,
        Int32: :int32,
        UInt32: :uint32,
        Int64: :int64,
        UInt64: :uint64,
        Float: :float,
        Double: :double,
        String: :string,
        DateTime: :date_time,
        GUID: :guid,
        ByteString: :byte_string,
        XmlElement: :xml_element,
        NodeId: :node_id,
        QualifiedName: :qualified_name,
        LocalizedText: :localized_text,
        # Subtypes, and an enumeration, as the built-in types they're encoded as.
        Duration: :double,
        UtcTime: :date_time,
        LocaleId: :string,
        ServerState: :int32
      ]

      nodes = for {name, _} <- types, do: "ns=5;s=#{name}"
      assert {:ok, values} = Client.read_many(client, nodes)

      for {{name, type}, value} <- Enum.zip(types, values) do
        assert %DataValue{status: 0, value: %Variant{type: ^type}} = value, "#{name}"
      end
    end

    test "reads arrays", %{client: client} do
      assert {:ok, [_ | _] = ints} = Client.read(client, "ns=5;s=Int32Array")
      assert Enum.all?(ints, &is_integer/1)
      assert {:ok, [_ | _] = texts} = Client.read(client, "ns=5;s=LocalizedTextArray")
      assert Enum.all?(texts, &match?(%OPCUA.LocalizedText{}, &1))
    end

    test "reads standard structures, and leaves Prosys's own encoded", %{client: client} do
      assert Client.read(client, "ns=5;s=Range") == {:ok, %Types.Range{low: 100.0, high: 1000.0}}

      assert Client.read(client, "ns=5;s=3DVector") ==
               {:ok, %Types.ThreeDVector{x: 1.0, y: 2.0, z: 3.0}}

      assert {:ok, %Types.BuildInfo{manufacturer_name: "Prosys OPC Ltd"}} =
               Client.read(client, "ns=5;s=BuildInfo")

      # No custom structure decoding (see the client's "Not supported").
      assert {:ok, %OPCUA.ExtensionObject{type_id: %NodeId{ns: 6}, encoding: :binary}} =
               Client.read(client, "ns=6;s=MyStructure")
    end

    test "writes plain values as each node's type, and reads them back", %{client: client} do
      writes = [
        {"ns=5;s=Boolean", false},
        {"ns=5;s=SByte", -7},
        {"ns=5;s=Byte", 200},
        {"ns=5;s=Int16", -1234},
        {"ns=5;s=UInt16", 60_000},
        {"ns=5;s=Int32", -100_000},
        {"ns=5;s=UInt32", 4_000_000_000},
        {"ns=5;s=Int64", -(2 ** 40)},
        {"ns=5;s=UInt64", 2 ** 63},
        {"ns=5;s=Float", 1.5},
        {"ns=5;s=Double", 2.25},
        {"ns=5;s=Duration", 2500.0},
        {"ns=5;s=String", "yaopcua"},
        {"ns=5;s=DateTime", ~U[2026-01-02 03:04:05.000000Z]}
      ]

      nodes = for {node, _} <- writes, do: node
      {:ok, before} = Client.read_many(client, nodes)
      on_exit(fn -> restore(Enum.zip(nodes, before)) end)

      assert {:ok, statuses} = Client.write_many(client, writes)
      assert Enum.uniq(statuses) == [0]

      for {node, value} <- writes, do: assert(Client.read(client, node) == {:ok, value}, node)
    end

    test "refuses what it should", %{client: client} do
      assert Client.write(client, "ns=5;s=AccessLevelCurrentRead", 1) ==
               {:error, :bad_not_writable}

      assert Client.read(client, "ns=5;s=AccessLevelCurrentWrite") == {:error, :bad_not_readable}
      assert Client.read(client, "ns=5;s=Nope") == {:error, :bad_node_id_unknown}

      assert Client.write(client, "ns=5;s=Int16", %Variant{type: :string, value: "x"}) ==
               {:error, :bad_type_mismatch}

      assert Client.write(client, "ns=5;s=Byte", 300) == {:error, :bad_type_mismatch}
    end

    test "browses, following continuation points", %{client: client} do
      {:ok, all} = Client.browse(client, "ns=5;s=StaticVariables")
      {:ok, paged} = Client.browse(client, "ns=5;s=StaticVariables", max_references: 5)
      assert length(all) > 30
      assert Enum.map(paged, & &1.node_id) == Enum.map(all, & &1.node_id)
    end

    test "calls methods with the argument types they declare", %{client: client} do
      # Operation is a Double: the plain 3 goes as one.
      assert {:ok, [result]} =
               Client.call(client, "ns=5;s=Methods", "ns=5;s=InputOutputMethod", [3])

      assert is_float(result)

      assert Client.call(client, "ns=5;s=Methods", "ns=5;s=InputOutputMethod", ["three"]) ==
               {:error, :bad_type_mismatch}

      assert Client.call(client, "ns=5;s=Methods", "ns=5;s=OutputMethod", []) == {:ok, [1.2345]}

      assert Client.call(client, "ns=5;s=Methods", "ns=5;s=NoInputNoOutputMethod", []) ==
               {:ok, []}

      # sin(90°), with the angle a plain integer for a Double.
      assert {:ok, [sine]} =
               Client.call(client, "ns=6;s=MyDevice", "ns=6;s=MyMethod", ["sin", 90])

      assert_in_delta sine, 1.0, 1.0e-9
    end

    test "subscriptions follow the simulation", %{client: client} do
      {:ok, sub} = Client.subscribe(client, ["ns=3;i=1001"], interval: 100)
      assert {:value, _, %DataValue{value: %Variant{value: first}}} = next(sub)
      assert {:value, _, %DataValue{value: %Variant{value: second}}} = next(sub)
      assert second != first
    end

    test "ConditionRefresh brackets the standing alarms with its two events", %{client: client} do
      {:ok, sub} = Client.subscribe_events(client, fields: ["EventType"], interval: 50)
      assert :ok = Client.refresh(client, sub)

      types = collect(sub, [])
      start = OPCUA.NodeIds.node_id!("RefreshStartEventType")
      ending = OPCUA.NodeIds.node_id!("RefreshEndEventType")
      assert hd(types) == start
      assert List.last(types) == ending
    end
  end

  # The event types until RefreshEnd.
  defp collect(sub, acc) do
    {:event, %{"EventType" => type}} = next(sub)
    acc = [type | acc]

    if type == OPCUA.NodeIds.node_id!("RefreshEndEventType"),
      do: Enum.reverse(acc),
      else: collect(sub, acc)
  end

  describe "with security" do
    @describetag :prosys_secure

    setup keys do
      dir = System.get_env("PROSYS_PKI", Path.join(Mix.Project.build_path(), "prosys"))
      cert_file = Path.join(dir, "client.der")
      key_file = Path.join(dir, "client.pem")

      unless File.exists?(cert_file) do
        File.mkdir_p!(dir)
        {:ok, host} = :inet.gethostname()

        {cert, key} =
          Certificate.self_signed(@application_uri,
            name: "yaopcua prosys test",
            hostnames: ["#{host}"]
          )

        :ok = Certificate.write(cert_file, cert)
        :ok = Certificate.write_key(key_file, key)
      end

      keys =
        Map.merge(keys, %{cert: Certificate.read(cert_file), key: Certificate.read_key(key_file)})

      case secure(keys, []) do
        {:ok, _} ->
          keys

        error ->
          flunk("""
          Prosys refused yaopcua's test certificate (#{inspect(error)}). Trust
          "yaopcua prosys test" on Prosys's Certificates tab, then run again.
          The certificate is #{cert_file}.
          """)
      end
    end

    defp secure(keys, opts) do
      defaults = [
        url: @url,
        security: {:basic256sha256, :sign_and_encrypt},
        trust: [keys.server_cert],
        certificate: keys.cert,
        private_key: keys.key,
        application_uri: @application_uri
      ]

      case Client.start(Keyword.merge(defaults, opts)) do
        {:ok, client} ->
          result = Client.read(client, "ns=3;i=1007")
          Client.close(client)
          result

        error ->
          error
      end
    end

    test "every policy and mode", keys do
      results =
        for policy <- @policies, mode <- [:sign, :sign_and_encrypt] do
          {policy, mode, secure(keys, security: {policy, mode})}
        end

      assert for({_, _, result} <- results, uniq: true, do: result) == [{:ok, 1.0}],
             inspect(results, pretty: true)
    end

    test "Prosys's certificate passes the client's checks, and fails the wrong ones", keys do
      uri = Certificate.application_uri(keys.server_cert)
      assert secure(keys, server_uri: uri) == {:ok, 1.0}

      assert secure(keys, server_uri: "urn:somewhere:else") ==
               {:error, :bad_certificate_uri_invalid}

      # It names the server's host, not 127.0.0.1.
      assert secure(keys, verify: [host_name: true]) ==
               {:error, :bad_certificate_host_name_invalid}

      [endpoint | _] = keys.endpoints
      by_name = endpoint.endpoint_url

      if Certificate.names_host?(keys.server_cert, URI.parse(by_name).host),
        do: assert(secure(keys, url: by_name, verify: [host_name: true]) == {:ok, 1.0})
    end

    if user = System.get_env("PROSYS_USER") do
      @user List.to_tuple(String.split(user, ":", parts: 2))

      test "logs in with a username, over None and encrypted", keys do
        assert {:ok, client} = Client.start(url: @url, user: @user)
        assert {:ok, _} = Client.read(client, "ns=3;i=1007")
        Client.close(client)

        assert secure(keys, user: @user) == {:ok, 1.0}
        assert {:error, _} = Client.start(url: @url, user: {elem(@user, 0), "wrong"})
      end
    end
  end

  # Writes back what a test changed, as it was.
  defp restore(values) do
    {:ok, client} = Client.start(url: @url)
    for {node, %DataValue{value: %Variant{} = v}} <- values, do: Client.write(client, node, v)
    Client.close(client)
  end
end
