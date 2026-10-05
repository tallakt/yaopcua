defmodule OPCUA.SecurityTest do
  # Secure channels and sessions between yaopcua's own client and server.
  use ExUnit.Case, async: true

  alias OPCUA.{Certificate, Client, Server}

  setup_all do
    {client_cert, client_key} = Certificate.self_signed("urn:yaopcua:client")
    {user_cert, user_key} = Certificate.self_signed("urn:operator")
    {stranger_cert, stranger_key} = Certificate.self_signed("urn:yaopcua:client")

    %{
      client_cert: client_cert,
      client_key: client_key,
      user_cert: user_cert,
      user_key: user_key,
      stranger_cert: stranger_cert,
      stranger_key: stranger_key
    }
  end

  setup keys do
    server =
      start_supervised!(
        {Server,
         port: 0,
         security: [:none, :basic256sha256, :aes128_sha256_rsa_oaep, :aes256_sha256_rsa_pss],
         trust: [keys.client_cert],
         users: %{"operator" => "secret"},
         user_certificates: [keys.user_cert]}
      )

    :ok =
      Server.add_variable(server, "ns=1;s=Speed", "Speed",
        type: :int16,
        value: 1500,
        writable: true
      )

    url = "opc.tcp://127.0.0.1:#{Server.port(server)}"
    {:ok, [endpoint | _]} = Client.endpoints(url)
    %{server: server, url: url, server_cert: endpoint.server_certificate}
  end

  defp connect(keys, opts) do
    defaults = [
      url: keys.url,
      trust: [keys.server_cert],
      certificate: keys.client_cert,
      private_key: keys.client_key
    ]

    Client.start(Keyword.merge(defaults, opts))
  end

  test "offers an endpoint per policy and mode, strongest highest" do
    server =
      start_supervised!(
        {Server,
         port: 0, security: [:none, :aes256_sha256_rsa_pss], trust: :any, users: %{"a" => "b"}},
        id: :offer
      )

    {:ok, endpoints} = Client.endpoints("opc.tcp://127.0.0.1:#{Server.port(server)}")

    assert Enum.map(
             endpoints,
             &{OPCUA.SecurityPolicy.from_uri(&1.security_policy_uri), &1.security_mode,
              &1.security_level}
           ) ==
             [
               {:none, :none, 0},
               {:aes256_sha256_rsa_pss, :sign, 30},
               {:aes256_sha256_rsa_pss, :sign_and_encrypt, 35}
             ]

    # On the None endpoint, the password is to be encrypted with the strongest policy.
    [none | _] = endpoints

    assert Enum.find(none.user_identity_tokens, &(&1.token_type == :user_name)).security_policy_uri ==
             OPCUA.SecurityPolicy.uri(:aes256_sha256_rsa_pss)

    assert Certificate.application_uri(none.server_certificate) == "urn:yaopcua:server"
  end

  for policy <- [:basic256sha256, :aes128_sha256_rsa_oaep, :aes256_sha256_rsa_pss],
      mode <- [:sign, :sign_and_encrypt] do
    test "#{policy} #{mode}: anonymous, password and certificate logins", keys do
      logins = [:anonymous, {"operator", "secret"}, {:certificate, keys.user_cert, keys.user_key}]

      for user <- logins do
        {:ok, client} = connect(keys, security: {unquote(policy), unquote(mode)}, user: user)
        assert Client.write(client, "ns=1;s=Speed", 1600) == :ok
        assert Client.read(client, "ns=1;s=Speed") == {:ok, 1600}
        Client.close(client)
      end
    end
  end

  test "a wrong password or an unknown user certificate is refused", keys do
    assert connect(keys, security: :basic256sha256, user: {"operator", "wrong"}) ==
             {:error, :bad_user_access_denied}

    assert connect(keys,
             security: :basic256sha256,
             user: {:certificate, keys.stranger_cert, keys.stranger_key}
           ) == {:error, :bad_identity_token_rejected}

    assert connect(keys,
             security: :basic256sha256,
             user: {:certificate, keys.user_cert, keys.stranger_key}
           ) == {:error, :bad_user_signature_invalid}
  end

  test "the server refuses a client certificate it doesn't trust", keys do
    assert connect(keys,
             security: :basic256sha256,
             certificate: keys.stranger_cert,
             private_key: keys.stranger_key
           ) == {:error, :bad_certificate_untrusted}
  end

  test "the client refuses a server certificate it doesn't trust", keys do
    assert connect(keys, security: :basic256sha256, trust: [keys.client_cert]) ==
             {:error, :bad_certificate_untrusted}
  end

  test "a client certificate must name the client's application", keys do
    assert connect(keys, security: :basic256sha256, application_uri: "urn:someone:else") ==
             {:error, :bad_certificate_uri_invalid}
  end

  test "over None, the password is encrypted for the server", keys do
    {:ok, client} = Client.start(url: keys.url, user: {"operator", "secret"})
    assert Client.read(client, "ns=1;s=Speed") |> elem(0) == :ok
    Client.close(client)
  end

  test "without a None endpoint, None is only for asking the endpoints", keys do
    server =
      start_supervised!({Server, port: 0, security: [:basic256sha256], trust: :any},
        id: :secure_only
      )

    url = "opc.tcp://127.0.0.1:#{Server.port(server)}"
    assert {:ok, [_, _]} = Client.endpoints(url)
    assert Client.start(url: url) == {:error, :bad_security_policy_rejected}

    assert {:ok, client} =
             Client.start(
               url: url,
               security: :basic256sha256,
               trust: :any,
               certificate: keys.client_cert,
               private_key: keys.client_key
             )

    Client.close(client)
  end

  test "renews a secure channel with new keys", keys do
    {:ok, client} = connect(keys, security: :aes256_sha256_rsa_pss, channel_lifetime: 1000)
    first = :sys.get_state(client).token.token_id
    Process.sleep(1500)
    assert Client.read(client, "ns=1;s=Speed") |> elem(0) == :ok
    state = :sys.get_state(client)
    assert state.token.token_id != first

    # The keys of the current token, and of the one before it for messages still on the way.
    assert map_size(state.channel.keys) == 2
    assert Map.has_key?(state.channel.keys, state.token.token_id)
    Client.close(client)
  end

  test "subscriptions work over an encrypted channel", keys do
    {:ok, client} = connect(keys, security: :basic256sha256)
    {:ok, sub} = Client.subscribe(client, ["ns=1;s=Speed"], interval: 50)
    assert_receive {Client, ^sub, {:value, _, _}}, 2000
    :ok = Server.set(keys.server, "ns=1;s=Speed", 42)
    assert_receive {Client, ^sub, {:value, _, %{value: %{value: 42}}}}, 2000
    Client.close(client)
  end

  describe "the server's certificate" do
    # A server whose certificate a CA signed, naming urn:plant:plc1 and the
    # host localhost but not 127.0.0.1.
    setup keys do
      rsa = [key: {:rsa, 2048, 65_537}, digest: :sha256]
      names = [{:uniformResourceIdentifier, ~c"urn:plant:plc1"}, {:dNSName, ~c"localhost"}]
      san = {:Extension, {2, 5, 29, 17}, false, names}
      chain = :public_key.pkix_test_data(%{root: rsa, peer: rsa ++ [extensions: [san]]})
      {:RSAPrivateKey, key} = chain[:key]

      server =
        start_supervised!(
          {Server,
           port: 0,
           security: [:basic256sha256],
           certificate: chain[:cert],
           private_key: :public_key.der_decode(:RSAPrivateKey, key),
           trust: [keys.client_cert]},
          id: :signed
        )

      :ok = Server.add_variable(server, "ns=1;s=Speed", "Speed", type: :int16, value: 1500)
      port = Server.port(server)

      %{
        ca: hd(chain[:cacerts]),
        plc1: chain[:cert],
        by_ip: "opc.tcp://127.0.0.1:#{port}",
        by_name: "opc.tcp://localhost:#{port}"
      }
    end

    defp signed(keys, url, opts) do
      opts = Keyword.merge([url: url, security: :basic256sha256, trust: [keys.ca]], opts)

      with {:ok, client} <- connect(keys, opts) do
        result = Client.read(client, "ns=1;s=Speed")
        Client.close(client)
        result
      end
    end

    test "trusted through a CA, it must name the host in the URL", keys do
      assert signed(keys, keys.by_name, []) == {:ok, 1500}
      assert signed(keys, keys.by_ip, []) == {:error, :bad_certificate_host_name_invalid}
      assert signed(keys, keys.by_ip, verify: [host_name: false]) == {:ok, 1500}
    end

    test "trusted by itself, it needn't, unless asked", keys do
      assert signed(keys, keys.by_ip, trust: [keys.plc1]) == {:ok, 1500}
      assert signed(keys, keys.by_ip, server_certificate: keys.plc1) == {:ok, 1500}

      assert signed(keys, keys.by_ip, trust: [keys.plc1], verify: [host_name: true]) ==
               {:error, :bad_certificate_host_name_invalid}
    end

    test "it must name the application URI the client expects", keys do
      assert signed(keys, keys.by_name, server_uri: "urn:plant:plc1") == {:ok, 1500}

      assert signed(keys, keys.by_name, server_uri: "urn:plant:plc2") ==
               {:error, :bad_certificate_uri_invalid}

      assert signed(keys, keys.by_ip, server_certificate: keys.plc1, server_uri: "urn:plant:plc2") ==
               {:error, :bad_certificate_uri_invalid}
    end

    test "the server presents the application URI its certificate names", keys do
      assert {:ok, endpoints} = Client.endpoints(keys.by_name)
      assert Enum.uniq(for e <- endpoints, do: e.server.application_uri) == ["urn:plant:plc1"]

      assert_raise ArgumentError, ~r/names the application URI "urn:plant:plc1"/, fn ->
        Server.start_link(
          port: 0,
          security: [:basic256sha256],
          certificate: keys.plc1,
          application_uri: "urn:plant:other",
          trust: :any
        )
      end
    end

    test "it must name the application URI the server presents", keys do
      # A server that presents another URI than its certificate's, as some
      # devices do out of the box.
      hostile = OPCUA.HostileServer.start()

      OPCUA.HostileServer.answer(hostile, fn
        %OPCUA.Types.GetEndpointsRequest{}, _ ->
          endpoint = %OPCUA.Types.EndpointDescription{
            endpoint_url: hostile.url,
            server: %OPCUA.Types.ApplicationDescription{application_uri: "urn:unconfigured"},
            server_certificate: keys.plc1,
            security_mode: :sign_and_encrypt,
            security_policy_uri: OPCUA.SecurityPolicy.uri(:basic256sha256),
            security_level: 1
          }

          {:response, %OPCUA.Types.GetEndpointsResponse{endpoints: [endpoint]}}

        _, _ ->
          :default
      end)

      opts = [url: hostile.url, trust: [keys.plc1], security: :basic256sha256]
      assert Client.start(opts) == {:error, :bad_certificate_uri_invalid}

      # Past that check, it fails on what this server can't do.
      assert {:error, reason} = Client.start(opts ++ [verify: [uri: false]])
      assert reason != :bad_certificate_uri_invalid
    end

    test ":verify takes uri: and host_name:, true or false", keys do
      for verify <- [[uri: :yes], [hostname: false], :off] do
        assert_raise ArgumentError, fn -> signed(keys, keys.by_name, verify: verify) end
      end
    end
  end

  test "a login uses the first token policy the client has" do
    # A server, like Prosys's, that lists Basic256 for passwords before
    # Basic256Sha256; the client has only the latter.
    {cert, _} = Certificate.self_signed("urn:server")
    hostile = OPCUA.HostileServer.start()
    test = self()

    token = fn policy ->
      %OPCUA.Types.UserTokenPolicy{
        policy_id: "username_#{policy}",
        token_type: :user_name,
        security_policy_uri: "http://opcfoundation.org/UA/SecurityPolicy##{policy}"
      }
    end

    OPCUA.HostileServer.answer(hostile, fn
      %OPCUA.Types.CreateSessionRequest{request_header: header}, _ ->
        endpoint = %OPCUA.Types.EndpointDescription{
          endpoint_url: hostile.url,
          security_mode: :none,
          security_policy_uri: OPCUA.SecureChannel.none(),
          user_identity_tokens: [token.("Basic256"), token.("Basic256Sha256")]
        }

        {:response,
         %OPCUA.Types.CreateSessionResponse{
           response_header: %OPCUA.Types.ResponseHeader{request_handle: header.request_handle},
           session_id: %OPCUA.NodeId{ns: 1, id: 1},
           authentication_token: %OPCUA.NodeId{ns: 0, id: {:opaque, "token"}},
           revised_session_timeout: 60_000.0,
           server_nonce: :binary.copy(<<1>>, 32),
           server_certificate: cert,
           server_endpoints: [endpoint]
         }}

      %OPCUA.Types.ActivateSessionRequest{} = request, _ ->
        send(test, {:token, request.user_identity_token})
        :default

      _, _ ->
        :default
    end)

    assert {:ok, client} = Client.start(url: hostile.url, user: {"operator", "secret"})
    Client.close(client)

    assert_received {:token,
                     %OPCUA.Types.UserNameIdentityToken{policy_id: "username_Basic256Sha256"}}
  end

  test "a secure client or server must be told what to trust" do
    assert_raise ArgumentError, fn ->
      Client.start(url: "opc.tcp://127.0.0.1:1", security: :basic256sha256)
    end

    assert_raise ArgumentError, fn -> Server.start_link(port: 0, security: [:basic256sha256]) end
  end
end
