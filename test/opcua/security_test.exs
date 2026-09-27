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

  test "a secure client or server must be told what to trust" do
    assert_raise ArgumentError, fn ->
      Client.start(url: "opc.tcp://127.0.0.1:1", security: :basic256sha256)
    end

    assert_raise ArgumentError, fn -> Server.start_link(port: 0, security: [:basic256sha256]) end
  end
end
