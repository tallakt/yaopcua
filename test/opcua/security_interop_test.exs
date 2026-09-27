defmodule OPCUA.SecurityInteropTest do
  # Secure channels and sessions with asyncua, both ways. See test_helper.exs.
  use ExUnit.Case, async: false

  @moduletag :interop

  alias OPCUA.{Certificate, Client, Server}

  # asyncua's client names itself this, and checks the server's certificate
  # for its own URI; the certificates here are made to match.
  @asyncua_uri "urn:example.org:FreeOpcUa:opcua-asyncio"

  setup_all do
    dir = Path.join(System.tmp_dir!(), "yaopcua-#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf!(dir) end)

    keys =
      for name <- ["server", "client", "user", "stranger"], into: %{} do
        {cert, key} = Certificate.self_signed(@asyncua_uri, hostnames: ["127.0.0.1", "localhost"])
        :ok = Certificate.write(Path.join(dir, "#{name}.der"), cert)
        :ok = Certificate.write_key(Path.join(dir, "#{name}.pem"), key)
        {name, {cert, key}}
      end

    %{dir: dir, keys: keys}
  end

  defp free_port do
    {:ok, listener} = :gen_tcp.listen(0, [])
    {:ok, port} = :inet.port(listener)
    :gen_tcp.close(listener)
    port
  end

  defp python, do: System.fetch_env!("ASYNCUA_PYTHON")

  test "yaopcua's client with every policy, mode and login, against asyncua's server", %{
    dir: dir,
    keys: keys
  } do
    port = free_port()
    script = Path.expand("../support/asyncua_server.py", __DIR__)
    args = [script, to_string(port), Path.join(dir, "server.der"), Path.join(dir, "server.pem")]

    server =
      Port.open({:spawn_executable, python()}, [
        :binary,
        :exit_status,
        :stderr_to_stdout,
        line: 4096,
        args: args
      ])

    ready(server)

    url = "opc.tcp://127.0.0.1:#{port}/yaopcua/"
    {server_cert, _} = keys["server"]
    {client_cert, client_key} = keys["client"]
    {user_cert, user_key} = keys["user"]

    results =
      for policy <- [:basic256sha256, :aes128_sha256_rsa_oaep, :aes256_sha256_rsa_pss],
          mode <- [:sign, :sign_and_encrypt],
          user <- [:anonymous, {"operator", "secret"}, {:certificate, user_cert, user_key}] do
        opts = [
          url: url,
          security: {policy, mode},
          trust: [server_cert],
          certificate: client_cert,
          private_key: client_key,
          application_uri: @asyncua_uri,
          user: user
        ]

        case Client.start(opts) do
          {:ok, client} ->
            result = Client.read(client, "ns=2;s=Pump1.Speed")
            Client.close(client)
            result

          error ->
            {policy, mode, user, error}
        end
      end

    assert Enum.uniq(results) == [{:ok, 1500}]

    wrong = [
      url: url,
      security: :basic256sha256,
      trust: [server_cert],
      certificate: client_cert,
      private_key: client_key,
      application_uri: @asyncua_uri,
      user: {"operator", "wrong"}
    ]

    assert Client.start(wrong) == {:error, :bad_user_access_denied}

    # The password is encrypted for asyncua over None too.
    {:ok, client} = Client.start(url: url, user: {"operator", "secret"})
    assert Client.read(client, "ns=2;s=Pump1.Speed") == {:ok, 1500}
    Client.close(client)
    Port.close(server)
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

  test "asyncua's client with every policy, mode and login, against yaopcua's server", %{
    dir: dir,
    keys: keys
  } do
    {server_cert, server_key} = keys["server"]
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

    :ok =
      Server.add_variable(server, "ns=1;s=Speed", "Speed",
        type: :int16,
        value: 1500,
        writable: true
      )

    files =
      for name <- [
            "server.der",
            "client.der",
            "client.pem",
            "user.der",
            "user.pem",
            "stranger.der",
            "stranger.pem"
          ],
          do: Path.join(dir, name)

    script = Path.expand("../support/asyncua_secure_client.py", __DIR__)

    {output, 0} =
      System.cmd(python(), [script, "opc.tcp://127.0.0.1:#{Server.port(server)}" | files],
        stderr_to_stdout: true
      )

    seen =
      output |> String.split("\n") |> Enum.find(&String.starts_with?(&1, "{")) |> JSON.decode!()

    {refused, allowed} = Map.split(seen, ["untrusted"])
    assert allowed |> Map.values() |> Enum.uniq() == [1700]
    assert map_size(allowed) == 19
    assert refused == %{"untrusted" => "BadCertificateUntrusted"}
  end
end
