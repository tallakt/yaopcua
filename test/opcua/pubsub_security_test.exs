defmodule OPCUA.PubSubSecurityTest do
  use ExUnit.Case, async: true

  alias OPCUA.{Certificate, Client, Server, Variant}
  alias OPCUA.PubSub.{KeyStore, Publisher, Security, SKS, Subscriber, UADP}
  alias OPCUA.PubSub.UADP.DataSetMessage

  @fields [{"Speed", :int16}, {"Running", :boolean}]
  @values %{"Speed" => 1500, "Running" => true}

  defp url do
    {:ok, socket} = :gen_udp.open(0)
    {:ok, port} = :inet.port(socket)
    :gen_udp.close(socket)
    "opc.udp://127.0.0.1:#{port}"
  end

  defp data(name \\ {42, 1}, timeout \\ 1000) do
    receive do
      {OPCUA.PubSub, ^name, {:data, values}} -> values
    after
      timeout -> :none
    end
  end

  # Data that arrives from now on, not what's already waiting.
  defp fresh(timeout \\ 1000) do
    receive do
      {OPCUA.PubSub, _, _} -> fresh(timeout)
    after
      0 -> data({42, 1}, timeout)
    end
  end

  defp subscriber(url, security, id \\ :subscriber) do
    start_supervised!(
      {Subscriber,
       to: self(),
       url: url,
       security: security,
       readers: [[publisher_id: 42, writer_id: 1, fields: @fields]]},
      id: id
    )
  end

  defp publisher(url, security, id \\ :publisher) do
    start_supervised!(
      {Publisher,
       url: url,
       publisher_id: 42,
       interval: 20,
       security: security,
       writers: [[id: 1, fields: @fields, read: fn -> @values end]]},
      id: id
    )
  end

  defp eventually_current(table, tries \\ 100) do
    cond do
      KeyStore.current(table) != nil -> true
      tries == 0 -> false
      true -> Process.sleep(20) && eventually_current(table, tries - 1)
    end
  end

  defp bytes(policy), do: Security.generate(policy)

  describe "the policies" do
    test "have the key lengths of Part 14" do
      assert Security.key_length(:aes128_ctr) == 32 + 16 + 4
      assert Security.key_length(:aes256_ctr) == 32 + 32 + 4

      assert Security.uri(:aes128_ctr) ==
               "http://opcfoundation.org/UA/SecurityPolicy#PubSub-Aes128-CTR"

      assert Security.from_uri(Security.uri(:aes256_ctr)) == :aes256_ctr
      assert Security.from_uri("urn:other") == nil
    end

    test "split key material in order: signing, encrypting, nonce" do
      material = :binary.copy(<<1>>, 32) <> :binary.copy(<<2>>, 16) <> :binary.copy(<<3>>, 4)
      assert {:ok, keys} = Security.split(:aes128_ctr, material)
      assert keys.signing == :binary.copy(<<1>>, 32)
      assert keys.encrypting == :binary.copy(<<2>>, 16)
      assert keys.nonce == :binary.copy(<<3>>, 4)
      assert Security.split(:aes256_ctr, material) == :error
      assert Security.split(:aes128_ctr, "short") == :error
    end

    test "encrypt with AES in counter mode, the counter block KeyNonce, MessageNonce, 1" do
      # The first block of the key stream is the cipher of that counter block.
      {:ok, keys} = Security.split(:aes128_ctr, bytes(:aes128_ctr))
      nonce = <<9, 8, 7, 6, 5, 4, 3, 2>>
      block = keys.nonce <> nonce <> <<1::32>>
      stream = :crypto.crypto_one_time(:aes_128_ecb, keys.encrypting, block, true)
      assert Security.crypt(keys, nonce, <<0::128>>) == stream

      assert Security.crypt(keys, nonce, Security.crypt(keys, nonce, "round trip")) ==
               "round trip"
    end

    test "sign with HMAC-SHA256" do
      {:ok, keys} = Security.split(:aes256_ctr, bytes(:aes256_ctr))
      signature = Security.sign(keys, "data")
      assert signature == :crypto.mac(:hmac, :sha256, keys.signing, "data")
      assert Security.verify(keys, "data", signature)
      refute Security.verify(keys, "date", signature)
      refute Security.verify(keys, "data", binary_part(signature, 0, 31))
    end
  end

  describe "UADP" do
    def network(security) do
      %UADP{
        publisher_id: {:uint16, 42},
        writer_group_id: 1,
        sequence_number: 3,
        security: security,
        messages: [
          %DataSetMessage{
            writer_id: 1,
            sequence_number: 1,
            fields: [%Variant{type: :int16, value: 5}]
          },
          %DataSetMessage{
            writer_id: 2,
            sequence_number: 1,
            fields: [%Variant{type: :string, value: "second"}]
          }
        ]
      }
    end

    for policy <- [:aes128_ctr, :aes256_ctr], mode <- [:sign, :sign_and_encrypt] do
      test "#{policy} #{mode}: decodes what was encoded, and nothing tampered with" do
        policy = unquote(policy)
        mode = unquote(mode)
        {:ok, keys} = Security.split(policy, bytes(policy))
        nonce = Security.message_nonce(<<1, 2, 3, 4>>, 9)

        binary =
          %{mode: mode, token_id: 7, nonce: nonce, keys: keys}
          |> network()
          |> UADP.encode()
          |> IO.iodata_to_binary()

        lookup = fn
          7 -> keys
          _ -> nil
        end

        assert {:ok, decoded} = UADP.decode(binary, %{}, {mode, lookup})
        assert decoded.security == %{mode: mode, token_id: 7}

        assert [%{fields: [%Variant{value: 5}]}, %{fields: [%Variant{value: "second"}]}] =
                 decoded.messages

        # The payload isn't readable when it's encrypted, and is when it's only signed.
        assert String.contains?(binary, "second") == (mode == :sign)

        # Every byte counts: the header, the payload and the signature.
        for index <- 0..(byte_size(binary) - 1) do
          <<head::binary-size(index), byte, tail::binary>> = binary
          flipped = <<head::binary, Bitwise.bxor(byte, 1), tail::binary>>
          assert {:error, _} = UADP.decode(flipped, %{}, {mode, lookup}), "byte #{index}"
        end

        other = if mode == :sign, do: :sign_and_encrypt, else: :sign
        assert {:error, _} = UADP.decode(binary, %{}, {other, lookup})
        assert {:error, _} = UADP.decode(binary, %{}, nil)
        assert {:error, _} = UADP.decode(binary, %{}, {mode, fn _ -> nil end})
        {:ok, wrong} = Security.split(policy, bytes(policy))

        assert {:error, _} =
                 UADP.decode(
                   binary,
                   %{},
                   {mode,
                    fn
                      7 -> wrong
                      _ -> nil
                    end}
                 )

        assert {:error, _} = UADP.decode(binary_part(binary, 0, 20), %{}, {mode, lookup})
      end
    end

    test "a plain message isn't accepted by a reader that wants security" do
      binary = network(nil) |> UADP.encode() |> IO.iodata_to_binary()
      assert {:ok, _} = UADP.decode(binary)
      assert {:error, _} = UADP.decode(binary, %{}, {:sign, fn _ -> nil end})
    end
  end

  describe "a publisher and subscriber with fixed keys" do
    for policy <- [:aes128_ctr, :aes256_ctr], mode <- [:sign, :sign_and_encrypt] do
      test "#{policy} #{mode}" do
        url = url()

        security = [
          mode: unquote(mode),
          policy: unquote(policy),
          keys: [{1, bytes(unquote(policy))}]
        ]

        subscriber(url, security)
        publisher(url, security)
        assert data() == @values
      end
    end

    test "the key of a group both share is what matters" do
      url = url()
      shared = bytes(:aes128_ctr)
      subscriber(url, mode: :sign_and_encrypt, keys: [{1, shared}])
      publisher(url, mode: :sign_and_encrypt, keys: [{1, bytes(:aes128_ctr)}])
      assert data() == :none
    end

    test "messages in the clear, or in another mode, are not delivered" do
      url = url()
      keys = [{1, bytes(:aes128_ctr)}]
      subscriber(url, mode: :sign_and_encrypt, keys: keys)
      publisher(url, nil, :plain)
      publisher(url, [mode: :sign, keys: keys], :signed)
      assert data() == :none
    end

    test "a subscriber without security ignores secured messages" do
      url = url()
      subscriber(url, nil)
      publisher(url, mode: :sign_and_encrypt, keys: [{1, bytes(:aes128_ctr)}])
      assert data() == :none
    end

    test "keys of the wrong length are refused when starting" do
      assert_raise ArgumentError, fn ->
        Publisher.start_link(
          url: url(),
          publisher_id: 1,
          writers: [],
          security: [keys: [{1, "short"}]]
        )
      end

      assert_raise ArgumentError, ~r/needs :keys or :sks/, fn ->
        Subscriber.start_link(url: url(), readers: [], security: [mode: :sign])
      end

      assert_raise ArgumentError, ~r/sign_and_encrypt/, fn ->
        Subscriber.start_link(
          url: url(),
          readers: [],
          security: [sks: [url: "opc.tcp://localhost:1", group: "g", security: :none]]
        )
      end
    end
  end

  describe "the key service" do
    test "hands out the current key and the future ones" do
      {:ok, sks} = SKS.start_link()
      :ok = SKS.add_group(sks, "g", future_keys: 2)
      assert {:error, :already_exists} = SKS.add_group(sks, "g")

      assert {:ok, %{first_token_id: 1, keys: [a, b, c], policy: :aes128_ctr} = all} =
               SKS.keys(sks, "g")

      assert all.key_lifetime == 3_600_000.0
      assert all.time_to_next_key > 0
      assert Enum.all?([a, b, c], &(byte_size(&1) == Security.key_length(:aes128_ctr)))
      assert length(Enum.uniq([a, b, c])) == 3

      assert {:ok, %{first_token_id: 1, keys: [^a]}} = SKS.keys(sks, "g", 0, 1)
      assert {:ok, %{first_token_id: 2, keys: [^b, ^c]}} = SKS.keys(sks, "g", 2, 5)
      # A token the group doesn't have starts at the current one.
      assert {:ok, %{first_token_id: 1}} = SKS.keys(sks, "g", 99, 0)
      assert {:error, :bad_not_found} = SKS.keys(sks, "nobody")
    end

    test "moves on to the next key when the lifetime is up, and keeps the old one a while" do
      {:ok, sks} = SKS.start_link()
      :ok = SKS.add_group(sks, "g", key_lifetime: 100, future_keys: 2, past_keys: 1)
      {:ok, %{keys: [first, second, _]}} = SKS.keys(sks, "g")
      Process.sleep(130)
      assert {:ok, %{first_token_id: 2, keys: [^second, _, _]}} = SKS.keys(sks, "g")
      assert {:ok, %{first_token_id: 1, keys: [^first | _]}} = SKS.keys(sks, "g", 1, 0)
      Process.sleep(110)
      assert {:ok, %{first_token_id: 3}} = SKS.keys(sks, "g")
      # Token 1 is more than one past the current, and gone.
      assert {:ok, %{first_token_id: 3}} = SKS.keys(sks, "g", 1, 0)
    end

    test "can be told to move on now, and to forget a group" do
      {:ok, sks} = SKS.start_link()
      :ok = SKS.add_group(sks, "g")
      :ok = SKS.rotate(sks, "g")
      assert {:ok, %{first_token_id: 2}} = SKS.keys(sks, "g")
      assert {:error, :bad_not_found} = SKS.rotate(sks, "nobody")
      :ok = SKS.remove_group(sks, "g")
      assert {:error, :bad_not_found} = SKS.keys(sks, "g")
    end

    test "gives keys only to the users of the group" do
      {:ok, sks} = SKS.start_link()
      :ok = SKS.add_group(sks, "g", users: ["alice"])
      assert {:ok, _} = SKS.keys(sks, "g", 0, 0, "alice")
      assert {:error, :bad_user_access_denied} = SKS.keys(sks, "g", 0, 0, "mallory")
      assert {:error, :bad_user_access_denied} = SKS.keys(sks, "g", 0, 0, :anonymous)
      assert {:ok, _} = SKS.keys(sks, "g", 0, 0, :local)
    end
  end

  describe "with the key service of a server in the same VM" do
    setup do
      server = start_supervised!({Server, port: 0})
      :ok = Server.add_security_group(server, "g", policy: :aes256_ctr)
      %{server: server}
    end

    test "publishes to subscribers", %{server: server} do
      url = url()
      security = [mode: :sign_and_encrypt, policy: :aes256_ctr, sks: [server: server, group: "g"]]
      subscriber(url, security)
      publisher(url, security)
      assert data() == @values
    end

    test "keeps going as the keys rotate", %{server: server} do
      :ok = Server.add_security_group(server, "fast", policy: :aes128_ctr, key_lifetime: 400)
      url = url()
      security = [mode: :sign_and_encrypt, sks: [server: server, group: "fast"]]
      subscriber(url, security)
      publisher(url, security)
      assert data() == @values

      # Over several key lifetimes, with the data never stopping for long.
      for _ <- 1..30 do
        Process.sleep(100)
        assert fresh() == @values
      end

      assert {:ok, %{first_token_id: token}} = Server.security_keys(server, "fast")
      assert token >= 5
    end

    test "a token nobody has is survived, also while keys are being fetched", %{server: server} do
      {:ok, store} =
        KeyStore.start_link(
          mode: :sign,
          policy: :aes256_ctr,
          sks: [server: server, group: "g"]
        )

      table = KeyStore.table(store)

      for _ <- 1..20 do
        assert KeyStore.lookup(table, store, 999) == nil
      end

      assert eventually_current(table)
      assert Process.alive?(store)
      assert KeyStore.lookup(table, store, 999) == nil
      assert Process.alive?(store)
    end

    test "a group of another policy is refused", %{server: server} do
      url = url()
      security = [mode: :sign, policy: :aes128_ctr, sks: [server: server, group: "g"]]
      subscriber(url, security)
      publisher(url, security)
      assert data() == :none
    end

    test "a group that isn't there gives nothing", %{server: server} do
      url = url()
      security = [sks: [server: server, group: "nobody"]]
      subscriber(url, security)
      publisher(url, security)
      assert data() == :none
    end
  end

  describe "the key service over OPC UA" do
    setup do
      {server_cert, server_key} = Certificate.self_signed("urn:yaopcua:sks")
      {client_cert, client_key} = Certificate.self_signed("urn:yaopcua:pubsub")

      server =
        start_supervised!(
          {Server,
           port: 0,
           security: [:none, {:basic256sha256, :sign}, {:basic256sha256, :sign_and_encrypt}],
           application_uri: "urn:yaopcua:sks",
           certificate: server_cert,
           private_key: server_key,
           trust: [client_cert],
           users: %{"pubsub" => "secret", "other" => "secret"}}
        )

      :ok = Server.add_security_group(server, "g", users: ["pubsub"])
      url = "opc.tcp://127.0.0.1:#{Server.port(server)}"

      client = [
        url: url,
        trust: [server_cert],
        certificate: client_cert,
        private_key: client_key,
        application_uri: "urn:yaopcua:pubsub",
        user: {"pubsub", "secret"}
      ]

      %{server: server, client: client}
    end

    defp get_keys(client_opts, args) do
      {:ok, client} = Client.start(client_opts)

      try do
        Client.call(client, "i=14443", "i=15215", args)
      after
        Client.close(client)
      end
    end

    defp arguments(group, first \\ 0, count \\ 0),
      do: [
        %Variant{type: :string, value: group},
        %Variant{type: :uint32, value: first},
        %Variant{type: :uint32, value: count}
      ]

    test "GetSecurityKeys answers as Part 14 says", %{client: client} do
      client = [{:security, {:basic256sha256, :sign_and_encrypt}} | client]

      assert {:ok, [uri, 1, [a, b, c, d], time_to_next, lifetime]} =
               get_keys(client, arguments("g"))

      assert uri == Security.uri(:aes128_ctr)
      assert Enum.all?([a, b, c, d], &(byte_size(&1) == 52))
      assert time_to_next > 0 and time_to_next <= lifetime
      assert lifetime == 3_600_000.0

      assert {:ok, [_, 2, [^b, ^c], _, _]} = get_keys(client, arguments("g", 2, 2))
    end

    test "is refused on a channel that isn't encrypted", %{client: client} do
      assert {:error, :bad_security_mode_insufficient} = get_keys(client, arguments("g"))

      assert {:error, :bad_security_mode_insufficient} =
               get_keys([{:security, {:basic256sha256, :sign}} | client], arguments("g"))
    end

    test "is refused to users that aren't in the group, and for a group that isn't there",
         %{client: client} do
      client = [{:security, {:basic256sha256, :sign_and_encrypt}} | client]

      assert {:error, :bad_user_access_denied} =
               get_keys(Keyword.put(client, :user, {"other", "secret"}), arguments("g"))

      assert {:error, :bad_not_found} = get_keys(client, arguments("nobody"))
      assert {:error, :bad_arguments_missing} = get_keys(client, Enum.take(arguments("g"), 2))

      assert {:error, :bad_type_mismatch} =
               get_keys(
                 client,
                 [%Variant{type: :int32, value: 1}] ++ Enum.drop(arguments("g"), 1)
               )
    end

    test "feeds a publisher and a subscriber that fetch their keys over a session",
         %{client: client} do
      url = url()
      sks = [group: "g", security: {:basic256sha256, :sign_and_encrypt}] ++ client
      security = [mode: :sign_and_encrypt, policy: :aes128_ctr, sks: sks]
      subscriber(url, security)
      publisher(url, security)
      assert data({42, 1}, 20_000) == @values
    end

    test "refuses to fetch keys over a session that isn't encrypted", %{client: client} do
      assert_raise ArgumentError, ~r/sign_and_encrypt/, fn ->
        Subscriber.start_link(
          url: url(),
          readers: [],
          security: [sks: [group: "g", security: {:basic256sha256, :sign}] ++ client]
        )
      end
    end
  end
end
