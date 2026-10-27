defmodule OPCUA.PubSubSecurityTest do
  use ExUnit.Case, async: true

  alias OPCUA.{Certificate, Client, Server, Variant}
  alias OPCUA.PubSub.{KeyStore, Publisher, Security, SKS, Subscriber, UADP}
  alias OPCUA.PubSub.UADP.DataSetMessage

  @fields [{"Speed", :int16}, {"Running", :boolean}]
  @values %{"Speed" => 1500, "Running" => true}

  defmodule FakeSKS do
    @moduledoc false
    # An OPCUA.Server and its key service in one, answering what `answer`
    # gives, which may be anything a service elsewhere could.
    use GenServer
    def start_link(answer), do: GenServer.start_link(__MODULE__, answer)
    def init(answer), do: {:ok, answer}
    def handle_call(:sks, _from, answer), do: {:reply, self(), answer}
    def handle_call({:keys, _, _, _, _}, _from, answer), do: {:reply, {:ok, answer.()}, answer}
  end

  defmodule CountingSKS do
    @moduledoc false
    # An OPCUA.Server and its key service in one, passing the calls to a
    # real key service and noting what was asked in `log`.
    use GenServer
    def init(state), do: {:ok, state}
    def handle_call(:sks, _from, state), do: {:reply, self(), state}

    def handle_call({:keys, group, starting, count, _user} = keys, _from, {sks, log} = state) do
      Agent.update(log, &[{group, starting, count} | &1])
      {:reply, GenServer.call(sks, keys), state}
    end
  end

  # A server's key service that notes what it's asked, and the calls so far.
  defp counting(server) do
    {:ok, log} = Agent.start_link(fn -> [] end)
    {:ok, counting} = GenServer.start_link(CountingSKS, {GenServer.call(server, :sks), log})
    {counting, fn -> Agent.get(log, &Enum.reverse/1) end}
  end

  # As if the store's last fetch were long ago, so it may fetch again now.
  defp long_ago(store),
    do: :sys.replace_state(store, &%{&1 | last_fetch: &1.last_fetch - 60_000})

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

  defp eventually(fun, tries \\ 100) do
    cond do
      fun.() -> true
      tries == 0 -> false
      true -> Process.sleep(20) && eventually(fun, tries - 1)
    end
  end

  defp eventually_current(table), do: eventually(fn -> KeyStore.current(table) != nil end)

  defp bytes(policy), do: Security.generate(policy)

  # How many of `message` are waiting.
  defp count(message, n \\ 0) do
    receive do
      ^message -> count(message, n + 1)
    after
      0 -> n
    end
  end

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

    for policy <- [:aes128_ctr, :aes256_ctr],
        {mode, other} <- [sign: :sign_and_encrypt, sign_and_encrypt: :sign] do
      test "#{policy} #{mode}: decodes what was encoded, and nothing tampered with" do
        policy = unquote(policy)
        mode = unquote(mode)
        other = unquote(other)
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
        assert String.contains?(binary, "second") == unquote(mode == :sign)

        # Every byte counts: the header, the payload and the signature.
        for index <- 0..(byte_size(binary) - 1) do
          <<head::binary-size(index), byte, tail::binary>> = binary
          flipped = <<head::binary, Bitwise.bxor(byte, 1), tail::binary>>
          assert {:error, _} = UADP.decode(flipped, %{}, {mode, lookup}), "byte #{index}"
        end

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

      # Not at each fetch, when it's too late.
      assert_raise ArgumentError, ~r/server_certificate/, fn ->
        Subscriber.start_link(
          url: url(),
          readers: [],
          security: [sks: [url: "opc.tcp://localhost:1", group: "g"]]
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
               SKS.keys(sks, "g", 0, 10)

      assert all.key_lifetime == 3_600_000.0
      assert all.time_to_next_key > 0
      assert Enum.all?([a, b, c], &(byte_size(&1) == Security.key_length(:aes128_ctr)))
      assert length(Enum.uniq([a, b, c])) == 3

      assert {:ok, %{first_token_id: 1, keys: [^a, ^b]}} = SKS.keys(sks, "g", 0, 2)
      assert {:ok, %{first_token_id: 2, keys: [^b, ^c]}} = SKS.keys(sks, "g", 2, 5)
      # Part 14, 8.3.2: 0 keys asked for is none to come.
      assert {:ok, %{first_token_id: 1, keys: [^a]}} = SKS.keys(sks, "g")
      assert {:error, :bad_not_found} = SKS.keys(sks, "nobody")
    end

    test "moves on to the next key when the lifetime is up, and keeps the old one a while" do
      {:ok, sks} = SKS.start_link()
      :ok = SKS.add_group(sks, "g", key_lifetime: 100, future_keys: 2, past_keys: 1)
      {:ok, %{keys: [first, second, _]}} = SKS.keys(sks, "g", 0, 3)
      Process.sleep(130)
      assert {:ok, %{first_token_id: 2, keys: [^second, _, _]}} = SKS.keys(sks, "g", 0, 3)
      # From a past token, up to the current one when none to come are asked for.
      assert {:ok, %{first_token_id: 1, keys: [^first, ^second]}} = SKS.keys(sks, "g", 1, 0)
      Process.sleep(110)
      assert {:ok, %{first_token_id: 3}} = SKS.keys(sks, "g")
      # Token 1 is more than one past the current, and gone: a token the
      # group doesn't have starts at the oldest it has (Part 14, 8.3.2).
      assert {:ok, %{first_token_id: 2}} = SKS.keys(sks, "g", 1, 0)
      assert {:ok, %{first_token_id: 2}} = SKS.keys(sks, "g", 99, 0)
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

      # Without users, anyone who logged in, but anonymous sessions only if asked.
      :ok = SKS.add_group(sks, "open")
      assert {:ok, _} = SKS.keys(sks, "open", 0, 0, "mallory")
      assert {:error, :bad_user_access_denied} = SKS.keys(sks, "open", 0, 0, :anonymous)
      :ok = SKS.add_group(sks, "anyone", users: [:anonymous, "alice"])
      assert {:ok, _} = SKS.keys(sks, "anyone", 0, 0, :anonymous)
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

    test "keys are fetched from the current key on, every half lifetime", %{server: server} do
      :ok = Server.add_security_group(server, "half", key_lifetime: 2000, future_keys: 1)
      {counting, calls} = counting(server)

      {:ok, store} =
        KeyStore.start_link(
          mode: :sign,
          policy: :aes128_ctr,
          sks: [server: counting, group: "half"]
        )

      Process.sleep(2500)
      GenServer.stop(store)
      calls = calls.()

      # At the start, and at 1 and 2 s, not just when a key runs out; from
      # the current key, asking for keys to come, which 0 wouldn't give.
      assert length(calls) in 3..4

      assert Enum.all?(calls, fn {group, starting, count} ->
               {group, starting} == {"half", 0} and count > 1
             end)
    end

    test "an unknown token asks for keys only if it's newer, and less often while it doesn't come",
         %{server: server} do
      :ok = Server.add_security_group(server, "u", key_lifetime: 60_000, future_keys: 0)
      :ok = SKS.rotate(GenServer.call(server, :sks), "u")
      :ok = SKS.rotate(GenServer.call(server, :sks), "u")
      {counting, calls} = counting(server)

      {:ok, store} =
        KeyStore.start_link(mode: :sign, policy: :aes128_ctr, sks: [server: counting, group: "u"])

      table = KeyStore.table(store)
      assert eventually_current(table)
      assert {3, _} = KeyStore.current(table)
      long_ago(store)

      # Token 2 is older, which a fetch from the current key can't bring,
      # and 99 not asked for.
      assert KeyStore.lookup(table, store, 2) == nil
      assert KeyStore.lookup(table, store, 99, false) == nil
      Process.sleep(100)
      assert length(calls.()) == 1

      # A newer one is asked for; it doesn't come, so the next ask waits longer.
      assert KeyStore.lookup(table, store, 99) == nil
      assert eventually(fn -> length(calls.()) == 2 end)
      assert eventually(fn -> :sys.get_state(store).between == 4000 end)
      assert KeyStore.lookup(table, store, 99) == nil
      Process.sleep(100)
      assert length(calls.()) == 2
    end

    test "a subscriber asks for keys only for messages it reads", %{server: server} do
      :ok = Server.add_security_group(server, "r", key_lifetime: 60_000)
      {counting, calls} = counting(server)
      url = url()
      sub = subscriber(url, mode: :sign, policy: :aes128_ctr, sks: [server: counting, group: "r"])
      {_mode, store, table} = :sys.get_state(sub).security
      assert eventually_current(table)
      long_ago(store)
      unknown = [mode: :sign, policy: :aes128_ctr, keys: [{99, bytes(:aes128_ctr)}]]

      # Another publisher on the address, with a token the subscriber doesn't have.
      start_supervised!(
        {Publisher,
         url: url,
         publisher_id: 43,
         interval: 20,
         security: unknown,
         writers: [[id: 1, fields: @fields, read: fn -> @values end]]},
        id: :other
      )

      Process.sleep(300)
      assert length(calls.()) == 1

      # The publisher it reads, with that token.
      publisher(url, unknown)
      assert eventually(fn -> length(calls.()) == 2 end)
    end

    @tag :capture_log
    test "a service's answers that make no sense are survived" do
      key = bytes(:aes128_ctr)

      good = %{
        policy: :aes128_ctr,
        first_token_id: 1,
        keys: [key],
        time_to_next_key: 1000.0,
        key_lifetime: 2000.0
      }

      answers = [
        fn -> %{good | first_token_id: "1"} end,
        fn -> %{good | first_token_id: 0} end,
        fn -> %{good | first_token_id: 0x1_0000_0000} end,
        fn -> %{good | first_token_id: 0xFFFF_FFFF, keys: [key, key]} end,
        fn -> %{good | keys: "keys"} end,
        fn -> %{good | keys: [<<1, 2, 3>>]} end,
        fn -> %{good | policy: :nonsense} end,
        fn -> raise "broken" end
      ]

      stores =
        for {answer, index} <- Enum.with_index(answers) do
          fake = start_supervised!({FakeSKS, answer}, id: index)
          security = [mode: :sign, policy: :aes128_ctr, sks: [server: fake, group: "g"]]
          {:ok, store} = KeyStore.start_link(security)
          store
        end

      Process.sleep(300)
      assert Enum.all?(stores, &Process.alive?/1)
      assert {0xFFFF_FFFF, _} = KeyStore.current(KeyStore.table(Enum.at(stores, 3)))
    end

    test "a service that gives no key to come is asked when the key runs out", %{server: server} do
      :ok = Server.add_security_group(server, "one", key_lifetime: 60_000, future_keys: 0)

      {:ok, store} =
        KeyStore.start_link(mode: :sign, policy: :aes128_ctr, sks: [server: server, group: "one"])

      table = KeyStore.table(store)
      assert eventually_current(table)
      assert {1, _} = KeyStore.current(table)

      # The service moves on, and the store's timer says the key's time is up:
      # it gets the new key now, not at the refresh in 30 s.
      :ok = SKS.rotate(GenServer.call(server, :sks), "one")
      send(store, :switch)

      assert Enum.any?(1..20, fn _ ->
               Process.sleep(20)
               match?({2, _}, KeyStore.current(table))
             end)
    end

    test "odd times from a service are survived, and don't make it asked often" do
      key = bytes(:aes128_ctr)
      test = self()

      stores =
        for {next, lifetime} = times <- [
              {1000.0, 1.0e300},
              {1.0e300, 1.0e300},
              {-5.0, 1000.0},
              {:nan, :infinity},
              {:infinity, -1.0},
              {1.0, 1.0}
            ] do
          answer = fn ->
            send(test, {:asked, times})

            %{
              policy: :aes128_ctr,
              first_token_id: 1,
              keys: [key],
              time_to_next_key: next,
              key_lifetime: lifetime
            }
          end

          {:ok, fake} = GenServer.start_link(FakeSKS, answer)
          security = [mode: :sign, policy: :aes128_ctr, sks: [server: fake, group: "g"]]
          {:ok, store} = KeyStore.start_link(security)
          {times, store}
        end

      Process.sleep(1500)

      for {times, store} <- stores do
        assert KeyStore.current(KeyStore.table(store)) != nil
        GenServer.stop(store)
        # The first fetch, one when the key runs out, and then one a second
        # at most.
        assert count({:asked, times}) in 1..4, inspect(times)
      end
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
               get_keys(client, arguments("g", 0, 10))

      assert uri == Security.uri(:aes128_ctr)
      assert Enum.all?([a, b, c, d], &(byte_size(&1) == 52))
      assert time_to_next > 0 and time_to_next <= lifetime
      assert lifetime == 3_600_000.0

      assert {:ok, [_, 2, [^b, ^c], _, _]} = get_keys(client, arguments("g", 2, 2))
      assert {:ok, [_, 1, [^a], _, _]} = get_keys(client, arguments("g"))
    end

    test "is refused on a channel that isn't encrypted", %{client: client} do
      assert {:error, :bad_security_mode_insufficient} = get_keys(client, arguments("g"))

      assert {:error, :bad_security_mode_insufficient} =
               get_keys([{:security, {:basic256sha256, :sign}} | client], arguments("g"))
    end

    test "is refused to users that aren't in the group, and for a group that isn't there",
         %{client: client, server: server} do
      client = [{:security, {:basic256sha256, :sign_and_encrypt}} | client]

      assert {:error, :bad_user_access_denied} =
               get_keys(Keyword.put(client, :user, {"other", "secret"}), arguments("g"))

      assert {:error, :bad_not_found} = get_keys(client, arguments("nobody"))
      assert {:error, :bad_arguments_missing} = get_keys(client, Enum.take(arguments("g"), 2))

      # A group for any user, which isn't an anonymous one.
      :ok = Server.add_security_group(server, "open")
      assert {:ok, _} = get_keys(client, arguments("open"))

      assert {:error, :bad_user_access_denied} =
               get_keys(Keyword.delete(client, :user), arguments("open"))

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
