# Encrypted PubSub between machines, with the Security Key Service on one of them.
#
#     mix run examples/encrypted_pubsub.exs certs DIR
#         makes the certificates every node needs; copy DIR to each machine
#
#     mix run examples/encrypted_pubsub.exs publish DIR --serve 4840 --seconds 60
#         publishes a dataset to opc.udp://239.0.0.1:4840 and is the key service
#         for the group "plant", whose keys last --lifetime ms (default 10000)
#
#     mix run examples/encrypted_pubsub.exs subscribe DIR --sks opc.tcp://HOST:4840 --seconds 60
#         fetches the keys from the service and prints what arrives
#
#     mix run examples/encrypted_pubsub.exs sniff --seconds 10
#         is an eavesdropper: joins the group without keys and says whether it
#         can read the datagrams
#
# Common options: --url (opc.udp://239.0.0.1:4840), --interface (the local
# address to join multicast on), --mode (sign_and_encrypt, or sign),
# --policy (aes128_ctr, or aes256_ctr), --id (the publisher id, 42), and
# --wrong-keys and --plain, for a subscriber that has other keys, or none.

alias OPCUA.{Certificate, PubSub, Server}
alias OPCUA.PubSub.{Publisher, Subscriber}

{opts, [role | rest], _} =
  OptionParser.parse(System.argv(),
    strict: [
      serve: :integer,
      sks: :string,
      seconds: :integer,
      lifetime: :integer,
      url: :string,
      interface: :string,
      mode: :string,
      policy: :string,
      id: :integer,
      wrong_keys: :boolean,
      plain: :boolean,
      secret: :string
    ]
  )

dir = List.first(rest)
url = Keyword.get(opts, :url, "opc.udp://239.0.0.1:4840")
seconds = Keyword.get(opts, :seconds, 30)
mode = String.to_atom(Keyword.get(opts, :mode, "sign_and_encrypt"))
policy = String.to_atom(Keyword.get(opts, :policy, "aes128_ctr"))
publisher_id = Keyword.get(opts, :id, 42)
secret = Keyword.get(opts, :secret, "SECRET-PAYLOAD-0123456789")
fields = [{"Count", :uint32}, {"Wave", :double}, {"Secret", :string}]

parse_ip = fn text ->
  {:ok, ip} = :inet.parse_address(String.to_charlist(text))
  ip
end

load = fn name ->
  {Certificate.read(Path.join(dir, name <> ".der")), Certificate.read_key(Path.join(dir, name <> ".pem"))}
end

sks_security = fn sks_url ->
  {server_cert, _} = load.("server")
  {client_cert, client_key} = load.("client")

  [
    mode: mode,
    policy: policy,
    sks: [
      url: sks_url,
      group: "plant",
      security: {:basic256sha256, :sign_and_encrypt},
      trust: [server_cert],
      certificate: client_cert,
      private_key: client_key,
      application_uri: "urn:yaopcua:pubsub",
      user: {"pubsub", "secret"}
    ]
  ]
end

stamp = fn -> Calendar.strftime(DateTime.utc_now(), "%H:%M:%S") end

case role do
  "certs" ->
    File.mkdir_p!(dir)

    for {name, uri} <- [{"server", "urn:yaopcua:sks"}, {"client", "urn:yaopcua:pubsub"}] do
      {cert, key} = Certificate.self_signed(uri)
      :ok = Certificate.write(Path.join(dir, name <> ".der"), cert)
      :ok = Certificate.write_key(Path.join(dir, name <> ".pem"), key)
    end

    IO.puts("certificates in #{dir}")

  "publish" ->
    service =
      if port = opts[:serve] do
        {server_cert, server_key} = load.("server")
        {client_cert, _} = load.("client")

        {:ok, service} =
          Server.start_link(
            port: port,
            application_uri: "urn:yaopcua:sks",
            security: [{:basic256sha256, :sign_and_encrypt}],
            certificate: server_cert,
            private_key: server_key,
            trust: [client_cert],
            anonymous: false,
            users: %{"pubsub" => "secret"}
          )

        :ok =
          Server.add_security_group(service, "plant",
            policy: policy,
            key_lifetime: Keyword.get(opts, :lifetime, 10_000),
            future_keys: 2,
            users: ["pubsub"]
          )

        IO.puts("#{stamp.()} key service on port #{port}, group plant, #{policy}")
        service
      end

    sks_url = opts[:sks] || "opc.tcp://127.0.0.1:#{opts[:serve]}"
    count = :counters.new(1, [])

    {:ok, _} =
      Publisher.start_link(
        [
          url: url,
          publisher_id: publisher_id,
          interval: 100,
          ttl: 2,
          security: sks_security.(sks_url),
          writers: [
            [
              id: 1,
              fields: fields,
              read: fn ->
                n = :counters.get(count, 1) + 1
                :counters.put(count, 1, n)
                %{"Count" => n, "Wave" => :math.sin(n / 10), "Secret" => secret}
              end
            ]
          ]
        ]
      )

    IO.puts("#{stamp.()} publishing #{publisher_id} to #{url}, #{mode}")

    for _ <- 1..div(seconds, 5) do
      Process.sleep(5000)

      token =
        if service do
          {:ok, %{first_token_id: token}} = Server.security_keys(service, "plant")
          " (key token #{token})"
        else
          ""
        end

      IO.puts("#{stamp.()} sent #{:counters.get(count, 1)} messages#{token}")
    end

  "subscribe" ->
    security =
      cond do
        opts[:plain] ->
          nil

        opts[:wrong_keys] ->
          [mode: mode, policy: policy, keys: [{1, PubSub.Security.generate(policy)}]]

        true ->
          sks_security.(Keyword.fetch!(opts, :sks))
      end

    {:ok, _} =
      Subscriber.start_link(
        [
          url: url,
          to: self(),
          security: security,
          readers: [[publisher_id: publisher_id, writer_id: 1, fields: fields, timeout: 2000]]
        ] ++ if(opts[:interface], do: [interface: parse_ip.(opts[:interface])], else: [])
      )

    label = cond do
      opts[:plain] -> "no security"
      opts[:wrong_keys] -> "wrong keys"
      true -> "keys from #{opts[:sks]}"
    end

    IO.puts("#{stamp.()} subscribing to #{url} with #{label}")

    deadline = System.monotonic_time(:second) + seconds

    loop = fn loop, received, last, reported ->
      now = System.monotonic_time(:second)

      if now >= deadline do
        IO.puts("#{stamp.()} done: #{received} datasets, last #{inspect(last)}")
        System.halt(if received > 0, do: 0, else: 3)
      else
        receive do
          {PubSub, _reader, {:data, values}} ->
            reported =
              if now - reported >= 5 do
                IO.puts("#{stamp.()} #{received + 1} datasets, last #{inspect(values)}")
                now
              else
                reported
              end

            loop.(loop, received + 1, values, reported)

          {PubSub, _reader, :timeout} ->
            IO.puts("#{stamp.()} nothing arriving")
            loop.(loop, received, last, reported)
        after
          1000 -> loop.(loop, received, last, reported)
        end
      end
    end

    loop.(loop, 0, nil, 0)

  "sniff" ->
    {:ok, group, port} = PubSub.address(url)
    interface = if opts[:interface], do: parse_ip.(opts[:interface]), else: {0, 0, 0, 0}

    {:ok, socket} =
      :gen_udp.open(port, [
        :binary,
        active: true,
        reuseaddr: true,
        reuseport: true,
        add_membership: {group, interface}
      ])

    IO.puts("#{stamp.()} eavesdropping on #{url}")
    deadline = System.monotonic_time(:second) + seconds

    loop = fn loop, datagrams, readable ->
      if System.monotonic_time(:second) >= deadline do
        IO.puts(
          "#{stamp.()} saw #{datagrams} datagrams; #{readable} contained the secret in the clear"
        )

        System.halt(if datagrams > 0 and readable == 0, do: 0, else: 4)
      else
        receive do
          {:udp, ^socket, _, _, data} ->
            loop.(loop, datagrams + 1, readable + if(String.contains?(data, secret), do: 1, else: 0))
        after
          500 -> loop.(loop, datagrams, readable)
        end
      end
    end

    loop.(loop, 0, 0)
end
