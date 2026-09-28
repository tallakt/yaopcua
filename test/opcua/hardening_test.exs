defmodule OPCUA.HardeningTest do
  # What a hostile client or network can try, from the attack surface
  # analysis, and what stops it. The server must stay up and answer everyone
  # else.
  use ExUnit.Case, async: true

  import ExUnit.CaptureLog

  alias OPCUA.{Binary, Certificate, Client, NodeId, SecureChannel, Server, Transport, Variant}
  alias OPCUA.Client.Connection
  alias OPCUA.PubSub.{Subscriber, UADP}
  alias OPCUA.Types

  @limits %{
    protocol_version: 0,
    receive_buffer_size: 8192,
    send_buffer_size: 8192,
    max_message_size: 0,
    max_chunk_count: 0
  }

  defp start_server(opts \\ []) do
    server = start_supervised!({Server, Keyword.merge([port: 0], opts)}, id: make_ref())
    :ok = Server.add_variable(server, "ns=1;s=X", "X", type: :int16, value: 7)
    :ok = Server.add_variable(server, "ns=1;s=Levels", "Levels", type: :double, value: [1.0, 2.0])
    {server, "opc.tcp://127.0.0.1:#{Server.port(server)}"}
  end

  defp client(url), do: start_supervised!({Client, url: url}, id: make_ref())

  defp connections(server) do
    for {_, pid, _, _} <- DynamicSupervisor.which_children(:sys.get_state(server).connections),
        is_pid(pid),
        do: pid
  end

  defp literal(type, value), do: %Types.LiteralOperand{value: %Variant{type: type, value: value}}

  defp element(operator, operands),
    do: %Types.ContentFilterElement{filter_operator: operator, filter_operands: operands}

  defp tcp(url) do
    {:ok, {host, port}} = Transport.endpoint(url)
    {:ok, socket} = :gen_tcp.connect(host, port, [:binary, active: false])
    socket
  end

  describe "event filters" do
    test "one that refers to itself, backwards or past its end is refused" do
      {server, url} = start_server()
      client = client(url)
      not_false = element(:not, [literal(:boolean, false)])

      for elements <- [
            [element(:not, [%Types.ElementOperand{index: 0}])],
            [element(:not, [%Types.ElementOperand{index: 5}])],
            [not_false, element(:not, [%Types.ElementOperand{index: 0}])]
          ] do
        where = %Types.ContentFilter{elements: elements}
        {:ok, sub} = Client.subscribe_events(client, where: where)
        assert_receive {Client, ^sub, {:status, :bad_monitored_item_filter_invalid}}, 1000
      end

      :ok = Server.event(server, message: "after")
      assert Client.read(client, "ns=1;s=X") == {:ok, 7}
    end

    test "an element that many refer to is evaluated once" do
      {server, url} = start_server()
      client = client(url)

      # Each element compares the next with itself: evaluated by following
      # references, that's 2^40 comparisons.
      elements =
        for(
          i <- 0..39,
          do:
            element(:equals, [
              %Types.ElementOperand{index: i + 1},
              %Types.ElementOperand{index: i + 1}
            ])
        ) ++ [element(:equals, [literal(:int32, 1), literal(:int32, 1)])]

      {:ok, sub} =
        Client.subscribe_events(client,
          where: %Types.ContentFilter{elements: elements},
          fields: ["Message"],
          interval: 50
        )

      :ok = Server.event(server, message: "through")

      assert_receive {Client, ^sub, {:event, %{"Message" => %{text: "through"}}}}, 2000
    end
  end

  describe "decoding" do
    defp nested(n) do
      Enum.reduce(1..n, %Variant{type: :int32, value: 1}, fn _, inner ->
        %Variant{
          type: :extension_object,
          value: element(:not, [%Types.LiteralOperand{value: inner}])
        }
      end)
      |> Binary.encode(:variant)
      |> IO.iodata_to_binary()
    end

    test "structures nested past the limit are refused, and quickly" do
      # Each level is two structures: the element, and its operand.
      assert {:ok, _, ""} = Binary.decode(nested(50), :variant)
      assert Binary.decode(nested(51), :variant) == {:error, :bad_decoding_error}

      # Copying each level's body made this take seconds.
      deep = nested(5000)
      {time, result} = :timer.tc(fn -> Binary.decode(deep, :variant) end)
      assert result == {:error, :bad_decoding_error}
      assert time < 100_000
    end

    test "an index range too long to be one is refused before it's parsed" do
      {_server, url} = start_server()
      client = client(url)

      read = %Types.ReadValueId{
        node_id: NodeId.parse!("ns=1;s=Levels"),
        attribute_id: 13,
        index_range: "0:" <> String.duplicate("9", 100_000)
      }

      assert {:ok, %{results: [result]}} =
               Client.request(client, %Types.ReadRequest{nodes_to_read: [read]})

      assert OPCUA.StatusCode.name(result.status) == :bad_index_range_invalid
    end
  end

  describe "limits" do
    test "connections past the limit are refused" do
      {_server, url} = start_server(limits: [connections: 2])
      client(url)
      client(url)
      assert Client.start(url: url) == {:error, :bad_max_connections_reached}
    end

    test "sessions, subscriptions and monitored items past their limits are refused" do
      {_server, url} =
        start_server(limits: [sessions: 1, subscriptions: 2, monitored_items: 3])

      {:ok, state} = Connection.connect(url, 1000, 60_000)
      {:ok, state} = Connection.session(state, [])
      assert Connection.session(state, []) == {:error, :bad_too_many_sessions}
      :gen_tcp.close(state.socket)

      client = client(url)
      {:ok, _} = Client.subscribe(client, ["ns=1;s=X"])
      {:ok, sub} = Client.subscribe(client, ["ns=1;s=X", "ns=1;s=X", "ns=1;s=X"])
      assert Client.subscribe(client, ["ns=1;s=X"]) == {:error, :bad_too_many_subscriptions}

      statuses =
        for _ <- 1..3 do
          assert_receive {Client, ^sub, {:value, _, %{status: status}}}, 2000
          OPCUA.StatusCode.name(status)
        end

      assert Enum.sort(statuses) == [:bad_too_many_monitored_items, :good, :good]
    end

    test "a message over the size limit isn't sent, and isn't taken if it is" do
      {_server, url} = start_server(limits: [message_size: 100_000])
      client = client(url)
      nodes = List.duplicate("ns=1;s=X", 20_000)
      assert Client.read_many(client, nodes) == {:error, :bad_request_too_large}

      # A client that ignores the limit is cut off.
      {:ok, state} = Connection.connect(url, 1000, 60_000)
      {:ok, state} = Connection.session(state, [])
      channel = %{state.channel | send_max_message: 0}
      {id, channel} = SecureChannel.next_request_id(channel)

      reads =
        for node <- nodes, do: %Types.ReadValueId{node_id: NodeId.parse!(node), attribute_id: 13}

      {request, _} =
        Connection.with_header(
          %{state | channel: channel},
          %Types.ReadRequest{nodes_to_read: reads},
          1000
        )

      {:ok, frames, _} = SecureChannel.encode(channel, :message, id, request)
      :ok = :gen_tcp.send(state.socket, frames)
      assert {:ok, <<"ERRF", _::binary>>} = :gen_tcp.recv(state.socket, 0, 2000)
      assert Client.read(client, "ns=1;s=X") == {:ok, 7}
    end

    test "a connection that needs more memory than its limit is closed, and only it" do
      {server, url} = start_server(limits: [connection_memory: 2_000_000])
      client = client(url)
      {:ok, greedy} = Client.start(url: url)
      ref = Process.monitor(greedy)

      capture_log(fn ->
        # An error from the client as it stops, or its exit.
        result =
          try do
            Client.read_many(greedy, List.duplicate("ns=1;s=X", 20_000))
          catch
            :exit, _ -> :exit
          end

        refute match?({:ok, _}, result)
        assert_receive {:DOWN, ^ref, :process, _, {:shutdown, _}}, 5000
      end)

      assert Process.alive?(server)
      assert Client.read(client, "ns=1;s=X") == {:ok, 7}
    end

    test "a connection that doesn't open its channel in time is closed" do
      {_server, url} = start_server(limits: [open_timeout: 200])
      socket = tcp(url)
      :ok = :gen_tcp.send(socket, Transport.frame(:hello, :final, Transport.hello(@limits, url)))
      assert {:ok, <<"ACKF", _::binary>>} = :gen_tcp.recv(socket, 0, 1000)
      assert {:ok, <<"ERRF", _::binary>>} = :gen_tcp.recv(socket, 0, 1000)
      assert {:error, :closed} = :gen_tcp.recv(socket, 0, 1000)
    end

    test "a connection without an activated session is closed after a while, one with one isn't" do
      {_server, url} = start_server(limits: [session_wait: 200])
      client = client(url)

      # A channel alone, and one with a session created but not activated.
      {:ok, bare} = Connection.connect(url, 1000, 60_000)
      {:ok, created} = Connection.connect(url, 1000, 60_000)

      {:ok, _, created} =
        Connection.exchange(created, %Types.CreateSessionRequest{
          requested_session_timeout: 3_600_000.0
        })

      for state <- [bare, created],
          do: assert({:ok, <<"ERRF", _::binary>>} = :gen_tcp.recv(state.socket, 0, 1000))

      assert Client.read(client, "ns=1;s=X") == {:ok, 7}
    end

    test "a busy session and a renewing channel leave one timer each" do
      {server, url} = start_server()
      client = start_supervised!({Client, url: url, channel_lifetime: 1000})
      [connection] = connections(server)

      timers = fn ->
        state = :sys.get_state(connection)
        [session] = Map.values(state.sessions)
        {session.timer, state.token_timer}
      end

      {session_timer, token_timer} = timers.()
      for _ <- 1..10, do: {:ok, 7} = Client.read(client, "ns=1;s=X")
      {new_session_timer, _} = timers.()
      assert new_session_timer != session_timer
      assert Process.read_timer(session_timer) == false

      # The client renews at 75% of the channel's lifetime.
      new_token_timer =
        Enum.find_value(1..30, fn _ ->
          Process.sleep(100)
          {_, timer} = timers.()
          timer != token_timer && timer
        end)

      assert new_token_timer
      assert Process.read_timer(token_timer) == false
    end
  end

  describe "certificates" do
    setup do
      {client_cert, client_key} = Certificate.self_signed("urn:client")
      {server_cert, server_key} = Certificate.self_signed("urn:server")
      %{client: {client_cert, client_key}, server: {server_cert, server_key}}
    end

    test "an OpenSecureChannel from an untrusted or weak certificate is refused before any RSA",
         %{client: {client_cert, _} = client, server: {server_cert, server_key}} do
      server =
        SecureChannel.new(@limits,
          policies: [:basic256sha256],
          certificate: server_cert,
          private_key: server_key,
          trust: [client_cert]
        )

      # The last byte garbled, so that decrypting it would fail.
      open = fn {cert, key} ->
        channel =
          SecureChannel.new(@limits,
            policy: :basic256sha256,
            mode: :sign_and_encrypt,
            certificate: cert,
            private_key: key,
            remote_certificate: server_cert
          )

        request = %Types.OpenSecureChannelRequest{
          request_type: :issue,
          security_mode: :sign_and_encrypt,
          client_nonce: :crypto.strong_rand_bytes(32),
          requested_lifetime: 60_000
        }

        {:ok, frames, _} = SecureChannel.encode(channel, :open, 1, request)
        bytes = IO.iodata_to_binary(frames)
        garbled = binary_part(bytes, 0, byte_size(bytes) - 1) <> <<:binary.last(bytes) + 1>>
        {:ok, [chunk], ""} = Transport.split(garbled, 100_000)
        SecureChannel.receive(server, chunk)
      end

      assert open.(Certificate.self_signed("urn:client")) == {:error, :bad_certificate_untrusted}

      assert open.(Certificate.self_signed("urn:client", key_size: 1024)) ==
               {:error, :bad_certificate_policy_check_failed}

      # The trusted one gets as far as the garbled ciphertext.
      assert open.(client) == {:error, :bad_security_checks_failed}
    end

    test "a user certificate with a weak key is refused, even when any is trusted" do
      {_server, url} = start_server(user_certificates: :any)
      {cert, key} = Certificate.self_signed("urn:operator", key_size: 1024)

      assert Client.start(url: url, user: {:certificate, cert, key}) ==
               {:error, :bad_identity_token_rejected}
    end

    test "a client refuses a server whose key is too weak for the policy" do
      {cert, key} = Certificate.self_signed("urn:weak", key_size: 1024)

      {_server, url} =
        start_server(
          security: [:basic256sha256],
          trust: :any,
          certificate: cert,
          private_key: key
        )

      assert Client.start(url: url, security: :basic256sha256, trust: :any) ==
               {:error, :bad_certificate_policy_check_failed}
    end
  end

  describe "a hostile server" do
    test "can't make the client or its caller crash with what it answers" do
      hostile = OPCUA.HostileServer.start()

      OPCUA.HostileServer.answer(hostile, fn
        # The node is a String, it says.
        %Types.ReadRequest{}, _ ->
          value = %OPCUA.DataValue{value: %Variant{type: :string, value: "x"}}
          {:response, %Types.ReadResponse{results: [value]}}

        # A write gets an answer of another service.
        %Types.WriteRequest{}, _ ->
          {:response, %Types.BrowseResponse{}}

        # NaN and zeros for the subscription, and no results for its items.
        %Types.CreateSubscriptionRequest{}, _ ->
          {:response,
           %Types.CreateSubscriptionResponse{
             subscription_id: 1,
             revised_publishing_interval: :nan,
             revised_max_keep_alive_count: 0
           }}

        %Types.CreateMonitoredItemsRequest{}, _ ->
          {:response, %Types.CreateMonitoredItemsResponse{results: nil}}

        # The session as it should be, and nothing else.
        _, _ ->
          :default
      end)

      {:ok, client} = Client.start(url: hostile.url, timeout: 300)
      assert Client.write(client, "ns=2;s=X", 5) == {:error, :bad_type_mismatch}

      assert Client.write(client, "ns=2;s=X", %Variant{type: :int16, value: 5}) ==
               {:error, :bad_unknown_response}

      assert {:ok, _} = Client.subscribe(client, ["ns=2;s=X"])
      Process.sleep(100)
      assert Process.alive?(client)
    end
  end

  describe "PubSub" do
    test "a UDP flood waits in the socket, not in the subscriber's mailbox" do
      {:ok, socket} = :gen_udp.open(0)
      {:ok, port} = :inet.port(socket)
      :gen_udp.close(socket)

      subscriber =
        start_supervised!(
          {Subscriber,
           url: "opc.udp://127.0.0.1:#{port}",
           to: self(),
           readers: [[publisher_id: 1, writer_id: 1, fields: [{"a", :int16}]]]}
        )

      :sys.suspend(subscriber)
      {:ok, socket} = :gen_udp.open(0, [:binary])
      for _ <- 1..5000, do: :gen_udp.send(socket, {127, 0, 0, 1}, port, :binary.copy(<<0>>, 100))
      Process.sleep(200)
      assert {:message_queue_len, queued} = Process.info(subscriber, :message_queue_len)
      assert queued <= 101
      :sys.resume(subscriber)

      # It still reads what comes after, once the flood has drained.
      message =
        %UADP{
          publisher_id: {:byte, 1},
          messages: [
            %UADP.DataSetMessage{writer_id: 1, fields: [%Variant{type: :int16, value: 5}]}
          ]
        }
        |> UADP.encode()

      Enum.find_value(1..50, fn _ ->
        :gen_udp.send(socket, {127, 0, 0, 1}, port, message)

        receive do
          {OPCUA.PubSub, {1, 1}, {:data, %{"a" => 5}}} -> true
        after
          50 -> nil
        end
      end) || flunk("no data after the flood")
    end
  end
end
