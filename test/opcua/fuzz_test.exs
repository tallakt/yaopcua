defmodule OPCUA.FuzzTest do
  # Fuzzing with StreamData, in the spirit of open62541's fuzzers: random and
  # mutated bytes into every decoder and into a running server, which must
  # answer or refuse, never crash. Each property runs FUZZ_RUNS cases (100 by
  # default), or for FUZZ_SECONDS each:
  #
  #     FUZZ_SECONDS=600 mix test test/opcua/fuzz_test.exs
  use ExUnit.Case, async: false
  use ExUnitProperties

  import OPCUA.Fuzz

  alias OPCUA.{Binary, Client, NodeId, SecureChannel, Server, Transport, Variant}
  alias OPCUA.PubSub.{Subscriber, UADP}
  alias OPCUA.Types

  @moduletag timeout: :infinity

  @limits %{
    protocol_version: 0,
    receive_buffer_size: 8192,
    send_buffer_size: 8192,
    max_message_size: 0,
    max_chunk_count: 0
  }

  # Keys for the secure channel properties, and a server to throw things at.
  setup_all do
    {client_cert, client_key} = OPCUA.Certificate.self_signed("urn:client")
    {server_cert, server_key} = OPCUA.Certificate.self_signed("urn:server")

    server = start_supervised!({Server, port: 0, users: %{"operator" => "secret"}})
    2 = Server.namespace(server, "urn:fuzz")
    :ok = Server.add_object(server, "ns=2;s=Pump", "Pump")

    :ok =
      Server.add_variable(server, "ns=2;s=Pump.Speed", "Speed",
        parent: "ns=2;s=Pump",
        type: :int16,
        value: 1,
        writable: true
      )

    :ok =
      Server.add_variable(server, "ns=2;s=Pump.Levels", "Levels",
        parent: "ns=2;s=Pump",
        type: :double,
        value: [1.0],
        writable: true
      )

    :ok =
      Server.add_method(server, "ns=2;s=Pump.Add", "Add",
        parent: "ns=2;s=Pump",
        inputs: [{"a", :int32}, {"b", :int32}],
        outputs: [{"sum", :int64}],
        call: fn [a, b] -> {:ok, [a + b]} end
      )

    :ok = Server.add_condition(server, "ns=2;s=Pump.Fault", "Fault", source: "ns=2;s=Pump")
    :ok = Server.condition(server, "ns=2;s=Pump.Fault", active: true)

    %{
      keys: %{
        client_cert: client_cert,
        client_key: client_key,
        server_cert: server_cert,
        server_key: server_key
      },
      server: server,
      url: "opc.tcp://127.0.0.1:#{Server.port(server)}"
    }
  end

  defp types, do: Binary.builtins() ++ structs()

  defp typed_value, do: bind(member_of(types()), fn type -> map(value(type), &{type, &1}) end)

  defp encode(value, type), do: value |> Binary.encode(type) |> IO.iodata_to_binary()

  # Whatever decodes must encode again, and come back the same.
  defp stable(bytes, type) do
    case Binary.decode(bytes, type) do
      {:ok, value, _rest} ->
        again = encode(value, type)
        assert {:ok, ^value, ""} = Binary.decode(again, type)
        assert encode(value, type) == again

      {:error, :bad_decoding_error} ->
        :ok
    end
  end

  describe "the binary encoding" do
    property "every valid value of every type encodes and decodes to a fixed point" do
      check all({type, value} <- typed_value(), max_runs: runs(), max_run_time: run_time()) do
        bytes = encode(value, type)
        assert {:ok, decoded, ""} = Binary.decode(bytes, type)
        stable(encode(decoded, type), type)
      end
    end

    property "random bytes decode or fail cleanly, as any type" do
      check all(
              type <- member_of(types()),
              bytes <- binary(max_length: 96),
              max_runs: runs(),
              max_run_time: run_time()
            ) do
        stable(bytes, type)
      end
    end

    property "mutated encodings decode or fail cleanly" do
      check all(
              {type, value} <- typed_value(),
              bytes <- mutations(encode(value, type)),
              max_runs: runs(),
              max_run_time: run_time()
            ) do
        stable(bytes, type)
      end
    end

    property "decoded service messages survive re-encoding" do
      check all(
              module <- member_of(encodable_structs()),
              value <- value(module),
              bytes <-
                mutations(
                  IO.iodata_to_binary([
                    Binary.encode(%OPCUA.NodeId{id: module.encoding_id()}, :node_id),
                    module.encode(value)
                  ])
                ),
              max_runs: runs(),
              max_run_time: run_time()
            ) do
        case SecureChannel.decode_message(bytes) do
          {:ok, %decoded{} = message} ->
            assert {:ok, ^message, ""} =
                     Binary.decode(IO.iodata_to_binary(decoded.encode(message)), decoded)

          {:error, :bad_decoding_error} ->
            :ok
        end
      end
    end

    property "values nested up to and past the depth limits decode, or are refused, quickly" do
      check all(
              bytes <-
                bind(tuple({member_of(Map.keys(deep_types())), integer(1..130)}), fn {kind, n} ->
                  one_of([constant(deep(kind, n)), mutations(deep(kind, n))])
                  |> map(&{Map.fetch!(deep_types(), kind), &1})
                end),
              max_runs: runs(),
              max_run_time: run_time()
            ) do
        {type, bytes} = bytes
        {time, _} = :timer.tc(fn -> stable(bytes, type) end)
        assert time < 1_000_000
      end
    end

    defp deep_types,
      do: %{
        variant: :variant,
        structure: :variant,
        data_value: :data_value,
        diagnostic: :diagnostic_info
      }

    # A value `n` deep, the way each kind nests.
    defp deep(kind, n) do
      Enum.reduce(1..n, nil, fn _, inner -> deeper(kind, inner) end)
      |> Binary.encode(Map.fetch!(deep_types(), kind))
      |> IO.iodata_to_binary()
    end

    defp deeper(:variant, inner), do: %Variant{type: :variant, value: [inner]}

    defp deeper(:structure, inner) do
      %Variant{
        type: :extension_object,
        value: %Types.ContentFilterElement{
          filter_operator: :not,
          filter_operands: [%Types.LiteralOperand{value: inner}]
        }
      }
    end

    defp deeper(:data_value, inner),
      do: %OPCUA.DataValue{value: inner && %Variant{type: :data_value, value: inner}}

    defp deeper(:diagnostic, inner),
      do: %OPCUA.DiagnosticInfo{symbolic_id: 1, inner_diagnostic_info: inner}
  end

  describe "the transport and secure channel" do
    @limits %{
      protocol_version: 0,
      receive_buffer_size: 8192,
      send_buffer_size: 8192,
      max_message_size: 0,
      max_chunk_count: 0
    }

    property "framing splits or refuses any bytes" do
      check all(
              bytes <-
                one_of([
                  binary(max_length: 64),
                  bind(
                    binary(max_length: 32),
                    &mutations(Transport.frame(:message, :final, &1) |> IO.iodata_to_binary())
                  )
                ]),
              max_runs: runs(),
              max_run_time: run_time()
            ) do
        case Transport.split(bytes, 8192) do
          {:ok, chunks, rest} -> assert is_list(chunks) and is_binary(rest)
          {:error, reason} -> assert is_atom(reason)
        end

        for type <- [:hello, :acknowledge, :error, :reverse_hello],
            do: Transport.decode(type, bytes)
      end
    end

    property "a None channel answers any chunk with a result" do
      check all(
              kind <- member_of([:open, :message, :close]),
              chunk <- member_of([:final, :continued, :abort]),
              body <- binary(max_length: 96),
              max_runs: runs(),
              max_run_time: run_time()
            ) do
        assert elem(SecureChannel.receive(SecureChannel.new(@limits), {kind, chunk, body}), 0) in [
                 :ok,
                 :abort,
                 :error
               ]
      end
    end

    property "a secure channel refuses mutated chunks without crashing", %{keys: keys} do
      combinations =
        for policy <- [:basic256sha256, :aes128_sha256_rsa_oaep, :aes256_sha256_rsa_pss],
            mode <- [:sign, :sign_and_encrypt],
            do: {policy, mode}

      # Each combination gets its share of the runs.
      for {policy, mode} <- combinations do
        {client, server} = secure_pair(keys, policy, mode)

        request = %Types.ReadRequest{
          nodes_to_read: [
            %Types.ReadValueId{node_id: %OPCUA.NodeId{ns: 2, id: "Pump.Speed"}, attribute_id: 13}
          ]
        }

        {:ok, frames, _} = SecureChannel.encode(client, :message, 2, request)
        valid = IO.iodata_to_binary(frames)

        check all(
                bytes <- mutations(valid),
                max_runs: runs(length(combinations)),
                max_run_time: run_time(length(combinations))
              ) do
          case Transport.split(bytes, 100_000) do
            {:ok, chunks, _} ->
              for chunk <- chunks,
                  do:
                    assert(elem(SecureChannel.receive(server, chunk), 0) in [:ok, :abort, :error])

            {:error, _} ->
              :ok
          end
        end
      end
    end

    defp secure_pair(keys, policy, mode) do
      client =
        SecureChannel.new(@limits,
          policy: policy,
          mode: mode,
          certificate: keys.client_cert,
          private_key: keys.client_key,
          remote_certificate: keys.server_cert
        )

      server =
        SecureChannel.new(@limits,
          policies: [policy],
          certificate: keys.server_cert,
          private_key: keys.server_key
        )

      token = %Types.ChannelSecurityToken{channel_id: 1, token_id: 1, revised_lifetime: 60_000}
      [client_nonce, server_nonce] = for _ <- 1..2, do: :crypto.strong_rand_bytes(32)

      server = %{
        SecureChannel.token(%{server | policy: policy}, token, server_nonce, client_nonce)
        | mode: mode,
          remote_certificate: keys.client_cert
      }

      {SecureChannel.token(client, token, client_nonce, server_nonce), server}
    end
  end

  describe "PubSub" do
    property "UADP decodes or refuses random and mutated messages" do
      message = fn fields ->
        %UADP{
          publisher_id: {:uint16, 42},
          writer_group_id: 1,
          sequence_number: 1,
          messages: [
            %UADP.DataSetMessage{writer_id: 1, sequence_number: 1, fields: fields},
            %UADP.DataSetMessage{
              writer_id: 2,
              type: :delta_frame,
              fields: Enum.with_index(fields, &{&2, &1})
            }
          ]
        }
      end

      valid =
        map(
          list_of(value(:variant), max_length: 4),
          &(&1 |> message.() |> UADP.encode() |> IO.iodata_to_binary())
        )

      check all(
              bytes <- one_of([binary(max_length: 96), bind(valid, &mutations/1)]),
              max_runs: runs(),
              max_run_time: run_time()
            ) do
        case UADP.decode(bytes, %{1 => [:int16, :string]}) do
          {:ok, %UADP{}} -> :ok
          {:error, :bad_decoding_error} -> :ok
        end
      end
    end

    property "a subscriber survives random and mutated datagrams" do
      {:ok, socket} = :gen_udp.open(0, [:binary])
      {:ok, port} = :inet.port(socket)
      :gen_udp.close(socket)

      # Readers with and without field types, and a writer id that two
      # publishers share.
      readers = [
        [publisher_id: 42, writer_id: 1, fields: [{"a", :int16}, {"b", :string}]],
        [publisher_id: 42, writer_id: 2],
        [publisher_id: 43, writer_id: 1, fields: [{"c", :double}]]
      ]

      sink = spawn_link(&drain/0)

      subscriber =
        start_supervised!(
          {Subscriber, url: "opc.udp://127.0.0.1:#{port}", to: sink, readers: readers}
        )

      {:ok, socket} = :gen_udp.open(0, [:binary])

      check all(
              bytes <-
                one_of([
                  network_message(),
                  bind(network_message(), &mutations/1),
                  binary(max_length: 96)
                ]),
              max_runs: runs(),
              max_run_time: run_time()
            ) do
        # Within what a UDP datagram can carry here (9216 bytes on macOS).
        :ok = :gen_udp.send(socket, {127, 0, 0, 1}, port, binary_slice(bytes, 0, 8192))
        :sys.get_state(subscriber)
        assert Process.alive?(subscriber)
      end

      Process.sleep(50)
      assert Process.alive?(subscriber)
    end

    defp drain do
      receive do
        _ -> drain()
      end
    end

    defp network_message do
      gen all(
            publisher <- member_of([{:byte, 42}, {:uint16, 42}, {:byte, 43}, {:byte, 44}]),
            messages <- list_of(dataset_message(), min_length: 1, max_length: 3)
          ) do
        %UADP{publisher_id: publisher, writer_group_id: 1, sequence_number: 1, messages: messages}
        |> UADP.encode()
        |> IO.iodata_to_binary()
      end
    end

    defp dataset_message do
      gen all(
            writer <- member_of([1, 2]),
            encoding <- member_of([:variant, :raw, :data_value]),
            type <- member_of([:key_frame, :delta_frame, :keep_alive]),
            sequence <- integer(0..0xFFFF),
            fields <- list_of(field(encoding), max_length: 3)
          ) do
        fields =
          case type do
            :key_frame -> fields
            :delta_frame -> Enum.with_index(fields, &{&2, &1})
            :keep_alive -> []
          end

        %UADP.DataSetMessage{
          writer_id: writer,
          type: type,
          encoding: encoding,
          sequence_number: sequence,
          fields: fields
        }
      end
    end

    defp field(:raw),
      do:
        bind(member_of([:int16, :string, :double]), fn type -> map(value(type), &{type, &1}) end)

    defp field(encoding), do: value(encoding)
  end

  describe "a client" do
    # Every client call there is, against a server that answers anything.
    @calls [
      :read,
      :read_many,
      :write,
      :write_plain,
      :browse,
      :call,
      :subscribe,
      :subscribe_events,
      :request
    ]

    property "a client survives whatever a hostile server answers" do
      hostile = OPCUA.HostileServer.start()
      responses = for m <- structs(), String.ends_with?(inspect(m), "Response"), do: m

      check all(
              call <- member_of(@calls),
              seed <- integer(),
              max_runs: runs(),
              max_run_time: run_time()
            ) do
        OPCUA.HostileServer.answer(hostile, fn request, n ->
          [answer] = Enum.take(StreamData.seeded(answer(request, responses), seed + n), 1)
          answer
        end)

        log =
          ExUnit.CaptureLog.capture_log(fn ->
            # The session may fail, if the server spoils it, but not crash.
            case Client.start(url: hostile.url, timeout: 200) do
              {:ok, client} -> use_client(client, call)
              {:error, reason} -> assert is_atom(reason) or is_integer(reason), inspect(reason)
            end
          end)

        refute log =~ "terminating", log
        refute log =~ "** (", log
      end
    end

    defp use_client(client, call) do
      ref = Process.monitor(client)

      # It answers, or stops: any exception here is a failure.
      try do
        client_call(call, client)
      catch
        :exit, _ -> :ok
      end

      try do
        Client.close(client)
      catch
        :exit, _ -> :ok
      end

      assert_receive {:DOWN, ^ref, :process, _, reason}, 5000
      assert reason in [:normal, :noproc] or match?({:shutdown, _}, reason), inspect(reason)
    end

    defp client_call(:read, client), do: Client.read(client, "ns=2;s=X")
    defp client_call(:read_many, client), do: Client.read_many(client, ["ns=2;s=X", "i=2258"])

    defp client_call(:write, client),
      do: Client.write(client, "ns=2;s=X", %Variant{type: :int16, value: 1})

    defp client_call(:write_plain, client), do: Client.write(client, "ns=2;s=X", 5)
    defp client_call(:browse, client), do: Client.browse(client, "i=85")
    defp client_call(:call, client), do: Client.call(client, "i=85", "ns=2;s=M", [1, 2.5])

    defp client_call(:subscribe, client) do
      with {:ok, sub} <- Client.subscribe(client, ["ns=2;s=X", "ns=2;s=Y"], interval: 10) do
        Process.sleep(30)
        Client.unsubscribe(client, sub)
      end
    end

    defp client_call(:subscribe_events, client) do
      with {:ok, sub} <- Client.subscribe_events(client, interval: 10) do
        Client.refresh(client, sub)
        Process.sleep(30)
        Client.acknowledge(client, "ns=2;s=Alarm", "id", "ok")
        Client.unsubscribe(client, sub)
      end
    end

    defp client_call(:request, client),
      do: Client.request(client, %Types.TranslateBrowsePathsToNodeIdsRequest{})

    # The right response with random contents, most often; or any response,
    # a fault, a mangled one, or nothing. The session is set up properly
    # most of the time, so that the calls get a turn.
    defp answer(request, responses) do
      type = OPCUA.Client.Connection.response_type(request)
      session = request.__struct__ in [Types.CreateSessionRequest, Types.ActivateSessionRequest]
      default = if session, do: [{60, constant(:default)}], else: []

      frequency(
        default ++
          [
            {6, map(value(type), &{:response, &1})},
            {2, map(bind(member_of(responses), &value/1), &{:response, &1})},
            {1, map(value(Types.ServiceFault), &{:response, &1})},
            {2, map(tuple({value(type), integer()}), fn {r, seed} -> {:mangled, r, seed} end)},
            {1, constant(:nothing)}
          ]
      )
    end
  end

  describe "a running server" do
    # The server must still answer a well-behaved client.
    defp healthy(url) do
      {:ok, client} = Client.start(url: url)
      assert {:ok, _} = Client.read(client, "ns=2;s=Pump.Speed")
      Client.close(client)
    end

    defp tcp(url) do
      {:ok, {host, port}} = Transport.endpoint(url)
      {:ok, socket} = :gen_tcp.connect(host, port, [:binary, active: false], 1000)
      socket
    end

    property "garbage on a new connection is refused", %{url: url} do
      hello =
        Transport.frame(:hello, :final, Transport.hello(@limits, url)) |> IO.iodata_to_binary()

      check all(
              bytes <- one_of([binary(max_length: 128), mutations(hello)]),
              max_runs: runs(),
              max_run_time: run_time()
            ) do
        log =
          ExUnit.CaptureLog.capture_log(fn ->
            socket = tcp(url)
            :ok = :gen_tcp.send(socket, bytes)
            # An answer, an Error message, or the connection closes; nothing crashes.
            _ = :gen_tcp.recv(socket, 0, 100)
            :gen_tcp.close(socket)
          end)

        refute log =~ "terminating", log
      end

      healthy(url)
    end

    property "mutated requests on an open session are answered or refused", %{
      url: url,
      server: server
    } do
      check all(
              module <- member_of(requests() -- excluded()),
              request <- value(module),
              mutation <- integer(0..1_000_000),
              max_runs: runs(),
              max_run_time: run_time()
            ) do
        {:ok, state} = OPCUA.Client.Connection.connect(url, 1000, 60_000)
        {:ok, state} = OPCUA.Client.Connection.session(state, [])
        {id, channel} = SecureChannel.next_request_id(state.channel)

        {request, state} =
          OPCUA.Client.Connection.with_header(%{state | channel: channel}, request, 1000)

        {:ok, frames, _} = SecureChannel.encode(state.channel, :message, id, request)
        valid = IO.iodata_to_binary(frames)

        # One mutation, picked by the seed, so shrinking stays meaningful.
        [bytes] = Enum.take(StreamData.seeded(mutations(valid), mutation), 1)

        log =
          ExUnit.CaptureLog.capture_log(fn ->
            :ok = :gen_tcp.send(state.socket, bytes)
            _ = :gen_tcp.recv(state.socket, 0, 100)
            :gen_tcp.close(state.socket)
          end)

        # The connection may be refused or closed, but nothing may crash.
        refute log =~ "terminating", log
        refute log =~ "failed", log
        assert Process.alive?(server)
      end

      healthy(url)
    end

    property "every request with random contents gets an answer, and no internal error", %{
      url: url,
      server: server
    } do
      check all(
              module <- member_of(requests() -- excluded()),
              request <- value(module),
              max_runs: runs(),
              max_run_time: run_time()
            ) do
        client = client(url)

        {result, log} =
          ExUnit.CaptureLog.with_log(fn -> Client.request(client, request, 2000) end)

        assert match?({:ok, _}, result) or match?({:error, _}, result), inspect(result)
        refute log =~ "failed", log
        refute log =~ "terminating", log
        assert Process.alive?(client), "the connection closed on #{inspect(module)}"
        assert Process.alive?(server)
      end

      with {client, _} <- Process.get(:fuzz_client), do: Client.close(client)
      healthy(url)
    end

    property "method calls with random arguments get an answer, and no internal error", %{
      url: url,
      server: server
    } do
      # The application's method, and the alarm methods on its condition.
      methods = [
        {"ns=2;s=Pump", "ns=2;s=Pump.Add"},
        {"ns=2;s=Pump.Fault", "i=9111"},
        {"ns=2;s=Pump.Fault", "i=9029"},
        {"ns=2;s=Pump.Fault", "i=9027"},
        {"ns=2;s=Pump.Fault", "i=9028"},
        {"i=2782", "i=3875"},
        {"i=2782", "i=12912"}
      ]

      argument =
        one_of([
          constant(nil),
          value(:variant),
          map(integer(-100..100), &%Variant{type: :int32, value: &1}),
          map(integer(0..10), &%Variant{type: :uint32, value: &1})
        ])

      check all(
              {object, method} <- member_of(methods),
              args <- one_of([constant(nil), list_of(argument, max_length: 3)]),
              max_runs: runs(),
              max_run_time: run_time()
            ) do
        call = %Types.CallMethodRequest{
          object_id: NodeId.parse!(object),
          method_id: NodeId.parse!(method),
          input_arguments: args
        }

        client = client(url)
        request = %Types.CallRequest{methods_to_call: [call]}

        {result, log} =
          ExUnit.CaptureLog.with_log(fn -> Client.request(client, request, 2000) end)

        assert match?({:ok, _}, result) or match?({:error, _}, result), inspect(result)
        refute log =~ "failed", log
        refute log =~ "terminating", log
        assert Process.alive?(server)
      end

      with {client, _} <- Process.get(:fuzz_client), do: Client.close(client)
      healthy(url)
    end

    property "random event filters are checked, and events go through them", %{
      url: url,
      server: server
    } do
      paths = ["Message", "Severity", "EventType", "SourceNode", "ActiveState/Id", "2:Nope"]
      operators = Keyword.keys(Types.FilterOperator.values())

      # Mostly what the server evaluates, and elements referring forward, as
      # a valid filter does; now and then anything.
      supported =
        [:equals, :is_null, :greater_than, :less_than, :greater_than_or_equal] ++
          [:less_than_or_equal, :not, :between, :in_list, :and, :or, :of_type]

      literal =
        one_of([
          value(:variant),
          map(integer(0..1000), &%Variant{type: :uint16, value: &1}),
          map(boolean(), &%Variant{type: :boolean, value: &1}),
          map(
            member_of([2041, 2782, 2915, 10637]),
            &%Variant{type: :node_id, value: %NodeId{id: &1}}
          )
        ])

      operand = fn index, count ->
        reference =
          if index + 1 < count,
            do: [{6, map(integer((index + 1)..(count - 1)), &%Types.ElementOperand{index: &1})}],
            else: []

        frequency(
          reference ++
            [
              {1, map(integer(0..(count + 1)), &%Types.ElementOperand{index: &1})},
              {3, map(literal, &%Types.LiteralOperand{value: &1})},
              {3,
               map(member_of(paths), fn path ->
                 %Types.SimpleAttributeOperand{
                   browse_path:
                     path |> String.split("/") |> Enum.map(&OPCUA.QualifiedName.parse/1),
                   attribute_id: 13
                 }
               end)},
              {1, constant(nil)}
            ]
        )
      end

      element = fn index, count ->
        map(
          tuple({
            frequency([{9, member_of(supported)}, {1, member_of(operators)}]),
            list_of(operand.(index, count), max_length: 3)
          }),
          fn {operator, operands} ->
            %Types.ContentFilterElement{filter_operator: operator, filter_operands: operands}
          end
        )
      end

      filter =
        bind(integer(1..8), fn count ->
          fixed_list(for index <- 0..(count - 1), do: element.(index, count))
        end)

      check all(
              elements <- filter,
              active <- boolean(),
              max_runs: runs(),
              max_run_time: run_time()
            ) do
        client = client(url)
        where = %Types.ContentFilter{elements: elements}

        {_, log} =
          ExUnit.CaptureLog.with_log(fn ->
            with {:ok, sub} <-
                   Client.subscribe_events(client,
                     where: where,
                     fields: ["Message", "Severity"],
                     interval: 20
                   ) do
              :ok = Server.event(server, message: "fuzz", severity: 300)
              Server.condition(server, "ns=2;s=Pump.Fault", active: active)
              # Answered after the connection has taken the events.
              {:ok, _} = Client.read(client, "ns=2;s=Pump.Speed")
              Client.unsubscribe(client, sub)
            end
          end)

        drain_mailbox()
        refute log =~ "failed", log
        refute log =~ "terminating", log
        assert Process.alive?(client)
        assert Process.alive?(server)
      end

      with {client, _} <- Process.get(:fuzz_client), do: Client.close(client)
      healthy(url)
    end

    defp drain_mailbox do
      receive do
        {Client, _, _} -> drain_mailbox()
      after
        0 -> :ok
      end
    end

    # A client for a run of 50 cases, so that what the requests create, such
    # as subscriptions, doesn't pile up. One per case would open connections
    # faster than closed ones leave TIME_WAIT, and run out of ports.
    defp client(url) do
      case Process.get(:fuzz_client) do
        {client, n} when n < 50 ->
          if Process.alive?(client) do
            Process.put(:fuzz_client, {client, n + 1})
            client
          else
            new_client(url)
          end

        {client, _} ->
          Client.close(client)
          new_client(url)

        nil ->
          new_client(url)
      end
    end

    defp new_client(url) do
      {:ok, client} = Client.start(url: url, timeout: 2000)
      Process.put(:fuzz_client, {client, 1})
      client
    end

    # Requests that would end the session or wait for notifications.
    defp excluded do
      [
        Types.CreateSessionRequest,
        Types.ActivateSessionRequest,
        Types.CloseSessionRequest,
        Types.PublishRequest,
        Types.OpenSecureChannelRequest,
        Types.CloseSecureChannelRequest
      ]
    end
  end
end
