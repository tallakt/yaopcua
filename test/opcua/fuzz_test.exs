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

  alias OPCUA.{Binary, Client, SecureChannel, Server, Transport}
  alias OPCUA.PubSub.UADP
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
