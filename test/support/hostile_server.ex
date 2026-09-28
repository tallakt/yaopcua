defmodule OPCUA.HostileServer do
  @moduledoc false
  # A server for fuzzing the client. It does the handshake and opens the
  # channel properly, then answers every request with what `answer` returns
  # for it:
  #
  #   * `:default` - a proper answer to a session request (CreateSession,
  #     ActivateSession, CloseSession), and none to anything else
  #   * `{:response, struct}` - sent with the request's handle
  #   * `{:mangled, struct, seed}` - encoded, then mutated as the seed says
  #   * `{:bytes, binary}` - sent as they are
  #   * `:nothing` - no answer at all
  #
  # `answer` is set per case with `answer/2`, and gets the request and how
  # many requests came before it in the case.

  alias OPCUA.{SecureChannel, Transport}
  alias OPCUA.Types

  @limits %{
    protocol_version: 0,
    receive_buffer_size: 65_535,
    send_buffer_size: 65_535,
    max_message_size: 0,
    max_chunk_count: 0
  }

  def start do
    {:ok, listen} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
    {:ok, port} = :inet.port(listen)
    {:ok, answers} = Agent.start(fn -> fn _, _ -> :default end end)
    spawn(fn -> accept(listen, answers) end)
    %{url: "opc.tcp://127.0.0.1:#{port}", answers: answers}
  end

  def answer(server, fun), do: Agent.update(server.answers, fn _ -> fun end)

  # Until the process that started it, which owns the listening socket, ends.
  defp accept(listen, answers) do
    with {:ok, socket} <- :gen_tcp.accept(listen) do
      pid = spawn(fn -> receive(do: (:go -> loop(%{socket: socket, answers: answers}))) end)
      :ok = :gen_tcp.controlling_process(socket, pid)
      send(pid, :go)
      accept(listen, answers)
    end
  end

  defp loop(state) do
    state = Map.merge(%{buffer: <<>>, channel: nil, count: 0}, state)

    case :gen_tcp.recv(state.socket, 0) do
      {:ok, data} ->
        {:ok, chunks, rest} = Transport.split(state.buffer <> data, 1_000_000)
        state = Enum.reduce(chunks, %{state | buffer: rest}, &chunk/2)
        loop(state)

      {:error, _} ->
        :gen_tcp.close(state.socket)
    end
  end

  defp chunk({:hello, _, _}, state) do
    send_frame(state, Transport.frame(:acknowledge, :final, Transport.acknowledge(@limits)))
    %{state | channel: SecureChannel.new(@limits)}
  end

  defp chunk(chunk, state) do
    case SecureChannel.receive(state.channel, chunk) do
      {:ok, {:open, id, request}, channel} ->
        token = %Types.ChannelSecurityToken{
          channel_id: 1,
          token_id: 1,
          revised_lifetime: 3_600_000
        }

        response = %Types.OpenSecureChannelResponse{
          response_header: header(request),
          security_token: token,
          server_nonce: ""
        }

        channel = SecureChannel.token(channel, token)
        respond(%{state | channel: channel}, :open, id, response)

      {:ok, {:message, id, request}, channel} ->
        message(%{state | channel: channel}, id, request)

      {:ok, channel} ->
        %{state | channel: channel}

      _ ->
        state
    end
  end

  defp message(state, id, request) do
    answer = Agent.get(state.answers, & &1)
    state = %{state | count: state.count + 1}

    case answer.(request, state.count - 1) do
      :default -> default(state, id, request)
      answer -> send_answer(state, id, request, answer)
    end
  end

  defp default(state, id, %Types.CreateSessionRequest{} = request) do
    respond(state, :message, id, %Types.CreateSessionResponse{
      response_header: header(request),
      session_id: %OPCUA.NodeId{ns: 1, id: 1},
      authentication_token: %OPCUA.NodeId{ns: 0, id: {:opaque, "token"}},
      revised_session_timeout: 60_000.0,
      server_nonce: :binary.copy(<<1>>, 32)
    })
  end

  defp default(state, id, %Types.ActivateSessionRequest{} = request) do
    respond(state, :message, id, %Types.ActivateSessionResponse{
      response_header: header(request),
      server_nonce: :binary.copy(<<2>>, 32)
    })
  end

  defp default(state, id, %Types.CloseSessionRequest{} = request),
    do:
      respond(state, :message, id, %Types.CloseSessionResponse{response_header: header(request)})

  defp default(state, _, _), do: state

  defp send_answer(state, id, request, answer) do
    case answer do
      {:response, %{response_header: _} = response} ->
        response = %{response | response_header: header(request, response.response_header)}
        respond(state, :message, id, response)

      {:response, other} ->
        respond(state, :message, id, other)

      {:mangled, response, seed} ->
        response = %{response | response_header: header(request, response.response_header)}

        case SecureChannel.encode(state.channel, :message, id, response) do
          {:ok, frames, channel} ->
            mutations = OPCUA.Fuzz.mutations(IO.iodata_to_binary(frames))
            [bytes] = Enum.take(StreamData.seeded(mutations, seed), 1)
            send_frame(state, bytes)
            %{state | channel: channel}

          {:error, _} ->
            state
        end

      {:bytes, bytes} ->
        send_frame(state, bytes)
        state

      :nothing ->
        state
    end
  end

  defp header(request, header \\ %Types.ResponseHeader{}) do
    %{(header || %Types.ResponseHeader{}) | request_handle: request.request_header.request_handle}
  end

  defp respond(state, kind, id, response) do
    case SecureChannel.encode(state.channel, kind, id, response) do
      {:ok, frames, channel} ->
        send_frame(state, frames)
        %{state | channel: channel}

      {:error, _} ->
        state
    end
  end

  defp send_frame(state, frames), do: :gen_tcp.send(state.socket, frames)
end
