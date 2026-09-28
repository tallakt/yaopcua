defmodule OPCUA.Server.Connection do
  @moduledoc false
  # One client connection to a server: the UA-TCP handshake, the secure
  # channel, and the sessions made on it. Requests are answered in order, in
  # this process, by OPCUA.Server.Services.

  use GenServer, restart: :temporary

  require Logger

  alias OPCUA.{SecureChannel, StatusCode, Transport}
  alias OPCUA.Server.{Services, Subscriptions}
  alias OPCUA.Types

  @receive_buffer 65_535
  @max_message 16_777_216
  @hello_timeout 10_000

  def start_link({config, socket}), do: GenServer.start_link(__MODULE__, {config, socket})

  @impl true
  def init({config, socket}) do
    Process.send_after(self(), :hello_timeout, @hello_timeout)

    {:ok,
     %{
       config: config,
       socket: socket,
       buffer: <<>>,
       phase: :hello,
       channel: nil,
       receive_buffer: @receive_buffer,
       sessions: %{},
       request_id: nil,
       outbox: []
     }}
  end

  @impl true
  # The acceptor hands the socket over, then says go.
  def handle_info(:go, state) do
    :ok = :inet.setopts(state.socket, active: :once)
    {:noreply, state}
  end

  def handle_info({:tcp, socket, data}, state) do
    case Transport.split(state.buffer <> data, state.receive_buffer) do
      {:ok, chunks, rest} ->
        case Enum.reduce_while(chunks, {:ok, %{state | buffer: rest}}, &chunk/2) do
          {:ok, state} ->
            :ok = :inet.setopts(socket, active: :once)
            {:noreply, state}

          {:close, state} ->
            {:stop, :normal, state}
        end

      {:error, status} ->
        {:stop, :normal, fail(state, status)}
    end
  end

  def handle_info({:tcp_closed, _}, state), do: {:stop, :normal, state}
  def handle_info({:tcp_error, _, _}, state), do: {:stop, :normal, state}
  def handle_info(:hello_timeout, %{phase: :hello} = state), do: {:stop, :normal, state}
  def handle_info(:hello_timeout, state), do: {:noreply, state}

  # A channel whose token wasn't renewed in time is closed.
  def handle_info({:token_expired, token_id}, state) do
    if state.channel.token_id == token_id,
      do: {:stop, :normal, fail(state, :bad_secure_channel_token_unknown)},
      else: {:noreply, state}
  end

  def handle_info({:publish_cycle, auth, sub}, state),
    do: {:noreply, state |> in_session(auth, &Subscriptions.publish_cycle(&1, sub)) |> flush()}

  def handle_info({:sample, auth, sub}, state),
    do: {:noreply, in_session(state, auth, &Subscriptions.sample(&1, sub, state.config.space))}

  def handle_info({:publish_timeout, auth, id}, state),
    do: {:noreply, state |> in_session(auth, &Subscriptions.publish_timeout(&1, id)) |> flush()}

  # An event from the server, for the event items of every session.
  def handle_info({:event, event}, state) do
    sessions =
      Map.new(state.sessions, fn {auth, session} ->
        {auth, Subscriptions.event(session, event, state.config.space)}
      end)

    {:noreply, %{state | sessions: sessions}}
  end

  def handle_info({:session_timeout, auth, since}, state) do
    case state.sessions do
      %{^auth => %{last: ^since}} ->
        {:noreply, %{state | sessions: Map.delete(state.sessions, auth)}}

      _ ->
        {:noreply, state}
    end
  end

  defp chunk({:hello, :final, body}, {:ok, %{phase: :hello} = state}) do
    case Transport.decode(:hello, body) do
      {:ok, {hello, _url}} ->
        ack = %{
          protocol_version: 0,
          receive_buffer_size: min(@receive_buffer, hello.send_buffer_size),
          send_buffer_size: min(@receive_buffer, hello.receive_buffer_size),
          max_message_size: @max_message,
          max_chunk_count: 0
        }

        # What we may send is bounded by what the client can take.
        limits = %{
          ack
          | receive_buffer_size: ack.send_buffer_size,
            max_message_size: hello.max_message_size,
            max_chunk_count: hello.max_chunk_count
        }

        channel =
          SecureChannel.new(limits,
            receive_max_message: @max_message,
            # None is always allowed for the channel, so clients can ask for
            # the endpoints; sessions check the endpoint they're made on.
            policies: Enum.uniq([:none | Enum.map(state.config.security, &elem(&1, 0))]),
            certificate: state.config.certificate,
            private_key: state.config.private_key
          )

        :ok =
          :gen_tcp.send(
            state.socket,
            Transport.frame(:acknowledge, :final, Transport.acknowledge(ack))
          )

        {:cont,
         {:ok, %{state | phase: :open, channel: channel, receive_buffer: ack.receive_buffer_size}}}

      {:error, status} ->
        {:halt, {:close, fail(state, status)}}
    end
  end

  defp chunk(_, {:ok, %{phase: :hello} = state}),
    do: {:halt, {:close, fail(state, :bad_tcp_message_type_invalid)}}

  defp chunk(chunk, {:ok, state}) do
    case SecureChannel.receive(state.channel, chunk) do
      {:ok, channel} ->
        {:cont, {:ok, %{state | channel: channel}}}

      {:ok, {:open, id, %Types.OpenSecureChannelRequest{} = request}, channel} ->
        open(%{state | channel: channel}, id, request)

      {:ok, {:close, _, _}, channel} ->
        {:halt, {:close, %{state | channel: channel}}}

      # A message that decodes as some other structure has no header to
      # answer to; the connection is closed.
      {:ok, {:message, _, message}, _} when not is_map_key(message, :request_header) ->
        {:halt, {:close, fail(state, :bad_service_unsupported)}}

      {:ok, {:message, id, request}, channel} when state.phase == :running ->
        {:cont, {:ok, respond(%{state | channel: channel}, id, request)}}

      {:ok, _, _} ->
        {:halt, {:close, fail(state, :bad_tcp_message_type_invalid)}}

      # the client gave up on a request it was still sending
      {:abort, _, _, _, channel} ->
        {:cont, {:ok, %{state | channel: channel}}}

      {:error, status} ->
        {:halt, {:close, fail(state, status)}}
    end
  end

  defp open(state, id, request) do
    renew = request.request_type == :renew
    policy = state.channel.policy
    offered = policy == :none or {policy, request.security_mode} in state.config.security

    cond do
      renew != (state.phase == :running) ->
        {:halt, {:close, fail(state, :bad_request_type_invalid)}}

      not offered or (policy == :none and request.security_mode != :none) ->
        {:halt, {:close, fail(state, :bad_security_mode_rejected)}}

      renew and request.security_mode != state.channel.mode ->
        {:halt, {:close, fail(state, :bad_security_mode_rejected)}}

      policy != :none and
          not OPCUA.Certificate.trusted?(state.channel.remote_certificate, state.config.trust) ->
        {:halt, {:close, fail(state, :bad_certificate_untrusted)}}

      byte_size(request.client_nonce || "") != OPCUA.SecurityPolicy.nonce_length(policy) ->
        {:halt, {:close, fail(state, :bad_nonce_invalid)}}

      true ->
        channel_id =
          if renew, do: state.channel.channel_id, else: :atomics.add_get(state.config.ids, 1, 1)

        lifetime = request.requested_lifetime |> max(1000) |> min(3_600_000)

        token = %Types.ChannelSecurityToken{
          channel_id: channel_id,
          token_id: :atomics.add_get(state.config.ids, 2, 1),
          created_at: DateTime.utc_now(),
          revised_lifetime: lifetime
        }

        nonce = :crypto.strong_rand_bytes(OPCUA.SecurityPolicy.nonce_length(policy))

        response = %Types.OpenSecureChannelResponse{
          response_header: Services.header(request, 0),
          server_protocol_version: 0,
          security_token: token,
          server_nonce: nonce
        }

        # The new token is used for sending at once. The spec has the server
        # wait until the client first uses it; clients accept either, as the
        # response that brings the token arrives before anything sent with it.
        channel = %{
          SecureChannel.token(state.channel, token, nonce, request.client_nonce)
          | mode: request.security_mode
        }

        # The client should renew at 75% of the lifetime; give it until 125%.
        Process.send_after(self(), {:token_expired, token.token_id}, trunc(lifetime * 1.25))

        {:cont,
         {:ok, send_response(%{state | channel: channel, phase: :running}, :open, id, response)}}
    end
  end

  defp respond(state, id, request) do
    {response, state} =
      try do
        Services.handle(request, %{state | request_id: id})
      rescue
        exception ->
          Logger.error(
            "OPC UA request failed: " <> Exception.format(:error, exception, __STACKTRACE__)
          )

          {Services.fault(request, :bad_internal_error), state}
      end

    # A Publish request is answered later, by a publishing cycle.
    state = if response == :noreply, do: state, else: send_response(state, :message, id, response)
    flush(state)
  end

  defp in_session(state, auth, fun) do
    case state.sessions do
      %{^auth => session} -> %{state | sessions: Map.put(state.sessions, auth, fun.(session))}
      _ -> state
    end
  end

  # Sends the responses that waited, such as Publish requests answered by a timer.
  defp flush(state) do
    waiting =
      for {_, session} <- state.sessions, response <- Enum.reverse(session.outbox), do: response

    sessions = Map.new(state.sessions, fn {auth, session} -> {auth, %{session | outbox: []}} end)

    Enum.reduce(state.outbox ++ waiting, %{state | outbox: [], sessions: sessions}, fn {id,
                                                                                        response},
                                                                                       state ->
      send_response(state, :message, id, response)
    end)
  end

  defp send_response(state, kind, id, response) do
    case safe_encode(state.channel, kind, id, response) do
      {:ok, frames, channel} ->
        :gen_tcp.send(state.socket, frames)
        %{state | channel: channel}

      {:error, status} ->
        # Too big for the client, or a value that doesn't fit its type.
        fault =
          Services.fault(
            %{request_header: %{request_handle: response.response_header.request_handle}},
            status
          )

        {:ok, frames, channel} = SecureChannel.encode(state.channel, kind, id, fault)
        :gen_tcp.send(state.socket, frames)
        %{state | channel: channel}
    end
  end

  defp safe_encode(channel, kind, id, response) do
    case SecureChannel.encode(channel, kind, id, response) do
      {:error, :bad_encoding_limits_exceeded} -> {:error, :bad_response_too_large}
      {:error, :bad_request_too_large} -> {:error, :bad_response_too_large}
      other -> other
    end
  rescue
    exception in ArgumentError ->
      Logger.error("OPC UA response could not be encoded: " <> Exception.message(exception))
      {:error, :bad_encoding_error}
  end

  # Tells the client why the connection is closing.
  defp fail(state, status) do
    code = StatusCode.code(status)

    :gen_tcp.send(
      state.socket,
      Transport.frame(:error, :final, Transport.error(code, to_string(status)))
    )

    state
  end
end
