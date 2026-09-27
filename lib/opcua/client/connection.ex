defmodule OPCUA.Client.Connection do
  @moduledoc false
  # Setting up a client connection: Hello, OpenSecureChannel, CreateSession
  # and ActivateSession, one reply at a time with blocking receives, before
  # the client switches the socket to active mode. Also the request header
  # and reply helpers the running client shares.

  alias OPCUA.{SecureChannel, StatusCode, Transport}
  alias OPCUA.Types

  @receive_buffer 65_535
  @max_message 16_777_216

  @limits %{
    protocol_version: 0,
    receive_buffer_size: @receive_buffer,
    send_buffer_size: @receive_buffer,
    max_message_size: @max_message,
    max_chunk_count: 0
  }

  def receive_buffer, do: @receive_buffer

  @doc false
  # Connects, says Hello and opens a secure channel.
  def connect(url, timeout, lifetime) do
    with {:ok, {host, port}} <- Transport.endpoint(url),
         {:ok, socket} <-
           :gen_tcp.connect(host, port, [:binary, active: false, nodelay: true], timeout),
         state = new(socket, url, timeout, lifetime),
         :ok <-
           :gen_tcp.send(socket, Transport.frame(:hello, :final, Transport.hello(@limits, url))),
         {:ok, limits, state} <- acknowledge(state),
         state = %{state | channel: SecureChannel.new(limits, receive_max_message: @max_message)} do
      open(state)
    end
  end

  defp new(socket, url, timeout, lifetime) do
    %{
      socket: socket,
      url: url,
      timeout: timeout,
      lifetime: lifetime,
      buffer: <<>>,
      chunks: [],
      channel: nil,
      token: nil,
      auth: nil,
      session_timeout: nil,
      handle: 0,
      pending: %{},
      types: %{},
      subscriptions: %{},
      items: %{},
      next_handle: 0,
      publishing: 0,
      publish_target: 2,
      acks: []
    }
  end

  defp acknowledge(state) do
    case receive_chunk(state) do
      {:ok, {:acknowledge, :final, body}, state} ->
        with {:ok, limits} <- Transport.decode(:acknowledge, body), do: {:ok, limits, state}

      {:ok, {:error, _, body}, _} ->
        remote_error(body)

      {:ok, _, _} ->
        {:error, :bad_tcp_message_type_invalid}

      error ->
        error
    end
  end

  defp open(state) do
    {id, channel} = SecureChannel.next_request_id(state.channel)

    with {:ok, frames, channel} <-
           SecureChannel.encode(channel, :open, id, open_request(state, :issue)),
         :ok <- :gen_tcp.send(state.socket, frames),
         {:ok, %Types.OpenSecureChannelResponse{security_token: token}, state} <-
           await(%{state | channel: channel}, id) do
      {:ok, %{state | channel: SecureChannel.token(state.channel, token), token: token}}
    end
  end

  @doc false
  def open_request(state, type) do
    %Types.OpenSecureChannelRequest{
      request_header: header(state, 0),
      client_protocol_version: 0,
      request_type: type,
      security_mode: :none,
      client_nonce: "",
      requested_lifetime: state.lifetime
    }
  end

  @doc false
  # Creates and activates the session.
  def session(state, opts) do
    create = %Types.CreateSessionRequest{
      client_description: %Types.ApplicationDescription{
        application_uri: Keyword.get(opts, :application_uri, "urn:yaopcua:client"),
        product_uri: "urn:yaopcua",
        application_name: %OPCUA.LocalizedText{text: "yaopcua"},
        application_type: :client
      },
      endpoint_url: state.url,
      session_name: Keyword.get(opts, :session_name, "yaopcua"),
      client_nonce: :crypto.strong_rand_bytes(32),
      requested_session_timeout: Keyword.get(opts, :session_timeout, 60_000) * 1.0,
      max_response_message_size: @max_message
    }

    with {:ok, created, state} <- exchange(state, create),
         state = %{
           state
           | auth: created.authentication_token,
             session_timeout: created.revised_session_timeout
         },
         {:ok, token} <- identity(created.server_endpoints, Keyword.get(opts, :user, :anonymous)),
         activate = %Types.ActivateSessionRequest{user_identity_token: token, locale_ids: ["en"]},
         {:ok, _, state} <- exchange(state, activate) do
      {:ok, state}
    end
  end

  defp identity(endpoints, user) do
    none = SecureChannel.none()

    policies =
      for %{security_policy_uri: ^none, user_identity_tokens: tokens} <- endpoints || [],
          token <- tokens || [],
          do: token

    case user do
      :anonymous ->
        policy = Enum.find(policies, &(&1.token_type == :anonymous))
        id = if policy, do: policy.policy_id, else: "anonymous"
        {:ok, %Types.AnonymousIdentityToken{policy_id: id}}

      {name, password} ->
        case Enum.find(policies, &(&1.token_type == :user_name)) do
          nil ->
            {:error, :bad_identity_token_rejected}

          %{security_policy_uri: uri} = policy when uri in [nil, "", none] ->
            {:ok,
             %Types.UserNameIdentityToken{
               policy_id: policy.policy_id,
               user_name: name,
               password: password
             }}

          _ ->
            # The server wants the password encrypted; that comes with security.
            {:error, :bad_security_policy_rejected}
        end
    end
  end

  @doc false
  # Sends a request and waits for its response.
  def exchange(state, request) do
    {id, channel} = SecureChannel.next_request_id(state.channel)
    {request, state} = with_header(%{state | channel: channel}, request, state.timeout)

    with {:ok, frames, channel} <- SecureChannel.encode(state.channel, :message, id, request),
         :ok <- :gen_tcp.send(state.socket, frames),
         {:ok, response, state} <- await(%{state | channel: channel}, id) do
      with {:ok, response} <- result(response), do: {:ok, response, state}
    end
  end

  defp await(state, id) do
    with {:ok, chunk, state} <- receive_chunk(state) do
      case chunk do
        {:error, _, body} ->
          remote_error(body)

        {kind, _, _} = chunk when kind in [:open, :message] ->
          case SecureChannel.receive(state.channel, chunk) do
            {:ok, channel} -> await(%{state | channel: channel}, id)
            {:ok, {_, ^id, response}, channel} -> {:ok, response, %{state | channel: channel}}
            {:ok, _other, channel} -> await(%{state | channel: channel}, id)
            {:abort, ^id, status, _, _} -> {:error, status_name(status)}
            {:abort, _, _, _, channel} -> await(%{state | channel: channel}, id)
            {:error, _} = error -> error
          end

        _ ->
          {:error, :bad_tcp_message_type_invalid}
      end
    end
  end

  defp receive_chunk(%{chunks: [chunk | more]} = state), do: {:ok, chunk, %{state | chunks: more}}

  defp receive_chunk(state) do
    case Transport.split(state.buffer, @receive_buffer) do
      {:ok, [], rest} ->
        case :gen_tcp.recv(state.socket, 0, state.timeout) do
          {:ok, data} -> receive_chunk(%{state | buffer: rest <> data})
          {:error, :timeout} -> {:error, :bad_timeout}
          {:error, _} -> {:error, :bad_connection_closed}
        end

      {:ok, chunks, rest} ->
        receive_chunk(%{state | chunks: chunks, buffer: rest})

      error ->
        error
    end
  end

  @doc false
  def remote_error(body) do
    case Transport.decode(:error, body) do
      {:ok, {status, _reason}} -> {:error, status_name(status)}
      error -> error
    end
  end

  @doc false
  # Closes the secure channel and the socket.
  def disconnect(state) do
    {id, channel} = SecureChannel.next_request_id(state.channel)
    close = %Types.CloseSecureChannelRequest{request_header: header(state, 0)}

    with {:ok, frames, _} <- SecureChannel.encode(channel, :close, id, close) do
      :gen_tcp.send(state.socket, frames)
    end

    :gen_tcp.close(state.socket)
  end

  @doc false
  def header(state, handle) do
    %Types.RequestHeader{
      authentication_token: state.auth,
      timestamp: DateTime.utc_now(),
      request_handle: handle,
      timeout_hint: state.timeout
    }
  end

  @doc false
  def with_header(state, request, timeout) do
    handle = if state.handle >= 0xFFFF_FFFF, do: 1, else: state.handle + 1
    header = %{header(state, handle) | timeout_hint: trunc(timeout)}
    {%{request | request_header: header}, %{state | handle: handle}}
  end

  @doc false
  # A Bad service result or a ServiceFault is an error.
  def result(%Types.ServiceFault{response_header: %{service_result: status}}),
    do: {:error, status_name(status)}

  def result(%{response_header: %{service_result: status}} = response) do
    if StatusCode.bad?(status), do: {:error, status_name(status)}, else: {:ok, response}
  end

  @doc false
  def status_name(status), do: StatusCode.name(status) || status
end
