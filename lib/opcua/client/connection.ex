defmodule OPCUA.Client.Connection do
  @moduledoc false
  # Setting up a client connection: Hello, OpenSecureChannel, CreateSession
  # and ActivateSession, one reply at a time with blocking receives, before
  # the client switches the socket to active mode. Also the request header
  # and reply helpers the running client shares.

  alias OPCUA.{Certificate, SecureChannel, SecurityPolicy, StatusCode, Transport}
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
  # Connects, says Hello and opens a secure channel. `security` has the
  # policy and mode, and for a secure one our certificate and key and the
  # server's certificate.
  def connect(url, timeout, lifetime, security \\ %{policy: :none, mode: :none}) do
    with {:ok, {host, port}} <- Transport.endpoint(url),
         {:ok, socket} <-
           :gen_tcp.connect(host, port, [:binary, active: false, nodelay: true], timeout),
         state = new(socket, url, timeout, lifetime, security),
         :ok <-
           :gen_tcp.send(socket, Transport.frame(:hello, :final, Transport.hello(@limits, url))),
         {:ok, limits, state} <- acknowledge(state) do
      channel =
        SecureChannel.new(limits,
          receive_max_message: @max_message,
          policy: security.policy,
          mode: security.mode,
          certificate: security[:certificate],
          private_key: security[:private_key],
          remote_certificate: security[:server_certificate]
        )

      open(%{state | channel: channel})
    end
  end

  defp new(socket, url, timeout, lifetime, security) do
    %{
      socket: socket,
      url: url,
      timeout: timeout,
      lifetime: lifetime,
      security: security,
      nonce: nil,
      server_nonce: nil,
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
    {request, state} = open_request(state, :issue)

    with {:ok, frames, channel} <- SecureChannel.encode(channel, :open, id, request),
         :ok <- :gen_tcp.send(state.socket, frames),
         {:ok, %Types.OpenSecureChannelResponse{} = response, state} <-
           await(%{state | channel: channel}, id) do
      {:ok, opened(state, response)}
    end
  end

  @doc false
  # An OpenSecureChannel request, with a new nonce to derive keys from.
  def open_request(state, type) do
    nonce = :crypto.strong_rand_bytes(SecurityPolicy.nonce_length(state.security.policy))

    request = %Types.OpenSecureChannelRequest{
      request_header: header(state, 0),
      client_protocol_version: 0,
      request_type: type,
      security_mode: state.security.mode,
      client_nonce: nonce,
      requested_lifetime: state.lifetime
    }

    {request, %{state | nonce: nonce}}
  end

  @doc false
  # The channel's new token, with keys from our nonce and the server's.
  def opened(state, %Types.OpenSecureChannelResponse{
        security_token: token,
        server_nonce: server_nonce
      }) do
    %{
      state
      | channel: SecureChannel.token(state.channel, token, state.nonce, server_nonce),
        token: token
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
      client_nonce: nonce = :crypto.strong_rand_bytes(32),
      client_certificate: state.security[:certificate],
      requested_session_timeout: Keyword.get(opts, :session_timeout, 60_000) * 1.0,
      max_response_message_size: @max_message
    }

    with {:ok, created, state} <- exchange(state, create),
         :ok <- server_signature(state, created, nonce),
         state = %{
           state
           | auth: created.authentication_token,
             session_timeout: created.revised_session_timeout,
             server_nonce: created.server_nonce
         },
         {:ok, token, token_signature} <-
           identity(state, created, Keyword.get(opts, :user, :anonymous)),
         activate = %Types.ActivateSessionRequest{
           client_signature: client_signature(state, created),
           user_identity_token: token,
           user_token_signature: token_signature,
           locale_ids: ["en"]
         },
         {:ok, activated, state} <- exchange(state, activate) do
      {:ok, %{state | server_nonce: activated.server_nonce}}
    end
  end

  # The server proves it holds its certificate's key by signing ours and our nonce.
  defp server_signature(%{security: %{policy: :none}}, _, _), do: :ok

  defp server_signature(%{security: security}, created, nonce) do
    signature = created.server_signature && created.server_signature.signature
    data = security.certificate <> nonce
    key = Certificate.public_key(security.server_certificate)

    if is_binary(signature) and SecurityPolicy.verify(security.policy, data, signature, key),
      do: :ok,
      else: {:error, :bad_application_signature_invalid}
  end

  # And we sign the server's certificate and nonce.
  defp client_signature(%{security: %{policy: :none}}, _), do: nil

  defp client_signature(%{security: security}, created) do
    %Types.SignatureData{
      algorithm: SecurityPolicy.signature_uri(security.policy),
      signature:
        SecurityPolicy.sign(
          security.policy,
          security.server_certificate <> created.server_nonce,
          security.private_key
        )
    }
  end

  # The user token, and its signature for a certificate login.
  defp identity(state, created, user) do
    policy_uri = SecurityPolicy.uri(state.security.policy)

    endpoint =
      Enum.find(
        created.server_endpoints || [],
        &(&1.security_policy_uri == policy_uri and &1.security_mode == state.security.mode)
      )

    tokens = (endpoint && endpoint.user_identity_tokens) || []
    server_certificate = created.server_certificate || (endpoint && endpoint.server_certificate)

    # A token policy without a security policy of its own uses the channel's.
    token_policy = fn token ->
      case token.security_policy_uri do
        uri when uri in [nil, ""] -> state.security.policy
        uri -> SecurityPolicy.from_uri(uri)
      end
    end

    case {user, Enum.find(tokens, &(&1.token_type == token_type(user)))} do
      {:anonymous, policy} ->
        {:ok,
         %Types.AnonymousIdentityToken{
           policy_id: if(policy, do: policy.policy_id, else: "anonymous")
         }, nil}

      {_, nil} ->
        {:error, :bad_identity_token_rejected}

      {{name, password}, policy} ->
        case token_policy.(policy) do
          nil ->
            {:error, :bad_security_policy_rejected}

          :none ->
            {:ok,
             %Types.UserNameIdentityToken{
               policy_id: policy.policy_id,
               user_name: name,
               password: password
             }, nil}

          secure ->
            key = Certificate.public_key(server_certificate)
            password = SecurityPolicy.encrypt_secret(secure, password, state.server_nonce, key)
            algorithm = SecurityPolicy.encryption_uri(secure)

            {:ok,
             %Types.UserNameIdentityToken{
               policy_id: policy.policy_id,
               user_name: name,
               password: password,
               encryption_algorithm: algorithm
             }, nil}
        end

      {{:certificate, certificate, private_key}, policy} ->
        secure = with(:none <- token_policy.(policy), do: :basic256sha256)
        data = server_certificate <> state.server_nonce

        signature = %Types.SignatureData{
          algorithm: SecurityPolicy.signature_uri(secure),
          signature: SecurityPolicy.sign(secure, data, private_key)
        }

        {:ok,
         %Types.X509IdentityToken{policy_id: policy.policy_id, certificate_data: certificate},
         signature}
    end
  end

  defp token_type(:anonymous), do: :anonymous
  defp token_type({:certificate, _, _}), do: :certificate
  defp token_type({_, _}), do: :user_name

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
