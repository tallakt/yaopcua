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

  # The state of a client: what connect/4 and session/2 set up, then what
  # the running OPCUA.Client adds.
  defstruct [
    :socket,
    :url,
    # ms a request may take
    :timeout,
    # ms a channel token is asked to last
    :lifetime,
    # The policy and mode, and for a secure policy the certificates and key.
    :security,
    # Our nonce for the channel keys, and the server's for signing the session.
    :nonce,
    :server_nonce,
    :channel,
    # The channel's ChannelSecurityToken.
    :token,
    # The session's authentication token.
    :auth,
    :session_timeout,
    # Received and not yet split into chunks, and chunks not yet handled.
    buffer: <<>>,
    chunks: [],
    # The last request handle.
    handle: 0,
    # By request id: {tag, timer}, the tag saying what to do with the response.
    pending: %{},
    # The types of nodes written with plain values.
    types: %{},
    # By subscription id.
    subscriptions: %{},
    # {subscription, {:value, node} | {:events, fields}} by client handle.
    items: %{},
    next_handle: 0,
    # Publish requests at the server, and how many to keep there.
    publishing: 0,
    publish_target: 2,
    # Notifications to acknowledge with the next Publish request.
    acks: []
  ]

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
    %__MODULE__{
      socket: socket,
      url: url,
      timeout: timeout,
      lifetime: lifetime,
      security: security
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
         {:ok, response, state} <- await(%{state | channel: channel}, id),
         {:ok, response} <- result(response, Types.OpenSecureChannelResponse) do
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
         :ok <- session_certificate(state.security, created.server_certificate),
         :ok <- server_signature(state, created, nonce),
         state = %{
           state
           | auth: created.authentication_token,
             session_timeout: ms(created.revised_session_timeout, 1000, 86_400_000),
             server_nonce: created.server_nonce || ""
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

  @doc false
  # The certificate a server answers CreateSession with must be the one the
  # secure channel was opened to; either may be followed by its chain.
  def session_certificate(%{policy: :none}, _), do: :ok
  def session_certificate(_security, empty) when empty in [nil, ""], do: :ok

  def session_certificate(security, certificate) do
    if leaf(certificate) == leaf(security.server_certificate),
      do: :ok,
      else: {:error, :bad_certificate_invalid}
  end

  # The first certificate of a chain, certificates one after another in DER
  # (Part 6, 6.2.3).
  defp leaf(<<0x30, 0x82, length::16, _::binary>> = der) when byte_size(der) >= length + 4,
    do: binary_part(der, 0, length + 4)

  defp leaf(<<0x30, 0x83, length::24, _::binary>> = der) when byte_size(der) >= length + 5,
    do: binary_part(der, 0, length + 5)

  defp leaf(der), do: der

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

  # The user token, and its signature for a certificate login. Of the server's
  # token policies for the kind of login, the first whose security policy the
  # client has: servers often list Basic256 before Basic256Sha256.
  defp identity(state, created, user) do
    {tokens, server_certificate} = endpoint(state, created)
    tokens = Enum.filter(tokens, &(&1.token_type == token_type(user)))

    case {user, Enum.find(tokens, &token_policy(state, &1)) || List.first(tokens)} do
      {:anonymous, policy} ->
        {:ok,
         %Types.AnonymousIdentityToken{
           policy_id: if(policy, do: policy.policy_id, else: "anonymous")
         }, nil}

      {_, nil} ->
        {:error, :bad_identity_token_rejected}

      {user, policy} ->
        token(user, policy, token_policy(state, policy), server_certificate, state.server_nonce)
    end
  end

  # The user token policies of the endpoint the channel was opened to, and the server's
  # certificate: the one the channel was opened to, or over None the one the session or
  # the endpoint gives.
  defp endpoint(state, created) do
    policy_uri = SecurityPolicy.uri(state.security.policy)

    endpoint =
      Enum.find(
        created.server_endpoints || [],
        &(&1.security_policy_uri == policy_uri and &1.security_mode == state.security.mode)
      ) || %{user_identity_tokens: nil, server_certificate: nil}

    server_certificate =
      state.security[:server_certificate] || created.server_certificate ||
        endpoint.server_certificate

    {endpoint.user_identity_tokens || [], server_certificate}
  end

  defp token(_user, _policy, nil, _server_certificate, _nonce),
    do: {:error, :bad_security_policy_rejected}

  # A secret to encrypt, or a signature to make, for a server that hasn't said what its
  # certificate is.
  defp token(user, _policy, security, server_certificate, _nonce)
       when (security != :none or elem(user, 0) == :certificate) and
              not is_binary(server_certificate),
       do: {:error, :bad_certificate_invalid}

  defp token(user, policy, security, server_certificate, nonce),
    do: user_token(user, policy, security, server_certificate, nonce)

  # A token policy without a security policy of its own uses the channel's.
  defp token_policy(state, policy) do
    case policy.security_policy_uri do
      uri when uri in [nil, ""] -> state.security.policy
      uri -> SecurityPolicy.from_uri(uri)
    end
  end

  defp user_token({name, password}, policy, :none, _, _) do
    {:ok,
     %Types.UserNameIdentityToken{
       policy_id: policy.policy_id,
       user_name: name,
       password: password
     }, nil}
  end

  defp user_token({name, password}, policy, security, server_certificate, nonce) do
    key = Certificate.public_key(server_certificate)

    {:ok,
     %Types.UserNameIdentityToken{
       policy_id: policy.policy_id,
       user_name: name,
       password: SecurityPolicy.encrypt_secret(security, password, nonce, key),
       encryption_algorithm: SecurityPolicy.encryption_uri(security)
     }, nil}
  end

  # The user proves they hold the certificate's key by signing the server's
  # certificate and nonce, with Basic256Sha256's algorithm when the token
  # policy has none.
  defp user_token({:certificate, certificate, key}, policy, security, server_certificate, nonce) do
    security = if security == :none, do: :basic256sha256, else: security

    signature = %Types.SignatureData{
      algorithm: SecurityPolicy.signature_uri(security),
      signature: SecurityPolicy.sign(security, server_certificate <> nonce, key)
    }

    {:ok, %Types.X509IdentityToken{policy_id: policy.policy_id, certificate_data: certificate},
     signature}
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
         {:ok, response, state} <- await(%{state | channel: channel}, id),
         {:ok, response} <- result(response, response_type(request)) do
      {:ok, response, state}
    end
  end

  defp await(state, id) do
    with {:ok, chunk, state} <- receive_chunk(state) do
      case chunk do
        {:error, _, body} -> remote_error(body)
        {kind, _, _} when kind in [:open, :message] -> received(state, id, chunk)
        _ -> {:error, :bad_tcp_message_type_invalid}
      end
    end
  end

  defp received(state, id, chunk) do
    case SecureChannel.receive(state.channel, chunk) do
      {:ok, channel} -> await(%{state | channel: channel}, id)
      {:ok, {_, ^id, response}, channel} -> {:ok, response, %{state | channel: channel}}
      {:ok, _other, channel} -> await(%{state | channel: channel}, id)
      {:abort, ^id, status, _, _} -> {:error, status_name(status)}
      {:abort, _, _, _, channel} -> await(%{state | channel: channel}, id)
      {:error, _} = error -> error
    end
  end

  defp receive_chunk(%{chunks: [chunk | more]} = state), do: {:ok, chunk, %{state | chunks: more}}

  defp receive_chunk(state) do
    case Transport.split(state.buffer, @receive_buffer) do
      {:ok, [], rest} -> receive_more(state, rest)
      {:ok, chunks, rest} -> receive_chunk(%{state | chunks: chunks, buffer: rest})
      error -> error
    end
  end

  defp receive_more(state, buffer) do
    case :gen_tcp.recv(state.socket, 0, state.timeout) do
      {:ok, data} -> receive_chunk(%{state | buffer: buffer <> data})
      {:error, :timeout} -> {:error, :bad_timeout}
      {:error, _} -> {:error, :bad_connection_closed}
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

    _ =
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
  # The response a request gets: a ReadResponse for a ReadRequest.
  def response_type(%module{}) do
    name = module |> Module.split() |> List.last() |> String.replace_suffix("Request", "Response")
    Module.concat(Types, name)
  end

  @doc false
  # A Bad service result or a ServiceFault is an error, and so is a response
  # of another type than `expected`: a server can't answer a Read with a
  # WriteResponse, say, and have the client take it.
  def result(%Types.ServiceFault{response_header: %{service_result: status}}, _),
    do: {:error, status_name(status)}

  def result(%expected{response_header: %{service_result: status}} = response, expected) do
    if StatusCode.bad?(status), do: {:error, status_name(status)}, else: {:ok, response}
  end

  def result(_, _), do: {:error, :bad_unknown_response}

  @doc false
  # A duration in ms from the server, within bounds: so that zero can't keep
  # the client busy, nor NaN or 1e300 break a timer.
  def ms(value, low, high) when is_number(value), do: value |> max(low) |> min(high) |> trunc()
  def ms(_, low, _), do: low

  @doc false
  def status_name(status), do: StatusCode.name(status) || status
end
