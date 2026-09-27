defmodule OPCUA.Client do
  @moduledoc """
  An OPC UA client: one TCP connection, one secure channel, one session.

      {:ok, client} = OPCUA.Client.start_link(url: "opc.tcp://10.0.0.5:4840")

      {:ok, 1500} = OPCUA.Client.read(client, "ns=2;s=Pump1.Speed")
      :ok = OPCUA.Client.write(client, "ns=2;s=Pump1.Speed", 1600)
      {:ok, refs} = OPCUA.Client.browse(client, "ns=2;s=Plant")
      {:ok, [42]} = OPCUA.Client.call(client, "ns=2;s=Plant", "ns=2;s=Multiply", [6, 7])

  Node ids are `OPCUA.NodeId` structs or their text form. Errors are the
  status code's name, such as `{:error, :bad_node_id_unknown}`.

  `start_link/1` returns once the session is active, or with the reason it
  couldn't get there. When the connection drops the client stops with
  `{:shutdown, reason}`, so run it under a supervisor to reconnect.

  Only the None security policy is supported so far, with anonymous or
  username login.

  ## Options

    * `:url` - the endpoint, `opc.tcp://host:port/path` (required)
    * `:user` - `{username, password}`, or `:anonymous` (the default)
    * `:timeout` - how long a request may take, in ms (default 5000)
    * `:session_timeout` - how long the server keeps an idle session, in ms
      (default 60000); the client keeps it alive
    * `:channel_lifetime` - how long a secure channel token lasts before the
      client renews it, in ms (default one hour)
    * `:session_name`, `:application_uri` - how the client presents itself
    * `:name` - to register the process
  """

  use GenServer

  require Logger

  alias OPCUA.{DataValue, NodeId, SecureChannel, StatusCode, Transport, Variant}
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

  # ServerStatus.State, read to keep the session alive
  @keep_alive 2259
  @session_lost [:bad_session_id_invalid, :bad_session_closed, :bad_session_not_activated]

  @type client :: GenServer.server()
  @type node_ref :: NodeId.t() | String.t()
  @type error :: {:error, atom | non_neg_integer}

  @doc "Connects and activates a session. See the module doc for the options."
  @spec start_link(keyword) :: GenServer.on_start()
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, Keyword.take(opts, [:name]))

  @doc "Like `start_link/1`, without linking to the caller."
  @spec start(keyword) :: GenServer.on_start()
  def start(opts), do: GenServer.start(__MODULE__, opts, Keyword.take(opts, [:name]))

  @doc "Closes the session and the connection."
  @spec close(client) :: :ok
  def close(client), do: GenServer.stop(client)

  @doc """
  Reads one attribute of one node; the value by default. Returns the plain
  value: a number, a string, a list for an array, a struct for a structure.

  A Good or Uncertain result is `{:ok, value}`; use `read_many/3` to see the
  status and timestamps.
  """
  @spec read(client, node_ref, atom) :: {:ok, term} | error
  def read(client, node, attribute \\ :value) do
    with {:ok, [result]} <- read_many(client, [node], attribute) do
      value(result)
    end
  end

  @doc "Reads the same attribute of several nodes, returning a `OPCUA.DataValue` for each."
  @spec read_many(client, [node_ref], atom) :: {:ok, [DataValue.t()]} | error
  def read_many(client, nodes, attribute \\ :value) do
    id = OPCUA.AttributeId.id(attribute)
    reads = for node <- nodes, do: %Types.ReadValueId{node_id: node_id(node), attribute_id: id}
    request = %Types.ReadRequest{timestamps_to_return: :both, nodes_to_read: reads}

    with {:ok, %{results: results}} <- request(client, request) do
      {:ok, results}
    end
  end

  defp value(%DataValue{status: status, value: value}) do
    if StatusCode.bad?(status), do: {:error, status_name(status)}, else: {:ok, unwrap(value)}
  end

  defp unwrap(nil), do: nil
  defp unwrap(%Variant{value: value}), do: value

  @doc """
  Writes the value of a node.

  `value` is either an `OPCUA.Variant`, sent as is, or a plain value. For a
  plain value the client reads the node once to learn its type, and remembers
  it for later writes.
  """
  @spec write(client, node_ref, term) :: :ok | error
  def write(client, node, value) do
    with {:ok, [status]} <- write_many(client, [{node, value}]) do
      if StatusCode.bad?(status), do: {:error, status_name(status)}, else: :ok
    end
  end

  @doc "Writes several values, returning the status code of each write."
  @spec write_many(client, [{node_ref, term}]) :: {:ok, [StatusCode.t()]} | error
  def write_many(client, writes) do
    with {:ok, variants} <- variants(client, writes) do
      value = OPCUA.AttributeId.id(:value)

      items =
        for {{node, _}, variant} <- Enum.zip(writes, variants),
            do: %Types.WriteValue{
              node_id: node_id(node),
              attribute_id: value,
              value: %DataValue{value: variant}
            }

      with {:ok, %{results: results}} <-
             request(client, %Types.WriteRequest{nodes_to_write: items}) do
        {:ok, results}
      end
    end
  end

  defp variants(client, writes) do
    Enum.reduce_while(writes, {:ok, []}, fn {node, value}, {:ok, acc} ->
      case variant(client, node_id(node), value) do
        {:ok, variant} -> {:cont, {:ok, [variant | acc]}}
        error -> {:halt, error}
      end
    end)
    |> then(fn
      {:ok, acc} -> {:ok, Enum.reverse(acc)}
      error -> error
    end)
  end

  defp variant(_, _, %Variant{} = variant), do: {:ok, variant}

  defp variant(client, node, value) do
    case GenServer.call(client, {:type, node}) do
      nil ->
        with {:ok, [%DataValue{value: %Variant{type: type}}]} <- read_many(client, [node]) do
          GenServer.cast(client, {:type, node, type})
          {:ok, %Variant{type: type, value: value}}
        else
          {:ok, [%DataValue{status: status}]} when status != 0 -> {:error, status_name(status)}
          {:ok, _} -> {:error, :bad_type_mismatch}
          error -> error
        end

      type ->
        {:ok, %Variant{type: type, value: value}}
    end
  end

  @doc """
  Lists the references of a node, following continuation points until the
  server has sent them all.

  ## Options

    * `:direction` - `:forward` (the default), `:inverse` or `:both`
    * `:reference_type` - the reference type to follow, with its subtypes
      (default `i=33`, HierarchicalReferences)
    * `:max_references` - how many references to ask for at a time (default 0,
      leaving it to the server)
  """
  @spec browse(client, node_ref, keyword) :: {:ok, [Types.ReferenceDescription.t()]} | error
  def browse(client, node, opts \\ []) do
    description = %Types.BrowseDescription{
      node_id: node_id(node),
      browse_direction: Keyword.get(opts, :direction, :forward),
      reference_type_id: node_id(Keyword.get(opts, :reference_type, "i=33")),
      include_subtypes: true,
      node_class_mask: 0,
      result_mask: 63
    }

    request = %Types.BrowseRequest{
      requested_max_references_per_node: Keyword.get(opts, :max_references, 0),
      nodes_to_browse: [description]
    }

    with {:ok, %{results: [result]}} <- request(client, request) do
      browse_rest(client, result, [])
    end
  end

  defp browse_rest(client, %Types.BrowseResult{status_code: status} = result, acc) do
    cond do
      StatusCode.bad?(status) ->
        {:error, status_name(status)}

      result.continuation_point in [nil, ""] ->
        {:ok, Enum.concat(Enum.reverse([result.references || [] | acc]))}

      true ->
        browse_next(client, result, acc)
    end
  end

  defp browse_next(client, %Types.BrowseResult{continuation_point: point, references: refs}, acc) do
    request = %Types.BrowseNextRequest{
      release_continuation_points: false,
      continuation_points: [point]
    }

    with {:ok, %{results: [result]}} <- request(client, request) do
      browse_rest(client, result, [refs || [] | acc])
    end
  end

  @doc """
  Calls a method on an object, returning its output arguments.

  Arguments are `OPCUA.Variant`s, or plain values: integers go as Int32,
  floats as Double, and strings, booleans and `DateTime`s as themselves. Use a
  variant when the method wants another type.
  """
  @spec call(client, node_ref, node_ref, [term]) :: {:ok, [term]} | error
  def call(client, object, method, args \\ []) do
    call = %Types.CallMethodRequest{
      object_id: node_id(object),
      method_id: node_id(method),
      input_arguments: Enum.map(args, &infer/1)
    }

    with {:ok, %{results: [result]}} <-
           request(client, %Types.CallRequest{methods_to_call: [call]}) do
      if StatusCode.bad?(result.status_code),
        do: {:error, status_name(result.status_code)},
        else: {:ok, Enum.map(result.output_arguments || [], &unwrap/1)}
    end
  end

  defp infer(%Variant{} = v), do: v
  defp infer(v) when is_boolean(v), do: %Variant{type: :boolean, value: v}

  defp infer(v) when is_integer(v) and v in -0x8000_0000..0x7FFF_FFFF,
    do: %Variant{type: :int32, value: v}

  defp infer(v) when is_integer(v), do: %Variant{type: :int64, value: v}
  defp infer(v) when is_float(v), do: %Variant{type: :double, value: v}
  defp infer(v) when is_binary(v), do: %Variant{type: :string, value: v}
  defp infer(%DateTime{} = v), do: %Variant{type: :date_time, value: v}
  defp infer(%NodeId{} = v), do: %Variant{type: :node_id, value: v}

  @doc """
  Sends any service request from `OPCUA.Types` and returns its response. The
  client fills in the request header.

  A response whose service result is Bad, or a ServiceFault, is
  `{:error, status}`.
  """
  @spec request(client, struct, timeout) :: {:ok, struct} | error
  def request(client, request, timeout \\ nil) do
    unless is_map_key(request, :request_header) do
      raise ArgumentError, "not a service request: #{inspect(request)}"
    end

    case GenServer.call(client, {:request, request, timeout}, :infinity) do
      # A value that doesn't fit its type raises here, not in the client.
      {:raise, exception} -> raise exception
      reply -> reply
    end
  end

  @doc """
  Asks a server for its endpoints, without opening a session: the security
  policies and login methods it offers.
  """
  @spec endpoints(String.t(), keyword) :: {:ok, [Types.EndpointDescription.t()]} | error
  def endpoints(url, opts \\ []) do
    timeout = Keyword.get(opts, :timeout, 5000)

    with {:ok, state} <- connect(url, timeout, 60_000) do
      case exchange(state, %Types.GetEndpointsRequest{endpoint_url: url}) do
        {:ok, %{endpoints: endpoints}, state} ->
          disconnect(state)
          {:ok, endpoints}

        error ->
          :gen_tcp.close(state.socket)
          error
      end
    end
  end

  defp node_id(%NodeId{} = node), do: node
  defp node_id(text) when is_binary(text), do: NodeId.parse!(text)

  defp status_name(status), do: StatusCode.name(status) || status

  ## Server

  @impl true
  def init(opts) do
    Process.flag(:trap_exit, true)
    url = Keyword.fetch!(opts, :url)
    timeout = Keyword.get(opts, :timeout, 5000)

    with {:ok, state} <- connect(url, timeout, Keyword.get(opts, :channel_lifetime, 3_600_000)),
         {:ok, state} <- session(state, opts),
         # Chunks that arrived with the last handshake reply still go through the channel.
         {:noreply, state} <-
           Enum.reduce_while(state.chunks, {:noreply, %{state | chunks: []}}, &chunk/2) do
      :ok = :inet.setopts(state.socket, active: true)
      {:ok, schedule(state)}
    else
      {:error, reason} -> {:stop, reason}
      {:stop, reason, _} -> {:stop, reason}
    end
  end

  # A connection that is set up with blocking receives, before the process
  # switches the socket to active mode.
  defp connect(url, timeout, lifetime) do
    with {:ok, {host, port}} <- Transport.endpoint(url),
         {:ok, socket} <-
           :gen_tcp.connect(host, port, [:binary, active: false, nodelay: true], timeout),
         state = %{
           socket: socket,
           url: url,
           timeout: timeout,
           lifetime: lifetime,
           buffer: <<>>,
           chunks: [],
           channel: nil,
           token: nil,
           pending: %{},
           types: %{},
           handle: 0
         },
         :ok <-
           :gen_tcp.send(socket, Transport.frame(:hello, :final, Transport.hello(@limits, url))),
         {:ok, limits, state} <- acknowledge(state),
         state = %{state | channel: SecureChannel.new(limits, receive_max_message: @max_message)},
         {:ok, state} <- open(state, :issue) do
      {:ok, state}
    else
      {:error, reason} -> {:error, reason}
    end
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

  defp open(state, type) do
    request = %Types.OpenSecureChannelRequest{
      request_header: header(state, 0),
      client_protocol_version: 0,
      request_type: type,
      security_mode: :none,
      client_nonce: "",
      requested_lifetime: state.lifetime
    }

    {id, channel} = SecureChannel.next_request_id(state.channel)

    with {:ok, frames, channel} <- SecureChannel.encode(channel, :open, id, request),
         :ok <- :gen_tcp.send(state.socket, frames),
         {:ok, %Types.OpenSecureChannelResponse{} = response, state} <-
           await(%{state | channel: channel}, id) do
      {:ok,
       %{
         state
         | channel: SecureChannel.token(state.channel, response.security_token),
           token: response.security_token
       }}
    end
  end

  defp session(state, opts) do
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
         state =
           Map.merge(state, %{
             auth: created.authentication_token,
             session_timeout: created.revised_session_timeout
           }),
         {:ok, token} <- identity(created.server_endpoints, Keyword.get(opts, :user, :anonymous)),
         {:ok, _, state} <-
           exchange(state, %Types.ActivateSessionRequest{
             user_identity_token: token,
             locale_ids: ["en"]
           }) do
      {:ok, state}
    end
  end

  defp identity(endpoints, user) do
    none = SecureChannel.none()

    policies =
      for %{security_policy_uri: ^none, user_identity_tokens: tokens} <- endpoints || [],
          token <- tokens || [],
          do: token

    case {user, policies} do
      {:anonymous, _} ->
        policy = Enum.find(policies, &(&1.token_type == :anonymous))

        {:ok,
         %Types.AnonymousIdentityToken{
           policy_id: if(policy, do: policy.policy_id, else: "anonymous")
         }}

      {{name, password}, _} ->
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

  # Sends a request and waits for its response, before the socket goes active.
  defp exchange(state, request) do
    {id, channel} = SecureChannel.next_request_id(state.channel)
    {request, state} = with_header(%{state | channel: channel}, request, state.timeout)

    with {:ok, frames, channel} <- SecureChannel.encode(state.channel, :message, id, request),
         :ok <- :gen_tcp.send(state.socket, frames),
         {:ok, response, state} <- await(%{state | channel: channel}, id) do
      case result(response) do
        {:ok, response} -> {:ok, response, state}
        error -> error
      end
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

  defp remote_error(body) do
    case Transport.decode(:error, body) do
      {:ok, {status, _reason}} -> {:error, status_name(status)}
      error -> error
    end
  end

  defp disconnect(state) do
    {id, channel} = SecureChannel.next_request_id(state.channel)

    with {:ok, frames, _} <-
           SecureChannel.encode(channel, :close, id, %Types.CloseSecureChannelRequest{
             request_header: header(state, 0)
           }) do
      :gen_tcp.send(state.socket, frames)
    end

    :gen_tcp.close(state.socket)
  end

  defp header(state, handle) do
    %Types.RequestHeader{
      authentication_token: Map.get(state, :auth),
      timestamp: DateTime.utc_now(),
      request_handle: handle,
      timeout_hint: state.timeout
    }
  end

  defp with_header(state, request, timeout) do
    handle = if state.handle >= 0xFFFF_FFFF, do: 1, else: state.handle + 1
    header = %{header(state, handle) | timeout_hint: timeout}
    {%{request | request_header: header}, %{state | handle: handle}}
  end

  defp result(%Types.ServiceFault{response_header: %{service_result: status}}),
    do: {:error, status_name(status)}

  defp result(%{response_header: %{service_result: status}} = response) do
    if StatusCode.bad?(status), do: {:error, status_name(status)}, else: {:ok, response}
  end

  ## Running

  @impl true
  def handle_call({:request, request, timeout}, from, state) do
    timeout = timeout || state.timeout
    {id, channel} = SecureChannel.next_request_id(state.channel)
    {request, state} = with_header(%{state | channel: channel}, request, timeout)

    try do
      send_message(state, :message, id, request)
    rescue
      exception in ArgumentError -> {:raise, exception}
    end
    |> case do
      {:ok, state} ->
        timer = Process.send_after(self(), {:timeout, id}, timeout)
        {:noreply, %{state | pending: Map.put(state.pending, id, {from, timer})}}

      {:raise, exception} ->
        {:reply, {:raise, exception}, state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:type, node}, _from, state), do: {:reply, Map.get(state.types, node), state}

  @impl true
  def handle_cast({:type, node, type}, state),
    do: {:noreply, %{state | types: Map.put(state.types, node, type)}}

  @impl true
  def handle_info({:tcp, _, data}, state) do
    case Transport.split(state.buffer <> data, @receive_buffer) do
      {:ok, chunks, rest} ->
        chunks |> Enum.reduce_while({:noreply, %{state | buffer: rest}}, &chunk/2)

      {:error, reason} ->
        {:stop, {:shutdown, reason}, state}
    end
  end

  def handle_info({:tcp_closed, _}, state),
    do: {:stop, {:shutdown, :bad_connection_closed}, state}

  def handle_info({:tcp_error, _, reason}, state), do: {:stop, {:shutdown, reason}, state}

  def handle_info({:timeout, id}, state) do
    case Map.pop(state.pending, id) do
      {{from, _}, pending} when is_tuple(from) ->
        GenServer.reply(from, {:error, :bad_timeout})
        {:noreply, %{state | pending: pending}}

      {_, pending} ->
        {:noreply, %{state | pending: pending}}
    end
  end

  def handle_info(:keep_alive, state) do
    {id, channel} = SecureChannel.next_request_id(state.channel)

    read = %Types.ReadValueId{
      node_id: %NodeId{id: @keep_alive},
      attribute_id: OPCUA.AttributeId.id(:value)
    }

    {request, state} =
      with_header(
        %{state | channel: channel},
        %Types.ReadRequest{nodes_to_read: [read]},
        state.timeout
      )

    case send_message(state, :message, id, request) do
      {:ok, state} ->
        {:noreply,
         schedule_keep_alive(%{state | pending: Map.put(state.pending, id, {:keep_alive, nil})})}

      {:error, reason} ->
        {:stop, {:shutdown, reason}, state}
    end
  end

  def handle_info(:renew, state) do
    {id, channel} = SecureChannel.next_request_id(state.channel)

    request = %Types.OpenSecureChannelRequest{
      request_header: header(state, 0),
      request_type: :renew,
      security_mode: :none,
      client_nonce: "",
      requested_lifetime: state.lifetime
    }

    case send_message(%{state | channel: channel}, :open, id, request) do
      {:ok, state} -> {:noreply, %{state | pending: Map.put(state.pending, id, {:renew, nil})}}
      {:error, reason} -> {:stop, {:shutdown, reason}, state}
    end
  end

  def handle_info({:session_lost, status}, state), do: {:stop, {:shutdown, status}, state}
  def handle_info({:EXIT, _, reason}, state), do: {:stop, reason, state}

  defp chunk({:error, _, body}, {:noreply, state}) do
    {:halt, {:stop, {:shutdown, remote_error(body)}, state}}
  end

  defp chunk(chunk, {:noreply, state}) do
    case SecureChannel.receive(state.channel, chunk) do
      {:ok, channel} ->
        {:cont, {:noreply, %{state | channel: channel}}}

      {:ok, {_kind, id, response}, channel} ->
        {:cont, {:noreply, respond(%{state | channel: channel}, id, {:ok, response})}}

      {:abort, id, status, _reason, channel} ->
        {:cont,
         {:noreply, respond(%{state | channel: channel}, id, {:error, status_name(status)})}}

      {:error, reason} ->
        {:halt, {:stop, {:shutdown, reason}, state}}
    end
  end

  defp respond(state, id, reply) do
    case Map.pop(state.pending, id) do
      {nil, _} ->
        state

      {{:renew, _}, pending} ->
        case reply do
          {:ok, %Types.OpenSecureChannelResponse{security_token: token}} ->
            schedule_renew(%{
              state
              | pending: pending,
                channel: SecureChannel.token(state.channel, token),
                token: token
            })

          _ ->
            Logger.warning("OPC UA secure channel renewal failed: #{inspect(reply)}")
            %{state | pending: pending}
        end

      {{:keep_alive, _}, pending} ->
        with {:error, status} when status in @session_lost <-
               with({:ok, response} <- reply, do: result(response)) do
          send(self(), {:session_lost, status})
        end

        %{state | pending: pending}

      {{from, timer}, pending} ->
        Process.cancel_timer(timer)
        GenServer.reply(from, with({:ok, response} <- reply, do: result(response)))
        %{state | pending: pending}
    end
  end

  defp send_message(state, kind, id, message) do
    with {:ok, frames, channel} <- SecureChannel.encode(state.channel, kind, id, message),
         :ok <- :gen_tcp.send(state.socket, frames) do
      {:ok, %{state | channel: channel}}
    else
      {:error, :closed} -> {:error, :bad_connection_closed}
      error -> error
    end
  end

  defp schedule(state), do: state |> schedule_renew() |> schedule_keep_alive()

  # Renew at 75% of the token's lifetime, as the spec recommends.
  defp schedule_renew(state) do
    Process.send_after(self(), :renew, trunc(state.token.revised_lifetime * 0.75))
    state
  end

  defp schedule_keep_alive(state) do
    Process.send_after(self(), :keep_alive, trunc(state.session_timeout / 3))
    state
  end

  @impl true
  def terminate(reason, state) do
    for {_, {from, _}} <- state.pending,
        is_tuple(from),
        do: GenServer.reply(from, {:error, :bad_connection_closed})

    # {:shutdown, reason} means the connection is already broken.
    if reason in [:normal, :shutdown], do: close_session(state)

    :gen_tcp.close(state.socket)
  end

  defp close_session(state) do
    {id, channel} = SecureChannel.next_request_id(state.channel)

    {request, state} =
      with_header(
        %{state | channel: channel},
        %Types.CloseSessionRequest{delete_subscriptions: true},
        state.timeout
      )

    with {:ok, state} <- send_message(state, :message, id, request) do
      # Give the server a moment to answer before the channel goes away.
      receive do
        {:tcp, _, _} -> :ok
      after
        1000 -> :ok
      end

      disconnect(state)
    end
  end
end
