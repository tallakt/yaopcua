defmodule OPCUA.Server.Services do
  @moduledoc false
  # Answers service requests for a connection: `handle(request, state)`
  # returns the response and the connection's new state. Sessions are kept in
  # `state.sessions`, by authentication token.

  require Logger

  alias OPCUA.{Certificate, NodeId, SecurityPolicy, StatusCode, Variant}
  alias OPCUA.Server.{AddressSpace, Conditions, Node, Subscriptions}
  alias OPCUA.Types

  # How many operations one request may ask for, and references one browse
  # may return before it needs a continuation point.
  @max_operations 10_000
  @max_references 1000
  @max_continuation_points 16

  @subscriptions [
    Types.CreateSubscriptionRequest,
    Types.ModifySubscriptionRequest,
    Types.SetPublishingModeRequest,
    Types.DeleteSubscriptionsRequest,
    Types.CreateMonitoredItemsRequest,
    Types.ModifyMonitoredItemsRequest,
    Types.SetMonitoringModeRequest,
    Types.DeleteMonitoredItemsRequest,
    Types.PublishRequest,
    Types.RepublishRequest
  ]

  @no_session [
    Types.GetEndpointsRequest,
    Types.FindServersRequest,
    Types.CreateSessionRequest,
    Types.ActivateSessionRequest
  ]

  @doc false
  def header(request, status) do
    %Types.ResponseHeader{
      timestamp: DateTime.utc_now(),
      request_handle: request.request_header.request_handle,
      service_result: StatusCode.code(status_atom(status))
    }
  end

  defp status_atom(0), do: :good
  defp status_atom(status), do: status

  @doc false
  def fault(request, status), do: %Types.ServiceFault{response_header: header(request, status)}

  @doc false
  def handle(%module{} = request, state) when module in @no_session, do: service(request, state)

  def handle(request, state) do
    auth = request.request_header.authentication_token

    case state.sessions do
      # CloseSession is allowed before activation, too.
      %{^auth => _} when is_struct(request, Types.CloseSessionRequest) ->
        close(request, state)

      %{^auth => %{activated: true} = session} ->
        {response, session} = session(request, touch(session), state)
        {response, %{state | sessions: Map.put(state.sessions, auth, session)}}

      %{^auth => _} ->
        {fault(request, :bad_session_not_activated), state}

      _ ->
        {fault(request, :bad_session_id_invalid), state}
    end
  end

  ## Without a session

  defp service(%Types.GetEndpointsRequest{} = request, state) do
    {%Types.GetEndpointsResponse{
       response_header: header(request, 0),
       endpoints: endpoints(state.config)
     }, state}
  end

  defp service(%Types.FindServersRequest{} = request, state) do
    {%Types.FindServersResponse{
       response_header: header(request, 0),
       servers: [state.config.application]
     }, state}
  end

  defp service(%Types.CreateSessionRequest{} = request, state) do
    channel = state.channel
    config = state.config

    with :ok <- offered(channel, config),
         :ok <- client_certificate(request, channel) do
      timeout = request.requested_session_timeout |> max(1000.0) |> min(3_600_000.0)
      auth = %NodeId{ns: 0, id: {:opaque, :crypto.strong_rand_bytes(32)}}
      nonce = :crypto.strong_rand_bytes(32)

      session =
        Subscriptions.new_session(%{
          id: %NodeId{ns: 1, id: {:guid, guid()}},
          auth: auth,
          name: request.session_name,
          timeout: timeout,
          activated: false,
          user: nil,
          nonce: nonce,
          continuation: %{},
          last: nil
        })

      response = %Types.CreateSessionResponse{
        response_header: header(request, 0),
        session_id: session.id,
        authentication_token: auth,
        revised_session_timeout: timeout,
        server_nonce: nonce,
        server_certificate: config.certificate,
        server_endpoints: endpoints(config),
        server_signature: server_signature(request, channel, config),
        max_request_message_size: 0
      }

      {response, %{state | sessions: Map.put(state.sessions, auth, touch(session))}}
    else
      {:error, status} -> {fault(request, status), state}
    end
  end

  defp service(%Types.ActivateSessionRequest{} = request, state) do
    auth = request.request_header.authentication_token

    with %{} = session <- state.sessions[auth] || {:error, :bad_session_id_invalid},
         :ok <- client_signature(request, session, state),
         {:ok, user} <-
           login(request.user_identity_token, request.user_token_signature, session, state) do
      nonce = :crypto.strong_rand_bytes(32)
      session = touch(%{session | activated: true, user: user, nonce: nonce})

      response = %Types.ActivateSessionResponse{
        response_header: header(request, 0),
        server_nonce: nonce
      }

      {response, %{state | sessions: Map.put(state.sessions, auth, session)}}
    else
      {:error, status} -> {fault(request, status), state}
    end
  end

  # A session is only made on an endpoint the server offers; without a None
  # endpoint, a None channel is only for asking the endpoints.
  defp offered(channel, config) do
    if {channel.policy, channel.mode} in config.security,
      do: :ok,
      else: {:error, :bad_security_policy_rejected}
  end

  # On a secure channel, the session is the application whose certificate
  # opened the channel.
  defp client_certificate(_, %{policy: :none}), do: :ok

  defp client_certificate(request, channel) do
    uri = Certificate.application_uri(channel.remote_certificate)

    cond do
      request.client_certificate != channel.remote_certificate ->
        {:error, :bad_certificate_invalid}

      byte_size(request.client_nonce || "") < 32 ->
        {:error, :bad_nonce_invalid}

      uri && uri != request.client_description.application_uri ->
        {:error, :bad_certificate_uri_invalid}

      true ->
        :ok
    end
  end

  # The server proves it holds its key by signing the client's certificate and nonce...
  defp server_signature(_, %{policy: :none}, _), do: nil

  defp server_signature(request, channel, config) do
    %Types.SignatureData{
      algorithm: SecurityPolicy.signature_uri(channel.policy),
      signature:
        SecurityPolicy.sign(
          channel.policy,
          request.client_certificate <> request.client_nonce,
          config.private_key
        )
    }
  end

  # ...and the client by signing the server's.
  defp client_signature(_, _, %{channel: %{policy: :none}}), do: :ok

  defp client_signature(request, session, %{channel: channel, config: config}) do
    signature = request.client_signature && request.client_signature.signature
    key = Certificate.public_key(channel.remote_certificate)

    if is_binary(signature) and
         SecurityPolicy.verify(
           channel.policy,
           config.certificate <> session.nonce,
           signature,
           key
         ),
       do: :ok,
       else: {:error, :bad_application_signature_invalid}
  end

  defp login(nil, signature, session, state),
    do: login(%Types.AnonymousIdentityToken{}, signature, session, state)

  defp login(%Types.AnonymousIdentityToken{}, _, _, %{config: %{anonymous: true}}),
    do: {:ok, :anonymous}

  defp login(%Types.AnonymousIdentityToken{}, _, _, _), do: {:error, :bad_identity_token_rejected}

  defp login(%Types.UserNameIdentityToken{} = token, _, session, %{
         channel: channel,
         config: config
       }) do
    password =
      case token.encryption_algorithm do
        # In plain text only where the endpoint doesn't ask for encryption,
        # or the channel encrypts everything anyway.
        algorithm when algorithm in [nil, ""] ->
          if channel.mode == :sign_and_encrypt or token_policy(config, channel) == :none,
            do: {:ok, token.password},
            else: {:error, :bad_identity_token_invalid}

        algorithm ->
          case Enum.find(
                 SecurityPolicy.all() -- [:none],
                 &(SecurityPolicy.encryption_uri(&1) == algorithm)
               ) do
            nil ->
              {:error, :bad_identity_token_invalid}

            policy ->
              SecurityPolicy.decrypt_secret(
                policy,
                token.password || "",
                session.nonce,
                config.private_key
              )
          end
      end

    with {:ok, password} <- password do
      valid =
        case config.users do
          nil -> false
          users when is_map(users) -> Map.fetch(users, token.user_name) == {:ok, password}
          fun when is_function(fun, 2) -> fun.(token.user_name, password) == true
        end

      if valid, do: {:ok, token.user_name}, else: {:error, :bad_user_access_denied}
    end
  end

  # A user certificate: trusted, and the user proves they hold its key by
  # signing the server's certificate and nonce.
  defp login(%Types.X509IdentityToken{certificate_data: certificate}, signature, session, %{
         config: config
       }) do
    policy =
      Enum.find(
        SecurityPolicy.all() -- [:none],
        &(signature && SecurityPolicy.signature_uri(&1) == signature.algorithm)
      )

    cond do
      config.user_certificates == nil or not is_binary(certificate) ->
        {:error, :bad_identity_token_rejected}

      not Certificate.trusted?(certificate, config.user_certificates) ->
        {:error, :bad_identity_token_rejected}

      policy == nil or not is_binary(signature.signature) or
          not SecurityPolicy.verify(
            policy,
            config.certificate <> session.nonce,
            signature.signature,
            Certificate.public_key(certificate)
          ) ->
        {:error, :bad_user_signature_invalid}

      true ->
        {:ok,
         Certificate.application_uri(certificate) ||
           Base.encode16(Certificate.thumbprint(certificate))}
    end
  end

  defp login(_, _, _, _), do: {:error, :bad_identity_token_invalid}

  # The policy that protects user secrets on an endpoint: a secure channel's
  # own, and on a None endpoint the strongest the server has.
  defp token_policy(_config, %{policy: policy}) when policy != :none, do: policy

  defp token_policy(config, _) do
    offered = for {policy, _} <- config.security, do: policy
    SecurityPolicy.all() |> Enum.filter(&(&1 in offered)) |> List.last()
  end

  defp endpoints(config) do
    for {policy, mode} <- config.security do
      # On secure endpoints tokens use the channel's policy; on None the strongest one.
      token_uri =
        case {policy, token_policy(config, %{policy: policy})} do
          {:none, secure} when secure != :none -> SecurityPolicy.uri(secure)
          _ -> nil
        end

      tokens =
        if(config.anonymous,
          do: [%Types.UserTokenPolicy{policy_id: "anonymous", token_type: :anonymous}],
          else: []
        ) ++
          if(config.users,
            do: [
              %Types.UserTokenPolicy{
                policy_id: "username",
                token_type: :user_name,
                security_policy_uri: token_uri
              }
            ],
            else: []
          ) ++
          if(config.user_certificates,
            do: [
              %Types.UserTokenPolicy{
                policy_id: "certificate",
                token_type: :certificate,
                security_policy_uri: token_uri
              }
            ],
            else: []
          )

      %Types.EndpointDescription{
        endpoint_url: config.endpoint_url,
        server: config.application,
        server_certificate: config.certificate,
        security_mode: mode,
        security_policy_uri: SecurityPolicy.uri(policy),
        user_identity_tokens: tokens,
        transport_profile_uri:
          "http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary",
        security_level: SecurityPolicy.level(policy, mode)
      }
    end
  end

  defp guid do
    <<a::32, b::16, c::16, d::16, e::48>> = :crypto.strong_rand_bytes(16)

    [{a, 8}, {b, 4}, {c, 4}, {d, 4}, {e, 12}]
    |> Enum.map_join("-", fn {n, w} ->
      n |> Integer.to_string(16) |> String.pad_leading(w, "0")
    end)
  end

  # Each request restarts the session's timeout.
  defp touch(session) do
    last = System.monotonic_time()
    Process.send_after(self(), {:session_timeout, session.auth, last}, trunc(session.timeout))
    %{session | last: last}
  end

  # Publish requests still waiting are answered before the session goes.
  defp close(request, state) do
    auth = request.request_header.authentication_token
    session = state.sessions[auth]

    waiting =
      for publish <- session.publishes,
          do: {publish.id, fault(publish.request, :bad_session_closed)}

    outbox = state.outbox ++ Enum.reverse(session.outbox) ++ waiting
    state = %{state | sessions: Map.delete(state.sessions, auth), outbox: outbox}
    {%Types.CloseSessionResponse{response_header: header(request, 0)}, state}
  end

  ## With a session

  defp session(request, session, state) do
    case operations(request) do
      0 -> {fault(request, :bad_nothing_to_do), session}
      n when n > @max_operations -> {fault(request, :bad_too_many_operations), session}
      _ -> call(request, session, state)
    end
  end

  defp operations(%Types.ReadRequest{nodes_to_read: list}), do: length(list || [])
  defp operations(%Types.WriteRequest{nodes_to_write: list}), do: length(list || [])
  defp operations(%Types.BrowseRequest{nodes_to_browse: list}), do: length(list || [])
  defp operations(%Types.BrowseNextRequest{continuation_points: list}), do: length(list || [])

  defp operations(%Types.TranslateBrowsePathsToNodeIdsRequest{browse_paths: list}),
    do: length(list || [])

  defp operations(%Types.CallRequest{methods_to_call: list}), do: length(list || [])
  defp operations(%Types.RegisterNodesRequest{nodes_to_register: list}), do: length(list || [])

  defp operations(%Types.UnregisterNodesRequest{nodes_to_unregister: list}),
    do: length(list || [])

  defp operations(_), do: 1

  defp call(%module{} = request, session, state) when module in @subscriptions,
    do: Subscriptions.handle(request, session, state)

  defp call(%Types.ReadRequest{} = request, session, state) do
    if request.timestamps_to_return in [:source, :server, :both, :neither] do
      results =
        for read <- request.nodes_to_read,
            do: AddressSpace.read(state.config.space, read, request.timestamps_to_return)

      {%Types.ReadResponse{response_header: header(request, 0), results: results}, session}
    else
      {fault(request, :bad_timestamps_to_return_invalid), session}
    end
  end

  defp call(%Types.WriteRequest{} = request, session, state) do
    results =
      for write <- request.nodes_to_write, do: AddressSpace.write(state.config.space, write)

    {%Types.WriteResponse{response_header: header(request, 0), results: results}, session}
  end

  defp call(%Types.BrowseRequest{} = request, session, state) do
    if request.view && request.view.view_id do
      {fault(request, :bad_view_id_unknown), session}
    else
      max = request.requested_max_references_per_node
      max = if max in [0, nil], do: @max_references, else: min(max, @max_references)

      {results, session} =
        Enum.map_reduce(request.nodes_to_browse, session, fn description, session ->
          case AddressSpace.browse(state.config.space, description) do
            {:ok, refs} ->
              page(session, refs, max)

            {:error, status} ->
              {%Types.BrowseResult{status_code: StatusCode.code(status)}, session}
          end
        end)

      {%Types.BrowseResponse{response_header: header(request, 0), results: results}, session}
    end
  end

  defp call(%Types.BrowseNextRequest{} = request, session, _state) do
    {results, session} =
      Enum.map_reduce(request.continuation_points, session, fn point, session ->
        case Map.pop(session.continuation, point) do
          {nil, _} ->
            {%Types.BrowseResult{status_code: StatusCode.code(:bad_continuation_point_invalid)},
             session}

          {_, continuation} when request.release_continuation_points ->
            {%Types.BrowseResult{status_code: 0}, %{session | continuation: continuation}}

          {{refs, max}, continuation} ->
            page(%{session | continuation: continuation}, refs, max)
        end
      end)

    {%Types.BrowseNextResponse{response_header: header(request, 0), results: results}, session}
  end

  defp call(%Types.TranslateBrowsePathsToNodeIdsRequest{} = request, session, state) do
    results =
      for path <- request.browse_paths, do: AddressSpace.translate(state.config.space, path)

    {%Types.TranslateBrowsePathsToNodeIdsResponse{
       response_header: header(request, 0),
       results: results
     }, session}
  end

  defp call(%Types.CallRequest{} = request, session, state) do
    {results, session} =
      Enum.map_reduce(request.methods_to_call, session, &call_method(&1, &2, state))

    {%Types.CallResponse{response_header: header(request, 0), results: results}, session}
  end

  # Nodes need no registering here; the ids are handed back as they are.
  defp call(%Types.RegisterNodesRequest{} = request, session, _state) do
    {%Types.RegisterNodesResponse{
       response_header: header(request, 0),
       registered_node_ids: request.nodes_to_register
     }, session}
  end

  defp call(%Types.UnregisterNodesRequest{} = request, session, _state) do
    {%Types.UnregisterNodesResponse{response_header: header(request, 0)}, session}
  end

  defp call(request, session, _state), do: {fault(request, :bad_service_unsupported), session}

  # The first `max` references, and a continuation point for the rest.
  defp page(session, refs, max) when length(refs) <= max do
    {%Types.BrowseResult{status_code: 0, references: refs}, session}
  end

  defp page(session, refs, max) do
    if map_size(session.continuation) >= @max_continuation_points do
      {%Types.BrowseResult{status_code: StatusCode.code(:bad_no_continuation_points)}, session}
    else
      {now, later} = Enum.split(refs, max)
      point = :crypto.strong_rand_bytes(16)
      result = %Types.BrowseResult{status_code: 0, continuation_point: point, references: now}
      {result, %{session | continuation: Map.put(session.continuation, point, {later, max})}}
    end
  end

  @condition_type %NodeId{id: 2782}
  @refresh %NodeId{id: 3875}
  @refresh2 %NodeId{id: 12912}
  @acknowledge %NodeId{id: 9111}
  @add_comment %NodeId{id: 9029}
  @enable %NodeId{id: 9027}
  @disable %NodeId{id: 9028}

  # The methods of ConditionType and AcknowledgeableConditionType, called on
  # the type (ConditionRefresh) or on a condition (the rest).
  defp call_method(%{object_id: @condition_type, method_id: method} = call, session, state)
       when method in [@refresh, @refresh2] do
    space = state.config.space

    case {method, call.input_arguments || []} do
      {@refresh, [%Variant{type: :uint32, value: sub}]} ->
        refresh(session, sub, nil, space)

      {@refresh2, [%Variant{type: :uint32, value: sub}, %Variant{type: :uint32, value: item}]} ->
        refresh(session, sub, item, space)

      {_, args} ->
        {arguments_status(args, if(method == @refresh, do: 1, else: 2)), session}
    end
  end

  defp call_method(%{method_id: method} = call, session, state)
       when method in [@acknowledge, @add_comment, @enable, @disable] do
    space = state.config.space

    case Conditions.state(space, call.object_id) do
      nil ->
        {method(space, call), session}

      condition ->
        {condition_method(method, condition, call.input_arguments || [], session, state), session}
    end
  end

  defp call_method(call, session, state), do: {method(state.config.space, call), session}

  defp refresh(session, sub, item, space) do
    case Subscriptions.refresh(session, sub, item, Conditions.refresh(space), space) do
      {:ok, session} -> {%Types.CallMethodResult{status_code: 0}, session}
      {:error, status} -> {%Types.CallMethodResult{status_code: StatusCode.code(status)}, session}
    end
  end

  defp arguments_status(args, wanted) do
    status =
      cond do
        length(args) < wanted -> :bad_arguments_missing
        length(args) > wanted -> :bad_too_many_arguments
        true -> :bad_invalid_argument
      end

    %Types.CallMethodResult{status_code: StatusCode.code(status)}
  end

  defp condition_method(method, condition, args, session, state)
       when method in [@acknowledge, @add_comment] do
    with [
           %Variant{type: :byte_string, value: event_id},
           %Variant{type: :localized_text, value: comment}
         ] <- args,
         comment = comment && comment.text,
         {:ok, condition} <- check_event(method, condition, event_id, state.config.space),
         :ok <- if(method == @acknowledge, do: acknowledged(condition, comment), else: :ok) do
      changes =
        if method == @acknowledge, do: [acked: true, comment: comment], else: [comment: comment]

      update(condition, changes ++ [user: user(session)], state)
    else
      {:error, status} -> %Types.CallMethodResult{status_code: StatusCode.code(status)}
      args when is_list(args) -> arguments_status(args, 2)
    end
  end

  defp condition_method(method, condition, [], _session, state) do
    enable = method == @enable

    if condition.enabled == enable,
      do: %Types.CallMethodResult{
        status_code:
          StatusCode.code(
            if(enable, do: :bad_condition_already_enabled, else: :bad_condition_already_disabled)
          )
      },
      else: update(condition, [enabled: enable], state)
  end

  defp condition_method(_, _, args, _, _), do: arguments_status(args, 0)

  defp check_event(@acknowledge, condition, event_id, space),
    do: Conditions.acknowledgeable(space, condition.id, event_id)

  defp check_event(@add_comment, %{event_id: event_id} = condition, event_id, _),
    do: {:ok, condition}

  defp check_event(@add_comment, _, _, _), do: {:error, :bad_event_id_unknown}

  # The application hears of an acknowledgement first, and may refuse it.
  defp acknowledged(%{acknowledge: nil}, _), do: :ok

  defp acknowledged(%{acknowledge: fun} = condition, comment) do
    case fun.(comment) do
      :ok -> :ok
      {:error, status} when is_atom(status) -> {:error, status}
    end
  rescue
    exception ->
      Logger.error(
        "OPC UA acknowledge of #{condition.id} failed: " <>
          Exception.format(:error, exception, __STACKTRACE__)
      )

      {:error, :bad_internal_error}
  end

  # The server process makes the change, so every client hears of it.
  defp update(condition, changes, state) do
    case GenServer.call(state.config.server, {:condition, condition.id, changes}) do
      :ok -> %Types.CallMethodResult{status_code: 0}
      {:error, status} -> %Types.CallMethodResult{status_code: StatusCode.code(status)}
    end
  end

  defp user(%{user: user}) when is_binary(user), do: user
  defp user(_), do: nil

  defp method(space, %Types.CallMethodRequest{} = call) do
    with %Node{} = object <-
           AddressSpace.get(space, call.object_id) || {:error, :bad_node_id_unknown},
         %Node{class: :method} = method <-
           AddressSpace.get(space, call.method_id) || {:error, :bad_method_invalid},
         true <-
           Enum.member?(object.references, {%NodeId{id: 47}, method.node_id, true}) ||
             {:error, :bad_method_invalid},
         %{call: fun, inputs: types, outputs: outputs} <- method.attributes,
         {:ok, args} <- arguments(call.input_arguments || [], types) do
      invoke(fun, args, outputs, method)
    else
      {:error, status} ->
        %Types.CallMethodResult{status_code: StatusCode.code(status)}

      {:error, status, results} ->
        %Types.CallMethodResult{
          status_code: StatusCode.code(status),
          input_argument_results: results
        }

      %Node{} ->
        %Types.CallMethodResult{status_code: StatusCode.code(:bad_method_invalid)}

      # a method from namespace 0 that this server doesn't implement
      %{} ->
        %Types.CallMethodResult{status_code: StatusCode.code(:bad_not_implemented)}
    end
  end

  defp arguments(args, types) when length(args) < length(types),
    do: {:error, :bad_arguments_missing}

  defp arguments(args, types) when length(args) > length(types),
    do: {:error, :bad_too_many_arguments}

  defp arguments(args, types) do
    results =
      for {%Variant{type: type}, wanted} <- Enum.zip(args, types),
          do: if(type == wanted, do: 0, else: StatusCode.code(:bad_type_mismatch))

    if Enum.all?(results, &(&1 == 0)),
      do: {:ok, Enum.map(args, & &1.value)},
      else: {:error, :bad_invalid_argument, results}
  end

  defp invoke(fun, args, outputs, method) do
    case fun.(args) do
      {:ok, values} when length(values) == length(outputs) ->
        variants =
          for {value, type} <- Enum.zip(values, outputs), do: %Variant{type: type, value: value}

        %Types.CallMethodResult{status_code: 0, output_arguments: variants}

      {:error, status} when is_atom(status) ->
        %Types.CallMethodResult{status_code: StatusCode.code(status)}
    end
  rescue
    exception ->
      Logger.error(
        "OPC UA method #{method.node_id} failed: " <>
          Exception.format(:error, exception, __STACKTRACE__)
      )

      %Types.CallMethodResult{status_code: StatusCode.code(:bad_internal_error)}
  end
end
