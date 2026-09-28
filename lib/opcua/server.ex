defmodule OPCUA.Server do
  @moduledoc ~S"""
  An OPC UA server.

      {:ok, server} = OPCUA.Server.start_link(port: 4840)
      ns = OPCUA.Server.namespace(server, "urn:plant")

      :ok = OPCUA.Server.add_object(server, "ns=#{ns};s=Pump1", "Pump1")
      :ok = OPCUA.Server.add_variable(server, "ns=#{ns};s=Pump1.Speed", "Speed",
              parent: "ns=#{ns};s=Pump1", type: :int16, value: 1500, writable: true)

      # from the application, as often as the value changes
      :ok = OPCUA.Server.set(server, "ns=#{ns};s=Pump1.Speed", 1510)

  The server starts with the standard nodes of namespace 0 (the Server
  object, the type hierarchy and so on) from the release in
  `OPCUA.Schema.version/0`. Each client connection gets its own process, so a
  misbehaving client can't disturb the others.

  ## Not supported

  Sessions live as long as the connection that made them, so they can't be
  reactivated, nor their subscriptions transferred, on a new connection.
  There's no history, Query, node management from clients, SetTriggering or
  views; only built-in data types for variables; no limits on connections,
  sessions or subscriptions per client; and most of namespace 0 has no
  values. See "What's missing" in the README.

  ## Security

      OPCUA.Server.start_link(
        security: [:basic256sha256, :aes256_sha256_rsa_pss],
        certificate: OPCUA.Certificate.read("server.der"),
        private_key: OPCUA.Certificate.read_key("server.pem"),
        trust: [OPCUA.Certificate.read("scada.der")])

  The server offers an endpoint for each policy and mode in `:security`, and
  opens secure channels only with clients whose certificate it trusts. A
  None channel is always allowed for clients to ask for the endpoints, but
  sessions only on the endpoints offered. Passwords are decrypted when the
  client encrypts them; on a None endpoint the server asks for them to be
  encrypted with its strongest policy.

  ## Options

    * `:port` - the TCP port (default 4840; 0 picks a free one, see `port/1`)
    * `:ip` - the address to listen on (default all)
    * `:endpoint_url` - the URL the server gives clients (default
      `opc.tcp://<hostname>:<port>`)
    * `:application_uri`, `:product_name` - how the server presents itself
    * `:anonymous` - whether clients may log in without a user (default true)
    * `:users` - a map of usernames to passwords, or a function of username
      and password returning true for a valid login
    * `:security` - the endpoints to offer: `:none`, a policy such as
      `:basic256sha256` (both modes), or `{policy, mode}` (default `[:none]`)
    * `:trust` - the client certificates to trust, or `:any`; required with
      a secure policy
    * `:certificate`, `:private_key` - the server's own; a self-signed one is
      made if not given, which clients must trust anew on each start
    * `:user_certificates` - the user certificates to accept for certificate
      logins, or `:any`
    * `:name` - to register the process
  """

  use GenServer

  alias OPCUA.{DataValue, LocalizedText, NodeId, QualifiedName, Variant}
  alias OPCUA.Server.{AddressSpace, Conditions, Connection, Events, Node}
  alias OPCUA.Types

  @objects %NodeId{id: 85}
  @organizes %NodeId{id: 35}
  @has_component %NodeId{id: 47}
  @has_property %NodeId{id: 46}
  @folder_type %NodeId{id: 61}
  @base_object_type %NodeId{id: 58}
  @base_data_variable_type %NodeId{id: 63}
  @property_type %NodeId{id: 68}
  @argument %NodeId{id: 296}

  @type server :: GenServer.server() | AddressSpace.t()
  @type node_ref :: NodeId.t() | String.t()

  @doc "Starts the server. See the module doc for the options."
  @spec start_link(keyword) :: GenServer.on_start()
  def start_link(opts \\ []),
    do: GenServer.start_link(__MODULE__, check(opts), Keyword.take(opts, [:name]))

  # A secure server needs a decision about which clients to trust; that
  # mistake raises here, in the caller.
  defp check(opts) do
    secure = Enum.any?(security(opts), fn {policy, _} -> policy != :none end)

    if secure and not Keyword.has_key?(opts, :trust) do
      raise ArgumentError,
            "a secure server needs :trust, the client certificates to trust (a list, or :any)"
    end

    opts
  end

  # The endpoints to offer, as {policy, mode}.
  defp security(opts) do
    opts
    |> Keyword.get(:security, [:none])
    |> Enum.flat_map(fn
      :none -> [{:none, :none}]
      {policy, mode} -> [{policy, mode}]
      policy -> [{policy, :sign}, {policy, :sign_and_encrypt}]
    end)
  end

  @doc false
  def child_spec(opts),
    do: %{id: Keyword.get(opts, :name, __MODULE__), start: {__MODULE__, :start_link, [opts]}}

  @doc "The port the server listens on."
  @spec port(GenServer.server()) :: :inet.port_number()
  def port(server), do: GenServer.call(server, :port)

  @doc "The endpoint URL clients connect to."
  @spec endpoint_url(GenServer.server()) :: String.t()
  def endpoint_url(server), do: GenServer.call(server, :endpoint_url)

  @doc """
  The index of a namespace, adding it if it's new. Index 0 is the OPC UA
  namespace and 1 the server's own; the application's start at 2.
  """
  @spec namespace(GenServer.server(), String.t()) :: non_neg_integer
  def namespace(server, uri), do: GenServer.call(server, {:namespace, uri})

  @doc """
  Adds a folder, organized under `:parent` (default the Objects folder).
  """
  @spec add_folder(GenServer.server(), node_ref, String.t(), keyword) :: :ok | {:error, atom}
  def add_folder(server, node, name, opts \\ []) do
    add(server, node, :object, name, opts, %{event_notifier: 0}, nil, @organizes, @folder_type)
  end

  @doc """
  Adds an object, organized under `:parent` (default the Objects folder).
  `:type_definition` sets its object type (default BaseObjectType).
  """
  @spec add_object(GenServer.server(), node_ref, String.t(), keyword) :: :ok | {:error, atom}
  def add_object(server, node, name, opts \\ []) do
    type = node_id(Keyword.get(opts, :type_definition, @base_object_type))
    add(server, node, :object, name, opts, %{event_notifier: 0}, nil, @organizes, type)
  end

  @doc """
  Adds a variable.

  ## Options

    * `:type` - its built-in type, such as `:int16`, `:double` or `:string`
      (required)
    * `:value` - its first value; a list makes it an array
    * `:parent` - the object it belongs to (default the Objects folder)
    * `:writable` - whether clients may write it (default false)
    * `:read` - a function returning the value, called on each read, instead
      of a stored value
    * `:write` - a function called with each value a client writes, before
      it's stored; it returns `:ok`, or `{:error, status}` to refuse it
    * `:property` - add it as a property (HasProperty) instead of a component
    * `:description` - text for clients
  """
  @spec add_variable(GenServer.server(), node_ref, String.t(), keyword) :: :ok | {:error, atom}
  def add_variable(server, node, name, opts) do
    type = Keyword.fetch!(opts, :type)
    initial = Keyword.get_lazy(opts, :value, fn -> default(type) end)
    array = is_list(initial) or Keyword.get(opts, :array, false)
    access = if Keyword.get(opts, :writable, false), do: 3, else: 1

    attributes = %{
      data_type: %NodeId{id: OPCUA.Binary.type_id(type)},
      value_rank: if(array, do: 1, else: -1),
      array_dimensions: if(array, do: [0]),
      access_level: access,
      user_access_level: access,
      minimum_sampling_interval: 0.0,
      historizing: false
    }

    attributes = if write = opts[:write], do: Map.put(attributes, :write, write), else: attributes

    value =
      case opts[:read] do
        nil ->
          %DataValue{
            value: %Variant{type: type, value: initial},
            source_timestamp: DateTime.utc_now()
          }

        fun ->
          {:read, fun, type}
      end

    {reference, type_definition} =
      if opts[:property],
        do: {@has_property, @property_type},
        else: {@has_component, @base_data_variable_type}

    add(server, node, :variable, name, opts, attributes, value, reference, type_definition)
  end

  @doc """
  Adds a method to an object.

      OPCUA.Server.add_method(server, "ns=2;s=Pump1.Start", "Start",
        parent: "ns=2;s=Pump1",
        inputs: [{"speed", :int16}],
        outputs: [{"ok", :boolean}],
        call: fn [speed] -> {:ok, [true]} end)

  `:call` gets the input arguments as plain values and returns
  `{:ok, outputs}` or `{:error, status}`. It runs in the process of the
  client's connection.
  """
  @spec add_method(GenServer.server(), node_ref, String.t(), keyword) :: :ok | {:error, atom}
  def add_method(server, node, name, opts) do
    inputs = Keyword.get(opts, :inputs, [])
    outputs = Keyword.get(opts, :outputs, [])

    attributes = %{
      executable: true,
      user_executable: true,
      call: Keyword.fetch!(opts, :call),
      inputs: Enum.map(inputs, &elem(&1, 1)),
      outputs: Enum.map(outputs, &elem(&1, 1))
    }

    method = node_id(node)

    with :ok <-
           add(
             server,
             method,
             :method,
             name,
             Keyword.put_new(opts, :parent, @objects),
             attributes,
             nil,
             @has_component,
             nil
           ),
         :ok <- arguments(server, method, "InputArguments", inputs),
         :ok <- arguments(server, method, "OutputArguments", outputs) do
      :ok
    end
  end

  defp arguments(_, _, _, []), do: :ok

  defp arguments(server, method, name, arguments) do
    id = if is_binary(method.id), do: method.id <> "." <> name, else: "#{method.id}.#{name}"

    value =
      for {arg, type} <- arguments do
        %Types.Argument{
          name: arg,
          data_type: %NodeId{id: OPCUA.Binary.type_id(type)},
          value_rank: -1
        }
      end

    attributes = %{
      data_type: @argument,
      value_rank: 1,
      array_dimensions: [length(value)],
      access_level: 1,
      user_access_level: 1,
      minimum_sampling_interval: 0.0,
      historizing: false
    }

    add(
      server,
      %NodeId{ns: method.ns, id: id},
      :variable,
      %QualifiedName{ns: 0, name: name},
      [parent: method],
      attributes,
      %DataValue{value: %Variant{type: :extension_object, value: value}},
      @has_property,
      @property_type
    )
  end

  defp add(server, node, class, name, opts, attributes, value, reference, type_definition) do
    node_id = node_id(node)

    browse_name =
      case name do
        %QualifiedName{} -> name
        name -> %QualifiedName{ns: node_id.ns, name: name}
      end

    node = %Node{
      node_id: node_id,
      class: class,
      browse_name: browse_name,
      display_name: %LocalizedText{text: browse_name.name},
      description: if(text = opts[:description], do: %LocalizedText{text: text}),
      attributes: attributes
    }

    parent = node_id(Keyword.get(opts, :parent, @objects))
    reference = node_id(Keyword.get(opts, :reference, reference))
    GenServer.call(server, {:add, node, value, parent, reference, type_definition})
  end

  @doc """
  Sends an event to the clients that subscribe to events.

  ## Options

    * `:source` - the node it's about (default the Server object)
    * `:message`, `:severity` (1 to 1000, default 500)
    * `:type` - the event type (default BaseEventType, `i=2041`)
    * `:fields` - more fields, as `{"Path", %OPCUA.Variant{}}`
  """
  @spec event(GenServer.server(), keyword) :: :ok
  def event(server, opts \\ []), do: GenServer.call(server, {:event, opts})

  @doc """
  Adds an alarm: a condition (Part 9) on `:source`, off and acknowledged to
  begin with. Clients see it through events, and can acknowledge it.

  ## Options

    * `:source` - the node the alarm is about (required); it becomes an
      event notifier, so clients can subscribe to its events
    * `:message` - the alarm text (default the name)
    * `:severity` - 1 to 1000 (default 500)
    * `:type` - `:off_normal` (the default), `:alarm`, `:discrete`, or the
      node id of another condition type
    * `:acknowledge` - a function called with the comment when a client
      acknowledges; it returns `:ok`, or `{:error, status}` to refuse. It runs
      in the process of the client's connection.
  """
  @spec add_condition(GenServer.server(), node_ref, String.t(), keyword) :: :ok | {:error, atom}
  def add_condition(server, node, name, opts) do
    opts = Keyword.update!(opts, :source, &node_id/1)
    GenServer.call(server, {:add_condition, node_id(node), name, opts})
  end

  @doc """
  Changes an alarm: `active:`, `acked:`, `enabled:`, `severity:` or
  `message:`. Clients get an event when anything changed. An alarm that
  becomes active also becomes unacknowledged, unless `acked:` says otherwise.

      :ok = OPCUA.Server.condition(server, "ns=2;s=Pump1.Overload", active: true)
  """
  @spec condition(GenServer.server(), node_ref, keyword) :: :ok | {:error, atom}
  def condition(server, node, changes),
    do: GenServer.call(server, {:condition, node_id(node), changes})

  @doc """
  Sets the value of a variable, with the current time as its source
  timestamp. A `OPCUA.DataValue` is stored as given.

  Pass `space/1` instead of the server to set values without going through
  the server process, when they change often.
  """
  @spec set(server, node_ref, term) :: :ok
  def set(%AddressSpace{} = space, node, value) do
    node = node_id(node)

    value =
      case value do
        %DataValue{} ->
          value

        value ->
          %DataValue{
            value: %Variant{type: type(space, node), value: value},
            source_timestamp: DateTime.utc_now()
          }
      end

    variable = AddressSpace.get(space, node)

    # Checked here, so a bad value raises in the caller rather than
    # breaking the responses of clients that read it.
    if value.value do
      :ok = AddressSpace.check(space, variable, value.value)
      OPCUA.Binary.encode(value.value, :variant)
    end

    AddressSpace.put_value(space, node, value)
    :ok
  rescue
    MatchError ->
      reraise ArgumentError, "#{inspect(value)} doesn't fit variable #{node}", __STACKTRACE__
  end

  def set(server, node, value), do: set(space(server), node, value)

  defp type(space, node) do
    case AddressSpace.get(space, node) do
      %Node{class: :variable, attributes: %{data_type: %NodeId{ns: 0, id: id}}}
      when id in 1..25 ->
        OPCUA.Binary.type_name(id)

      _ ->
        raise ArgumentError, "no variable #{node} of a built-in type"
    end
  end

  @doc "The value of a variable, as an `OPCUA.DataValue`."
  @spec get(server, node_ref) :: DataValue.t()
  def get(%AddressSpace{} = space, node), do: AddressSpace.value(space, node_id(node))
  def get(server, node), do: get(space(server), node)

  @doc "The server's address space, to pass to `set/3` and `get/2`."
  @spec space(GenServer.server()) :: AddressSpace.t()
  def space(server), do: GenServer.call(server, :space)

  defp node_id(%NodeId{} = node), do: node
  defp node_id(text) when is_binary(text), do: NodeId.parse!(text)

  defp default(type) when type in [:float, :double], do: 0.0
  defp default(:boolean), do: false

  defp default(type) when type in [:string, :byte_string, :localized_text, :node_id, :date_time],
    do: nil

  defp default(_), do: 0

  ## The process

  @impl true
  def init(opts) do
    Process.flag(:trap_exit, true)
    port = Keyword.get(opts, :port, 4840)
    ip = Keyword.get(opts, :ip, {0, 0, 0, 0})

    with {:ok, listen} <-
           :gen_tcp.listen(port, [
             :binary,
             active: false,
             reuseaddr: true,
             ip: ip,
             nodelay: true,
             backlog: 128
           ]),
         {:ok, {_, port}} <- :inet.sockname(listen),
         {:ok, connections} <- DynamicSupervisor.start_link(strategy: :one_for_one) do
      {:ok, host} = :inet.gethostname()
      url = Keyword.get(opts, :endpoint_url, "opc.tcp://#{host}:#{port}")
      application_uri = Keyword.get(opts, :application_uri, "urn:yaopcua:server")
      space = AddressSpace.new()
      security = security(opts)

      {certificate, private_key} =
        case {opts[:certificate], opts[:private_key]} do
          {nil, _} ->
            # Only made when something needs it: making an RSA key takes a moment.
            if Enum.any?(security, &(&1 != {:none, :none})) or opts[:user_certificates],
              do:
                OPCUA.Certificate.self_signed(application_uri,
                  hostnames: [List.to_string(host), "localhost"]
                ),
              else: {nil, nil}

          pair ->
            pair
        end

      config = %{
        space: space,
        endpoint_url: url,
        application: %Types.ApplicationDescription{
          application_uri: application_uri,
          product_uri: "urn:yaopcua",
          application_name: %LocalizedText{text: Keyword.get(opts, :product_name, "yaopcua")},
          application_type: :server,
          discovery_urls: [url]
        },
        anonymous: Keyword.get(opts, :anonymous, true),
        users: Keyword.get(opts, :users),
        security: security,
        certificate: certificate,
        private_key: private_key,
        trust: Keyword.get(opts, :trust, []),
        user_certificates: opts[:user_certificates],
        # channel, token and subscription ids, unique across the server's connections
        ids: :atomics.new(3, signed: false),
        server: self()
      }

      namespaces = ["http://opcfoundation.org/UA/", application_uri]
      server_nodes(space, config, namespaces)
      server = self()
      acceptor = spawn_link(fn -> accept(listen, connections, config, server) end)

      {:ok,
       %{
         listen: listen,
         port: port,
         connections: connections,
         acceptor: acceptor,
         config: config,
         namespaces: namespaces
       }}
    else
      {:error, reason} -> {:stop, reason}
    end
  end

  # The values of the Server object that describe this server.
  defp server_nodes(space, config, namespaces) do
    started = DateTime.utc_now()

    build = %Types.BuildInfo{
      product_uri: config.application.product_uri,
      manufacturer_name: "yaopcua",
      product_name: config.application.application_name.text,
      software_version: to_string(Application.spec(:yaopcua, :vsn) || "0"),
      build_number: OPCUA.Schema.version(),
      build_date: started
    }

    status = fn ->
      %Variant{
        type: :extension_object,
        value: %Types.ServerStatusDataType{
          start_time: started,
          current_time: DateTime.utc_now(),
          state: :running,
          build_info: build
        }
      }
    end

    fixed = [
      {2254, %Variant{type: :string, value: [config.application.application_uri]}},
      {2255, %Variant{type: :string, value: namespaces}},
      {2257, %Variant{type: :date_time, value: started}},
      {2259, %Variant{type: :int32, value: 0}},
      {2260, %Variant{type: :extension_object, value: build}},
      {2261, %Variant{type: :string, value: build.product_name}},
      {2262, %Variant{type: :string, value: build.product_uri}},
      {2263, %Variant{type: :string, value: build.manufacturer_name}},
      {2264, %Variant{type: :string, value: build.software_version}},
      {2265, %Variant{type: :string, value: build.build_number}},
      {2266, %Variant{type: :date_time, value: started}},
      {2267, %Variant{type: :byte, value: 255}},
      {2992, %Variant{type: :uint32, value: 0}},
      {2993, %Variant{type: :localized_text, value: nil}}
    ]

    for {id, variant} <- fixed,
        do:
          AddressSpace.put_value(space, %NodeId{id: id}, %DataValue{
            value: variant,
            source_timestamp: started
          })

    AddressSpace.put_value(space, %NodeId{id: 2256}, {:read, status, :extension_object})
    AddressSpace.put_value(space, %NodeId{id: 2258}, {:read, &DateTime.utc_now/0, :date_time})

    # The Server object reports events.
    server = AddressSpace.get(space, %NodeId{id: 2253})
    :ets.insert(space.nodes, {server.node_id, put_in(server.attributes[:event_notifier], 1)})
  end

  defp accept(listen, connections, config, server) do
    case :gen_tcp.accept(listen) do
      {:ok, socket} ->
        case DynamicSupervisor.start_child(connections, {Connection, {config, socket}}) do
          {:ok, pid} ->
            :ok = :gen_tcp.controlling_process(socket, pid)
            send(pid, :go)

          _ ->
            :gen_tcp.close(socket)
        end

        accept(listen, connections, config, server)

      {:error, :closed} ->
        :ok

      {:error, reason} ->
        exit(reason)
    end
  end

  @impl true
  def handle_call(:port, _, state), do: {:reply, state.port, state}
  def handle_call(:endpoint_url, _, state), do: {:reply, state.config.endpoint_url, state}
  def handle_call(:space, _, state), do: {:reply, state.config.space, state}

  def handle_call({:namespace, uri}, _, state) do
    case Enum.find_index(state.namespaces, &(&1 == uri)) do
      nil ->
        namespaces = state.namespaces ++ [uri]

        value = %DataValue{
          value: %Variant{type: :string, value: namespaces},
          source_timestamp: DateTime.utc_now()
        }

        AddressSpace.put_value(state.config.space, %NodeId{id: 2255}, value)
        {:reply, length(namespaces) - 1, %{state | namespaces: namespaces}}

      index ->
        {:reply, index, state}
    end
  end

  def handle_call({:event, opts}, _, state) do
    space = state.config.space
    source = node_id(Keyword.get(opts, :source, %NodeId{id: 2253}))
    type = node_id(Keyword.get(opts, :type, %NodeId{id: 2041}))

    event =
      Events.new(
        space,
        type,
        source,
        opts[:message],
        Keyword.get(opts, :severity, 500),
        Keyword.get(opts, :fields, [])
      )

    broadcast(state, event)
    {:reply, :ok, state}
  end

  def handle_call({:add_condition, node, name, opts}, _, state) do
    {:reply, Conditions.add(state.config.space, node, name, opts), state}
  end

  def handle_call({:condition, node, changes}, _, state) do
    case Conditions.update(state.config.space, node, changes) do
      {:ok, event} ->
        broadcast(state, event)
        {:reply, :ok, state}

      :unchanged ->
        {:reply, :ok, state}

      error ->
        {:reply, error, state}
    end
  end

  def handle_call({:add, node, value, parent, reference, type_definition}, _, state) do
    {:reply,
     AddressSpace.add(state.config.space, node, value, parent, reference, type_definition), state}
  end

  @impl true
  def handle_info({:EXIT, _, reason}, state), do: {:stop, reason, state}

  # Every connection gets the event; each checks its own event items.
  defp broadcast(state, event) do
    for {_, pid, _, _} <- DynamicSupervisor.which_children(state.connections),
        is_pid(pid),
        do: send(pid, {:event, event})
  end

  @impl true
  def terminate(_, state) do
    :gen_tcp.close(state.listen)
    Process.exit(state.connections, :shutdown)
  end
end
