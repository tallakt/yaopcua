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
  views; only built-in data types for variables; no access rights per
  user; and most of namespace 0 has no values. See "What's missing" in the
  README.

  ## Limits

  A client, or someone posing as one, can't take more than `:limits`
  allows, so that clients can't exhaust the machine the server runs on:

    * `:connections` - open connections (default 32); more are refused
    * `:message_size` - bytes in one request (default 4 MB); a message
      decodes to up to 16 times its size in memory
    * `:connection_memory` - bytes the process of one connection may take
      (default 256 MB); a connection that needs more is closed
    * `:sessions` - per connection (default 10)
    * `:subscriptions` - per session (default 50)
    * `:monitored_items` - per session (default 50,000)
    * `:open_timeout` - ms a connection has to open its secure channel
      (default 10 seconds)
    * `:session_wait` - ms a connection may go without an activated session
      (default a minute)

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
    * `:listen` - false to start without listening, until `listen/1`
      (default true): the address space is there to build meanwhile
    * `:ip` - the address to listen on (default all)
    * `:endpoint_url` - the URL the server gives clients (default
      `opc.tcp://<hostname>:<port>`)
    * `:application_uri`, `:product_name` - how the server presents itself;
      the application URI is the certificate's by default, or
      `"urn:yaopcua:server"`, and must be the one the certificate names
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
    * `:limits` - see Limits above
    * `:name` - to register the process
  """

  use GenServer

  require Logger

  alias OPCUA.{DataValue, LocalizedText, NodeId, NodeIds, QualifiedName, Transport, Variant}
  alias OPCUA.Server.{AddressSpace, Conditions, Connection, Events, Node}
  alias OPCUA.Types

  @objects NodeIds.node_id!("ObjectsFolder")
  @server NodeIds.node_id!("Server")
  @organizes NodeIds.node_id!("Organizes")
  @has_component NodeIds.node_id!("HasComponent")
  @has_property NodeIds.node_id!("HasProperty")
  @folder_type NodeIds.node_id!("FolderType")
  @base_object_type NodeIds.node_id!("BaseObjectType")
  @base_data_variable_type NodeIds.node_id!("BaseDataVariableType")
  @property_type NodeIds.node_id!("PropertyType")
  @argument NodeIds.node_id!("Argument")
  @base_event_type NodeIds.node_id!("BaseEventType")
  @namespace_array NodeIds.node_id!("Server_NamespaceArray")

  @analog_item_type NodeIds.node_id!("AnalogItemType")
  @eu_information NodeIds.node_id!("EUInformation")
  @range NodeIds.node_id!("Range")

  @readable Types.AccessLevelType.mask([:current_read])
  @writable Types.AccessLevelType.mask([:current_read, :current_write])
  @subscribe_to_events Types.EventNotifierType.mask([:subscribe_to_events])

  # Where UNECE unit codes are defined (Part 8, 5.6.3).
  @units_uri "http://www.opcfoundation.org/UA/units/un/cefact"

  # Ids unique across the server's connections, each counted in its own
  # slot of an :atomics array.
  @ids %{channel: 1, token: 2, subscription: 3}

  @limits [
    connections: 32,
    message_size: 4 * 1024 * 1024,
    connection_memory: 256 * 1024 * 1024,
    sessions: 10,
    subscriptions: 50,
    monitored_items: 50_000,
    open_timeout: 10_000,
    session_wait: 60_000
  ]

  @typedoc "A server's address space, from `space/1`."
  @opaque space :: AddressSpace.t()
  @type server :: GenServer.server() | space
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

    # Clients check that the certificate names the URI the server presents.
    with cert when is_binary(cert) <- opts[:certificate],
         uri when is_binary(uri) <- opts[:application_uri],
         named when is_binary(named) and named != uri <- OPCUA.Certificate.application_uri(cert) do
      raise ArgumentError,
            "the certificate names the application URI #{inspect(named)}, " <>
              "but :application_uri is #{inspect(uri)}"
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

  @doc "The port the server listens on, or `nil` before it listens."
  @spec port(GenServer.server()) :: :inet.port_number() | nil
  def port(server), do: GenServer.call(server, :port)

  @doc "The endpoint URL clients connect to, or `nil` before the server listens."
  @spec endpoint_url(GenServer.server()) :: String.t() | nil
  def endpoint_url(server), do: GenServer.call(server, :endpoint_url)

  @doc """
  Starts listening, for a server started with `listen: false`. Does nothing
  for one that listens already.
  """
  @spec listen(GenServer.server()) :: :ok | {:error, term}
  def listen(server), do: GenServer.call(server, :listen)

  @doc "How many clients are connected, and how many sessions they have."
  @spec info(GenServer.server()) :: %{connections: non_neg_integer, sessions: non_neg_integer}
  def info(server) do
    connections = GenServer.call(server, :connections)

    # Asked here rather than by the server, so a busy connection holds up
    # only the caller.
    sessions =
      for pid <- connections do
        try do
          GenServer.call(pid, :sessions, 1000)
        catch
          :exit, _gone_or_busy -> 0
        end
      end

    %{connections: length(connections), sessions: Enum.sum(sessions)}
  end

  @doc """
  The index of a namespace, adding it if it's new. Index 0 is the OPC UA
  namespace and 1 the server's own; the application's start at 2.
  """
  @spec namespace(GenServer.server(), String.t()) :: non_neg_integer
  def namespace(server, uri), do: GenServer.call(server, {:namespace, uri})

  @doc """
  Adds a folder, organized under `:parent` (default the Objects folder).

  ## Options

    * `:parent` - the folder or object it's in
    * `:reference` - the reference from the parent (default Organizes)
    * `:event_notifier` - true for one that clients can subscribe to events
      of: the events of its own, and of the nodes below it by HasNotifier or
      HasEventSource. `reference: "i=48"` (HasNotifier) puts one notifier
      below another.
    * `:description` - text for clients
  """
  @spec add_folder(GenServer.server(), node_ref, String.t(), keyword) :: :ok | {:error, atom}
  def add_folder(server, node, name, opts \\ []) do
    add(server, node, name, opts,
      class: :object,
      attributes: %{event_notifier: notifier(opts)},
      reference: @organizes,
      type_definition: @folder_type
    )
  end

  @doc """
  Adds an object, organized under `:parent` (default the Objects folder).
  `:type_definition` sets its object type (default BaseObjectType); the
  other options are `add_folder/4`'s.
  """
  @spec add_object(GenServer.server(), node_ref, String.t(), keyword) :: :ok | {:error, atom}
  def add_object(server, node, name, opts \\ []) do
    add(server, node, name, opts,
      class: :object,
      attributes: %{event_notifier: notifier(opts)},
      reference: @organizes,
      type_definition: node_id(Keyword.get(opts, :type_definition, @base_object_type))
    )
  end

  defp notifier(opts), do: if(opts[:event_notifier], do: @subscribe_to_events, else: 0)

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
    * `:units` - `{code, symbol}`: its unit as a UNECE code and how it shows,
      such as `{"CEL", "°C"}`, in an EngineeringUnits property
    * `:range` - `{low, high}`: what its value normally is, in an EURange
      property, which percent deadbands go by

  A variable with `:units` or `:range` is an AnalogItem.
  """
  @spec add_variable(GenServer.server(), node_ref, String.t(), keyword) :: :ok | {:error, atom}
  def add_variable(server, node, name, opts) do
    type = Keyword.fetch!(opts, :type)
    initial = Keyword.get_lazy(opts, :value, fn -> OPCUA.Binary.default(type) end)
    attributes = variable_attributes(opts, type, initial)
    {reference, type_definition} = variable_kind(opts)
    variable = node_id(node)

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

    with :ok <-
           add(server, variable, name, opts,
             class: :variable,
             attributes: attributes,
             value: value,
             reference: reference,
             type_definition: type_definition
           ),
         :ok <- units(server, variable, opts[:units]) do
      range(server, variable, opts[:range])
    end
  end

  defp variable_attributes(opts, type, initial) do
    array = is_list(initial) or Keyword.get(opts, :array, false)
    access = if Keyword.get(opts, :writable, false), do: @writable, else: @readable

    attributes = %{
      data_type: %NodeId{id: OPCUA.Binary.type_id(type)},
      value_rank: if(array, do: 1, else: -1),
      array_dimensions: if(array, do: [0]),
      access_level: access,
      user_access_level: access,
      minimum_sampling_interval: 0.0,
      historizing: false
    }

    if write = opts[:write], do: Map.put(attributes, :write, write), else: attributes
  end

  # A property, an AnalogItem (one with units or a range), or a plain variable.
  defp variable_kind(opts) do
    cond do
      opts[:property] -> {@has_property, @property_type}
      opts[:units] != nil or opts[:range] != nil -> {@has_component, @analog_item_type}
      true -> {@has_component, @base_data_variable_type}
    end
  end

  defp units(_server, _variable, nil), do: :ok

  defp units(server, variable, {code, symbol}) when is_binary(code) and is_binary(symbol) do
    units = %Types.EUInformation{
      namespace_uri: @units_uri,
      unit_id: code |> String.to_charlist() |> Enum.reduce(0, &(&2 * 256 + &1)),
      display_name: %LocalizedText{text: symbol},
      description: %LocalizedText{text: symbol}
    }

    property(server, variable, "EngineeringUnits", @eu_information, units)
  end

  defp range(_server, _variable, nil), do: :ok

  defp range(server, variable, {low, high}) when is_number(low) and is_number(high),
    do: property(server, variable, "EURange", @range, %Types.Range{low: low / 1, high: high / 1})

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
           add(server, method, name, opts,
             class: :method,
             attributes: attributes,
             reference: @has_component
           ),
         :ok <- arguments(server, method, "InputArguments", inputs) do
      arguments(server, method, "OutputArguments", outputs)
    end
  end

  defp arguments(_, _, _, []), do: :ok

  defp arguments(server, method, name, arguments) do
    value =
      for {arg, type} <- arguments do
        %Types.Argument{
          name: arg,
          data_type: %NodeId{id: OPCUA.Binary.type_id(type)},
          value_rank: -1
        }
      end

    property(server, method, name, @argument, value)
  end

  # A standard property of a node, such as a method's InputArguments: a
  # structure, or a list of them, at `<node id>.<name>`.
  defp property(server, parent, name, data_type, value) do
    id = if is_binary(parent.id), do: parent.id <> "." <> name, else: "#{parent.id}.#{name}"
    array = is_list(value)

    attributes = %{
      data_type: data_type,
      value_rank: if(array, do: 1, else: -1),
      array_dimensions: if(array, do: [length(value)]),
      access_level: @readable,
      user_access_level: @readable,
      minimum_sampling_interval: 0.0,
      historizing: false
    }

    add(
      server,
      %NodeId{ns: parent.ns, id: id},
      %QualifiedName{ns: 0, name: name},
      [parent: parent],
      class: :variable,
      attributes: attributes,
      value: %DataValue{value: %Variant{type: :extension_object, value: value}},
      reference: @has_property,
      type_definition: @property_type
    )
  end

  @doc """
  Removes a node and what it holds: the nodes below it by hierarchical
  references, such as a folder's contents, a variable's properties and a
  method's arguments. The conditions of a source stay; remove them too.
  Monitored items on a removed node read BadNodeIdUnknown. Nodes of
  namespace 0 can't be removed.
  """
  @spec delete(GenServer.server(), node_ref) ::
          :ok | {:error, :bad_node_id_unknown | :bad_no_delete_rights}
  def delete(server, node), do: GenServer.call(server, {:delete, node_id(node)})

  # `opts` are the caller's, and `spec` what the kind of node brings: its
  # class, attributes, value, reference from its parent and type definition.
  defp add(server, node, name, opts, spec) do
    node_id = node_id(node)

    browse_name =
      case name do
        %QualifiedName{} -> name
        name -> %QualifiedName{ns: node_id.ns, name: name}
      end

    node = %Node{
      node_id: node_id,
      class: Keyword.fetch!(spec, :class),
      browse_name: browse_name,
      display_name: %LocalizedText{text: browse_name.name},
      description: if(text = opts[:description], do: %LocalizedText{text: text}),
      attributes: Keyword.fetch!(spec, :attributes)
    }

    parent = node_id(Keyword.get(opts, :parent, @objects))
    reference = node_id(Keyword.get(opts, :reference, Keyword.fetch!(spec, :reference)))
    GenServer.call(server, {:add, node, spec[:value], parent, reference, spec[:type_definition]})
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
    * `:enable` - a function called with `false` when a client disables the
      condition, and `true` when it enables it, which returns `:ok`, or
      `{:error, status}` to refuse, such as `:bad_not_supported`; also in
      the client's connection. Without it clients may do either.

  A disabled condition reports no events until it's enabled again.
  """
  @spec add_condition(GenServer.server(), node_ref, String.t(), keyword) :: :ok | {:error, atom}
  def add_condition(server, node, name, opts) do
    opts =
      opts
      |> Keyword.update!(:source, &node_id/1)
      |> Keyword.update(:type, :off_normal, &condition_type/1)

    GenServer.call(server, {:add_condition, node_id(node), name, opts})
  end

  defp condition_type(type) when type in [:off_normal, :alarm, :discrete], do: type
  defp condition_type(type), do: node_id(type)

  @doc """
  Changes an alarm: `active:`, `acked:`, `enabled:`, `suppressed:`,
  `severity:` or `message:`. Clients get an event when anything changed,
  unless the alarm is disabled. An alarm that becomes active also becomes
  unacknowledged, unless `acked:` says otherwise.

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

    # Checked here, so a bad value raises in the caller rather than
    # breaking the responses of clients that read it.
    _ =
      case AddressSpace.get(space, node) do
        %Node{class: :variable} = variable when value.value != nil ->
          if AddressSpace.check(space, variable, value.value) != :ok,
            do: raise(ArgumentError, "#{inspect(value.value)} doesn't fit variable #{node}")

          # This raises for a value outside its type, such as 300 as a Byte.
          OPCUA.Binary.encode(value.value, :variant)

        %Node{class: :variable} ->
          :ok

        _ ->
          raise ArgumentError, "no variable #{node}"
      end

    AddressSpace.put_value(space, node, value)
    :ok
  end

  def set(server, node, value), do: set(space(server), node, value)

  @doc """
  Stores an `OPCUA.DataValue` as the value of a variable, as it is. Nothing is
  checked: a value that doesn't fit the variable, or a node that isn't one,
  breaks the responses of the clients that read it, where `set/3` raises here.

  For an application that has checked its values itself and sets many of
  them often, each scan of a control program for one, with `space/1`: what
  `set/3` checks is most of what setting a value costs.
  """
  @spec put(server, node_ref, DataValue.t()) :: :ok
  def put(%AddressSpace{} = space, node, %DataValue{} = value) do
    AddressSpace.put_value(space, node_id(node), value)
    :ok
  end

  def put(server, node, %DataValue{} = value), do: put(space(server), node, value)

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
  @spec space(GenServer.server()) :: space
  def space(server), do: GenServer.call(server, :space)

  defp node_id(%NodeId{} = node), do: node
  defp node_id(text) when is_binary(text), do: NodeId.parse!(text)

  @doc false
  # A new channel, token or subscription id.
  def next_id(config, kind), do: :atomics.add_get(config.ids, Map.fetch!(@ids, kind), 1)

  ## The process

  @impl true
  def init(opts) do
    Process.flag(:trap_exit, true)
    limits = Map.new(Keyword.merge(@limits, Keyword.get(opts, :limits, [])))

    case DynamicSupervisor.start_link(strategy: :one_for_one, max_children: limits.connections) do
      {:ok, connections} -> init(opts, limits, connections)
      {:error, reason} -> {:stop, reason}
    end
  end

  defp init(opts, limits, connections) do
    {:ok, host} = :inet.gethostname()

    application_uri =
      opts[:application_uri] ||
        (opts[:certificate] && OPCUA.Certificate.application_uri(opts[:certificate])) ||
        "urn:yaopcua:server"

    space = AddressSpace.new()
    security = security(opts)
    {certificate, private_key} = own_certificate(opts, security, application_uri, host)

    config = %{
      space: space,
      # Known once the server listens.
      endpoint_url: nil,
      application: %Types.ApplicationDescription{
        application_uri: application_uri,
        product_uri: "urn:yaopcua",
        application_name: %LocalizedText{text: Keyword.get(opts, :product_name, "yaopcua")},
        application_type: :server,
        discovery_urls: []
      },
      anonymous: Keyword.get(opts, :anonymous, true),
      users: Keyword.get(opts, :users),
      security: security,
      certificate: certificate,
      private_key: private_key,
      trust: Keyword.get(opts, :trust, []),
      user_certificates: opts[:user_certificates],
      ids: :atomics.new(map_size(@ids), signed: false),
      limits: limits,
      server: self()
    }

    namespaces = ["http://opcfoundation.org/UA/", application_uri]
    server_nodes(space, config, namespaces)

    state = %{
      listen: nil,
      port: nil,
      acceptor: nil,
      connections: connections,
      config: config,
      namespaces: namespaces,
      host: List.to_string(host),
      socket: Keyword.take(opts, [:port, :ip, :endpoint_url])
    }

    if Keyword.get(opts, :listen, true), do: started(open(state)), else: {:ok, state}
  end

  defp started({:ok, state}), do: {:ok, state}
  defp started({:error, reason}), do: {:stop, reason}

  # The server's certificate and key, given or, only when something needs them, made: making an
  # RSA key takes a moment.
  defp own_certificate(opts, security, application_uri, host) do
    case {opts[:certificate], opts[:private_key]} do
      {nil, _} ->
        if Enum.any?(security, &(&1 != {:none, :none})) or opts[:user_certificates],
          do:
            OPCUA.Certificate.self_signed(application_uri,
              hostnames: [List.to_string(host), "localhost"]
            ),
          else: {nil, nil}

      pair ->
        pair
    end
  end

  # The listening socket, and an acceptor handing each connection to a
  # process of its own. The endpoint URL is known from here on.
  defp open(state) do
    port = Keyword.get(state.socket, :port, 4840)
    ip = Keyword.get(state.socket, :ip, {0, 0, 0, 0})
    options = [:binary, active: false, reuseaddr: true, ip: ip, nodelay: true, backlog: 128]

    with {:ok, listen} <- :gen_tcp.listen(port, options),
         {:ok, {_, port}} <- :inet.sockname(listen) do
      url = Keyword.get(state.socket, :endpoint_url, "opc.tcp://#{state.host}:#{port}")

      config = %{
        state.config
        | endpoint_url: url,
          application: %{state.config.application | discovery_urls: [url]}
      }

      acceptor = spawn_link(fn -> accept(listen, state.connections, config) end)
      {:ok, %{state | listen: listen, port: port, acceptor: acceptor, config: config}}
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

    info = "Server_ServerStatus_BuildInfo_"

    fixed = [
      {"Server_ServerArray", :string, [config.application.application_uri]},
      {"Server_NamespaceArray", :string, namespaces},
      {"Server_ServerStatus_StartTime", :date_time, started},
      {"Server_ServerStatus_State", :int32, 0},
      {"Server_ServerStatus_BuildInfo", :extension_object, build},
      {info <> "ProductName", :string, build.product_name},
      {info <> "ProductUri", :string, build.product_uri},
      {info <> "ManufacturerName", :string, build.manufacturer_name},
      {info <> "SoftwareVersion", :string, build.software_version},
      {info <> "BuildNumber", :string, build.build_number},
      {info <> "BuildDate", :date_time, started},
      {"Server_ServiceLevel", :byte, 255},
      {"Server_ServerStatus_SecondsTillShutdown", :uint32, 0},
      {"Server_ServerStatus_ShutdownReason", :localized_text, nil}
    ]

    for {name, type, value} <- fixed do
      AddressSpace.put_value(space, NodeIds.node_id!(name), %DataValue{
        value: %Variant{type: type, value: value},
        source_timestamp: started
      })
    end

    AddressSpace.put_value(
      space,
      NodeIds.node_id!("Server_ServerStatus"),
      {:read, status, :extension_object}
    )

    AddressSpace.put_value(
      space,
      NodeIds.node_id!("Server_ServerStatus_CurrentTime"),
      {:read, &DateTime.utc_now/0, :date_time}
    )

    AddressSpace.notify_events(space, @server)
  end

  defp accept(listen, connections, config) do
    case :gen_tcp.accept(listen) do
      {:ok, socket} ->
        case DynamicSupervisor.start_child(connections, {Connection, {config, socket}}) do
          {:ok, pid} ->
            :ok = :gen_tcp.controlling_process(socket, pid)
            send(pid, :go)

          {:error, :max_children} ->
            error = Transport.error(:bad_max_connections_reached, "too many connections")
            _ = :gen_tcp.send(socket, Transport.frame(:error, :final, error))
            :gen_tcp.close(socket)

          _ ->
            :gen_tcp.close(socket)
        end

        accept(listen, connections, config)

      {:error, :closed} ->
        :ok

      # Out of file descriptors, say: the server goes on, and accepts again
      # when connections have closed.
      {:error, reason} ->
        Logger.warning("OPC UA server can't accept a connection: #{inspect(reason)}")
        Process.sleep(100)
        accept(listen, connections, config)
    end
  end

  @impl true
  def handle_call(:listen, _, %{listen: nil} = state) do
    case open(state) do
      {:ok, state} -> {:reply, :ok, state}
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call(:listen, _, state), do: {:reply, :ok, state}

  def handle_call(:connections, _, state) do
    pids =
      for {_, pid, _, _} <- DynamicSupervisor.which_children(state.connections),
          is_pid(pid),
          do: pid

    {:reply, pids, state}
  end

  def handle_call({:delete, node}, _, state),
    do: {:reply, AddressSpace.delete(state.config.space, node), state}

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

        AddressSpace.put_value(state.config.space, @namespace_array, value)
        {:reply, length(namespaces) - 1, %{state | namespaces: namespaces}}

      index ->
        {:reply, index, state}
    end
  end

  def handle_call({:event, opts}, _, state) do
    space = state.config.space
    source = node_id(Keyword.get(opts, :source, @server))
    type = node_id(Keyword.get(opts, :type, @base_event_type))

    event =
      Events.new(
        space,
        type,
        source,
        opts[:message],
        Keyword.get(opts, :severity, 500),
        Keyword.get(opts, :fields, [])
      )

    _ = broadcast(state, event)
    {:reply, :ok, state}
  end

  def handle_call({:add_condition, node, name, opts}, _, state) do
    {:reply, Conditions.add(state.config.space, node, name, opts), state}
  end

  def handle_call({:condition, node, changes}, _, state) do
    case Conditions.update(state.config.space, node, changes) do
      {:ok, event} ->
        _ = broadcast(state, event)
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
    if state.listen, do: :gen_tcp.close(state.listen)
    Process.exit(state.connections, :shutdown)
  end
end
