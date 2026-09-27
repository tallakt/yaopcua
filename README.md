# yaopcua

*Implemented by AI under the supervision of Tallak Tveide.*

Yet another OPC UA: a clean-room OPC UA stack in pure Elixir, for talking to
PLCs, SCADA systems and HMIs without running C inside the BEAM.

It implements a subset of what [open62541](https://github.com/open62541/open62541)
does, written from the OPC UA specification (free to read at
[reference.opcfoundation.org](https://reference.opcfoundation.org)) and the OPC
Foundation's machine-readable definitions, not from another stack's code. It
speaks the binary protocol over TCP only; the XML and JSON encodings are out.

**Status:** a client and a server that read, write, browse, call methods,
subscribe to value changes and events, and handle alarms, over signed and
encrypted channels; and PubSub over UDP for PLC to PLC. Fuzzing comes next;
see [the roadmap](#roadmap).

## Client

```elixir
{:ok, client} = OPCUA.Client.start_link(url: "opc.tcp://10.0.0.5:4840")

{:ok, 1500} = OPCUA.Client.read(client, "ns=2;s=Pump1.Speed")
{:ok, [1.0, 2.0, 3.0]} = OPCUA.Client.read(client, "ns=2;s=Tank.Setpoints")
:ok = OPCUA.Client.write(client, "ns=2;s=Pump1.Speed", 1600)
{:ok, refs} = OPCUA.Client.browse(client, "ns=2;s=Plant")
{:ok, [42]} = OPCUA.Client.call(client, "ns=2;s=Plant", "ns=2;s=Multiply", [6, 7])

{:error, :bad_node_id_unknown} = OPCUA.Client.read(client, "ns=2;s=Nope")
```

Subscriptions send messages to the subscriber, the caller by default:

```elixir
{:ok, sub} = OPCUA.Client.subscribe(client, ["ns=2;s=Pump1.Speed", "ns=2;s=Tank.Level"], interval: 100)

# first the current values, then each change
receive do
  {OPCUA.Client, ^sub, {:value, "ns=2;s=Pump1.Speed", %OPCUA.DataValue{value: %{value: speed}}}} -> speed
end

{:ok, alarms} = OPCUA.Client.subscribe_events(client, fields: ["Message", "Severity", "ActiveState/Id"])

receive do
  {OPCUA.Client, ^alarms, {:event, %{"Message" => message, "Severity" => severity}}} -> {message, severity}
end
```

| Function | Does |
|---|---|
| `read/3` | reads one attribute of one node, the value by default, as a plain Elixir value |
| `read_many/3` | reads several nodes, with status and timestamps (`OPCUA.DataValue`) |
| `write/3`, `write_many/2` | writes plain values in the node's own type (the client reads the node once to learn it), or `OPCUA.Variant`s as given |
| `browse/3` | lists a node's references, following continuation points |
| `call/4` | calls a method and returns its outputs |
| `subscribe/3` | sends the subscriber each change of some values, optionally with a deadband |
| `subscribe_events/2` | sends the subscriber the events a node reports, with the fields asked for, optionally only of one type |
| `acknowledge/4`, `refresh/2` | acknowledges an alarm; asks for the standing alarms again (ConditionRefresh) |
| `unsubscribe/2` | ends a subscription; it also ends when the subscriber exits |
| `request/3` | sends any service request from `OPCUA.Types` |
| `endpoints/2` | asks a server which endpoints and logins it offers, without a session |

Log in with `user: {"operator", "secret"}` or `user: {:certificate, der, key}`;
anonymous is the default.

The client keeps the session alive and renews the secure channel before it
expires. When the connection drops it stops with `{:shutdown, reason}`, so run
it under a supervisor to reconnect.

## Server

```elixir
{:ok, server} = OPCUA.Server.start_link(port: 4840)
2 = OPCUA.Server.namespace(server, "urn:plant")

:ok = OPCUA.Server.add_object(server, "ns=2;s=Pump1", "Pump1")
:ok = OPCUA.Server.add_variable(server, "ns=2;s=Pump1.Speed", "Speed",
        parent: "ns=2;s=Pump1", type: :int16, value: 1500, writable: true)
:ok = OPCUA.Server.add_variable(server, "ns=2;s=Pump1.Temp", "Temp",
        parent: "ns=2;s=Pump1", type: :double, read: fn -> read_sensor() end)
:ok = OPCUA.Server.add_method(server, "ns=2;s=Pump1.Start", "Start",
        parent: "ns=2;s=Pump1", inputs: [{"speed", :int16}], outputs: [],
        call: fn [speed] -> start_pump(speed) && {:ok, []} end)

# from the application, whenever the value changes
:ok = OPCUA.Server.set(server, "ns=2;s=Pump1.Speed", 1510)
```

| Function | Does |
|---|---|
| `namespace/2` | the index of a namespace URI, adding it if new |
| `add_folder/4`, `add_object/4` | adds a folder or an object, under the Objects folder by default |
| `add_variable/4` | adds a variable with a stored value, or one read from a function each time; `:write` sees and may refuse each client write |
| `add_method/4` | adds a method; the function gets the inputs as plain values |
| `set/3`, `get/2` | sets and gets a value from the application; a value that doesn't fit raises |
| `event/2` | sends an event to the clients that subscribe to events |
| `add_condition/4`, `condition/3` | adds an alarm on a node, and changes it: active, acknowledged, enabled, severity, message |
| `space/1` | the address space itself, for `set/3` without going through the server process |

The server starts with all 5,500 standard nodes of namespace 0, and answers
GetEndpoints, FindServers, sessions (anonymous and username logins), Read,
Write, Browse and BrowseNext, TranslateBrowsePathsToNodeIds, Call,
RegisterNodes, and the subscription services: value changes with deadbands and
queues, keep-alives, lifetimes and Republish. Each client connection runs in
its own process.

### Alarms

An alarm is a condition (Part 9) on the node it's about. Clients see it
through events, and acknowledge it through the server, which asks the
application first:

```elixir
:ok = OPCUA.Server.add_condition(server, "ns=2;s=Pump1.Overload", "Overload",
        source: "ns=2;s=Pump1", severity: 700, message: "Pump 1 overload",
        acknowledge: fn comment -> MyPlant.acknowledge(:pump_overload, comment) end)

:ok = OPCUA.Server.condition(server, "ns=2;s=Pump1.Overload", active: true)
```

| The application | What clients get |
|---|---|
| `condition(..., active: true)` | an event with ActiveState true, AckedState false, Retain true |
| a client calls Acknowledge | the `:acknowledge` function, then an event with AckedState true and the comment |
| `condition(..., active: false)` | an event with ActiveState false, and Retain false once acknowledged |
| a client calls ConditionRefresh | the retained alarms again, between RefreshStart and RefreshEnd events |

Event filters take select clauses by browse path (including ConditionId) and
where clauses with OfType, And, Or, Not, the comparisons, Between, InList and
IsNull. Enable, Disable and AddComment work too; Confirm and shelving don't.

Not yet: history, and sessions that outlive their connection.

## Security

Both the client and the server sign, or sign and encrypt, their channels with
the current security policies, using only OTP's `:crypto` and `:public_key`:

| Policy | Name here |
|---|---|
| Basic256Sha256 | `:basic256sha256` |
| Aes128_Sha256_RsaOaep | `:aes128_sha256_rsa_oaep` |
| Aes256_Sha256_RsaPss | `:aes256_sha256_rsa_pss` |

```elixir
# once, and keep the files: peers trust a certificate, not a name
{cert, key} = OPCUA.Certificate.self_signed("urn:plant:server", hostnames: ["plc1.local"])
OPCUA.Certificate.write("server.der", cert)
OPCUA.Certificate.write_key("server.pem", key)

{:ok, server} = OPCUA.Server.start_link(
  security: [:basic256sha256, :aes256_sha256_rsa_pss],
  certificate: cert, private_key: key,
  trust: [OPCUA.Certificate.read("scada.der")],
  users: %{"operator" => "secret"})

{:ok, client} = OPCUA.Client.start_link(
  url: "opc.tcp://plc1.local:4840",
  security: {:aes256_sha256_rsa_pss, :sign_and_encrypt},
  trust: [OPCUA.Certificate.read("server.der")],
  certificate: scada_cert, private_key: scada_key,
  user: {"operator", "secret"})
```

| | Client | Server |
|---|---|---|
| Channels | the policy and mode asked for; the server's certificate must be in `:trust` | an endpoint per policy and mode in `:security`; the client's certificate must be in `:trust` |
| Sessions | checks the server's signature, signs its own | checks the client's signature and application URI, signs its own |
| Passwords | encrypted for the server whenever it asks, even over None | decrypted; over None it asks for its strongest policy |
| User certificates | signs with the user's key | accepts those in `:user_certificates` |

A secure client or server won't start without being told what to trust
(`:trust`, a list of certificates or `:any`). The deprecated Basic128Rsa15 and
Basic256 aren't supported.

## PubSub

For controller-to-controller data: a publisher sends datasets over UDP every
interval, to a multicast group or one host, and any number of subscribers
pick out the ones they want. There are no sessions, and nothing to answer.

```elixir
fields = [{"Speed", :int16}, {"Level", :double}, {"Running", :boolean}]

# on one PLC
{:ok, _} = OPCUA.PubSub.Publisher.start_link(
  url: "opc.udp://239.0.0.1:4840", publisher_id: 42, interval: 50,
  writers: [[id: 1, fields: fields, read: fn -> Pump.values() end]])

# on another
{:ok, _} = OPCUA.PubSub.Subscriber.start_link(
  url: "opc.udp://239.0.0.1:4840",
  readers: [[publisher_id: 42, writer_id: 1, fields: fields, timeout: 200]])

# which then gets, every 50 ms
{OPCUA.PubSub, {42, 1}, {:data, %{"Speed" => 1500, "Level" => 2.5, "Running" => true}}}
# and if the publisher goes quiet for 200 ms
{OPCUA.PubSub, {42, 1}, :timeout}
```

| Option | |
|---|---|
| `encoding:` | `:variant` (typed, the default), `:raw` (smallest; both ends must agree on the types) or `:data_value` (with status and timestamps) |
| `key_frames:` | every value each N-th cycle, and only the changed ones in between |
| `read:` or `Publisher.set/3` | where the publisher's values come from |

Messages are UADP (Part 14), checked against asyncua in both directions. Not
yet: message security, chunked messages, Ethernet (TSN) and MQTT transports.

## Encoding

Every structure and enumeration of the spec is a module under `OPCUA.Types`,
with the spec's field names in snake case:

```elixir
alias OPCUA.Types.{ReadRequest, ReadValueId, RequestHeader}

request = %ReadRequest{
  request_header: %RequestHeader{request_handle: 1, timeout_hint: 5000},
  timestamps_to_return: :both,
  nodes_to_read: [
    %ReadValueId{node_id: OPCUA.NodeId.parse!("ns=3;s=Pump1.Speed"), attribute_id: OPCUA.AttributeId.id(:value)}
  ]
}

bytes = request |> ReadRequest.encode() |> IO.iodata_to_binary()
{:ok, ^request, ""} = OPCUA.Binary.decode(bytes, ReadRequest)
```

A structure field left `nil`, like a missing `request_header`, is sent as that
structure's defaults, and comes back as the default struct.

The built-in types have their own structs and conventions:

| OPC UA | Elixir |
|---|---|
| Int32, Double, ... | numbers; NaN and infinities are `:nan`, `:infinity`, `:neg_infinity` |
| String, ByteString | binaries, `nil` when null |
| DateTime | UTC `DateTime` with microseconds, `nil` for 0 |
| Guid | `"72962B91-FA75-4AE6-8D28-B404DC7DAF63"` |
| NodeId | `%OPCUA.NodeId{ns: 3, id: "Pump1.Speed"}`, or `nil` for `i=0` |
| StatusCode | an integer; `OPCUA.StatusCode.name(0x80340000)` is `:bad_node_id_unknown` |
| Variant | `%OPCUA.Variant{type: :int16, value: 42}`, a list for arrays |
| DataValue | `%OPCUA.DataValue{value: variant, status: 0, source_timestamp: ...}` |
| ExtensionObject | the `OPCUA.Types` struct inside it, or `%OPCUA.ExtensionObject{}` for a type yaopcua doesn't know |
| Enumeration | an atom, such as `:both` |

`OPCUA.Binary` has the details, and `OPCUA.NodeIds` looks up the standard nodes
by name: `OPCUA.NodeIds.id("Server_ServerStatus")` is 2256.

## The spec version

The types are generated at compile time from the OPC Foundation's own files,
copied unmodified into `schema/` from one release of their
[UA-Nodeset](https://github.com/OPCFoundation/UA-Nodeset) repository:

| File | Gives |
|---|---|
| `Opc.Ua.Types.bsd` | the layout of every structure and enumeration |
| `Opc.Ua.NodeSet2.xml` | the standard nodes the server starts with |
| `NodeIds.csv` | the ids of the standard nodes, including each structure's wire id |
| `StatusCode.csv` | status code names and descriptions |
| `AttributeIds.csv` | attribute ids |
| `VERSION` | the release tag, e.g. `UA-1.05.07-2026-07-30` |

So each yaopcua version builds against exactly one OPC UA release, and
`OPCUA.Schema.version/0` says which. To move to another release, give its tag:

```
mix opcua.schema UA-1.05.07-2026-07-30
mix test
```

The diff then shows the Foundation's own changes. The `.bsd` and the NodeSet
are XML, read with OTP's xmerl while compiling; nothing reads XML at runtime.

## Tests

yaopcua is tested against [asyncua](https://github.com/FreeOpcUa/opcua-asyncio),
a Python OPC UA stack written independently of this one, in two ways:

* `test/vectors/asyncua.txt` holds about 1,200 structures encoded by asyncua.
  yaopcua must decode each one and encode it back to the same bytes. These run
  with every `mix test`; `test/vectors/generate_asyncua.py` regenerates them.
* The interop tests run the client against an asyncua server, and asyncua's
  client against the server, as separate processes from `test/support/`,
  with and without every security policy and mode. They need a Python with
  asyncua, and are skipped without one:

  ```
  python3 -m venv ~/.venvs/asyncua && ~/.venvs/asyncua/bin/pip install asyncua
  ASYNCUA_PYTHON=~/.venvs/asyncua/bin/python mix test
  ```

Python only ever runs in tests, never inside yaopcua.

## Roadmap

| | Feature | Spec |
|---|---|---|
| ✅ | Binary encoding of the built-in types and all generated structures | Part 6 |
| ✅ | UA-TCP transport, secure channel (policy None), sessions | Parts 4, 6 |
| ✅ | Client: read, write, browse, method calls, anonymous and username login | Part 4 |
| ✅ | Client: subscriptions to value changes and events | Part 4 |
| | Client: custom structures, reconnecting | Part 4 |
| ✅ | Server: address space with namespace 0, callback variables, methods, subscriptions | Parts 3, 4, 5 |
| ✅ | Events and alarms in the server: event filters, conditions, acknowledge, ConditionRefresh | Parts 4, 9 |
| ✅ | Security: Basic256Sha256, Aes128_Sha256_RsaOaep and Aes256_Sha256_RsaPss, encrypted passwords and certificate logins, with OTP's `:crypto` and `:public_key` only | Parts 2, 4, 6, 7 |
| ✅ | PubSub: UADP over UDP, unicast and multicast, key and delta frames | Part 14 |
| | Fuzzing with [StreamData](https://github.com/whatyouhide/stream_data): random and mutated bytes into the decoder, the secure channel and the server | |

Out of scope: the XML and JSON encodings, HTTPS and WebSocket transports,
history, node management from clients, discovery servers and mDNS.
