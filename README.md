# yaopcua

*Implemented by AI under the supervision of Tallak Tveide.*

Yet another OPC UA: a clean-room OPC UA stack in pure Elixir, for talking to
PLCs, SCADA systems and HMIs without running C inside the BEAM.

It implements a subset of what [open62541](https://github.com/open62541/open62541)
does, written from the OPC UA specification (free to read at
[reference.opcfoundation.org](https://reference.opcfoundation.org)) and the OPC
Foundation's machine-readable definitions, not from another stack's code. It
speaks the binary protocol over TCP only; the XML and JSON encodings are out.

**Status:** a client that reads, writes, browses, calls methods and subscribes
to value changes and events, without security yet. The server comes next; see
[the roadmap](#roadmap).

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
| `subscribe_events/2` | sends the subscriber the events a node reports, with the fields asked for |
| `unsubscribe/2` | ends a subscription; it also ends when the subscriber exits |
| `request/3` | sends any service request from `OPCUA.Types` |
| `endpoints/2` | asks a server which endpoints and logins it offers, without a session |

Log in with `user: {"operator", "secret"}`; anonymous is the default.

The client keeps the session alive and renews the secure channel before it
expires. When the connection drops it stops with `{:shutdown, reason}`, so run
it under a supervisor to reconnect.

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

The diff then shows the Foundation's own changes. The `.bsd` is XML, read with
OTP's xmerl while compiling; nothing reads XML at runtime.

## Tests

yaopcua is tested against [asyncua](https://github.com/FreeOpcUa/opcua-asyncio),
a Python OPC UA stack written independently of this one, in two ways:

* `test/vectors/asyncua.txt` holds about 1,200 structures encoded by asyncua.
  yaopcua must decode each one and encode it back to the same bytes. These run
  with every `mix test`; `test/vectors/generate_asyncua.py` regenerates them.
* The interop tests run the client against an asyncua server, started as a
  separate process from `test/support/asyncua_server.py`. They need a Python
  with asyncua, and are skipped without one:

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
| | Server: address space, callback variables, subscriptions, a reduced namespace 0 | Parts 3, 4, 5 |
| | Events and alarms: event filters, conditions, acknowledge, ConditionRefresh | Part 9 |
| | Security: Basic256Sha256 and Aes128_Sha256_RsaOaep, username and certificate login, with OTP's `:crypto` and `:public_key` only | Parts 2, 6, 7 |
| | PubSub: UADP over UDP, for PLC to PLC | Part 14 |

Out of scope: the XML and JSON encodings, HTTPS and WebSocket transports,
history, node management from clients, discovery servers and mDNS.
