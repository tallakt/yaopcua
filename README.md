# yaopcua

*Implemented by AI under the supervision of Tallak Tveide.*

Yet another OPC UA: a clean-room OPC UA stack in pure Elixir, for talking to
PLCs, SCADA systems and HMIs without running C inside the BEAM.

It implements a subset of what [open62541](https://github.com/open62541/open62541)
does, written from the OPC UA specification (free to read at
[reference.opcfoundation.org](https://reference.opcfoundation.org)) and the OPC
Foundation's machine-readable definitions, not from another stack's code. It
speaks the binary protocol over TCP only; the XML and JSON encodings are out.

**Status:** the binary encoding is done. Connections, the client and the server
come next; see [the roadmap](#roadmap).

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

Besides unit tests built from the spec's rules, `test/vectors/asyncua.txt`
holds about 1,200 structures encoded by
[asyncua](https://github.com/FreeOpcUa/opcua-asyncio), a Python stack written
independently of this one. yaopcua must decode each one and encode it back to
the same bytes. `test/vectors/generate_asyncua.py` regenerates them; asyncua
itself is only needed for that, not to run the tests.

## Roadmap

| | Feature | Spec |
|---|---|---|
| ✅ | Binary encoding of the built-in types and all generated structures | Part 6 |
| | UA-TCP transport, secure channel (policy None), sessions | Parts 4, 6 |
| | Client: read, write, browse, subscriptions, method calls, custom structures | Part 4 |
| | Server: address space, callback variables, subscriptions, a reduced namespace 0 | Parts 3, 4, 5 |
| | Events and alarms: event filters, conditions, acknowledge, ConditionRefresh | Part 9 |
| | Security: Basic256Sha256 and Aes128_Sha256_RsaOaep, username and certificate login, with OTP's `:crypto` and `:public_key` only | Parts 2, 6, 7 |
| | PubSub: UADP over UDP, for PLC to PLC | Part 14 |

Out of scope: the XML and JSON encodings, HTTPS and WebSocket transports,
history, node management from clients, discovery servers and mDNS.
