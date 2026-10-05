# Changelog

## Unreleased

### Changed

- `OPCUA.Client.call/4` sends plain arguments as the types the method
  declares, read once from its InputArguments and remembered, the way
  `write/3` sends values as the node's type. Strict servers such as
  open62541 refused a plain 700 for a UInt16 argument, sent as Int32. A
  value that doesn't fit is `{:error, :bad_type_mismatch}`; variants go as
  given, and where a method leaves a type open, plain values go as before.
- The client checks that a server's certificate names the application URI
  the server presents (`:bad_certificate_uri_invalid`), and, when it's
  trusted through a CA, the host in the URL
  (`:bad_certificate_host_name_invalid`). `verify: [uri: false]` or
  `verify: [host_name: true | false]` changes that; `:server_uri` names the
  URI to expect. The certificate a server answers CreateSession with must be
  the channel's.
- `OPCUA.Server` presents its certificate's application URI unless
  `:application_uri` is given, and refuses to start with one the
  certificate doesn't name.

### Added

- `OPCUA.Certificate.names_host?/2`.
- Interop tests against open62541, with and without security, and against the
  Prosys OPC UA Simulation Server (`mix test --only prosys`).

### Fixed

- A username or certificate login used the first token policy the server
  listed for it, and failed with `:bad_security_policy_rejected` when that
  was one the client doesn't have; servers such as Prosys's list Basic256
  before Basic256Sha256. It now uses the first the client has.

- The spec of `OPCUA.Client.request/3` allows its default timeout of `nil`;
  Dialyzer took every client function that calls it to never return.

### Changed

- CI runs Credo and Dialyzer, and fails below 80% test coverage. Functions
  Credo found too complex or too deeply nested are split up, with no change
  in what they do.

## 0.2.0

### Added

- `OPCUA.Server`: `listen: false` and `listen/1`, to build the address space
  before opening the port; `delete/2`, to remove a node and what it holds;
  `info/1`, the connections and sessions there are.
- `add_folder/4` and `add_object/4` take `event_notifier: true`, for objects
  clients subscribe to events of, one below another by HasNotifier.
- `add_variable/4` takes `units:` and `range:`, as EngineeringUnits and
  EURange properties of an AnalogItem. Subscriptions take percent deadbands
  on such variables.
- Conditions: an `enable:` function hears of Enable and Disable first and
  may refuse them; `suppressed:` shows as SuppressedState; a disabled
  condition reports no events until it's enabled again.
- `OPCUA.PubSub.Publisher`: `interval: 0` and `publish/1`, to send when the
  application says, such as at the end of a PLC scan.
- Limits on what clients can take (`:limits` of `OPCUA.Server`): connections,
  message size, memory per connection, sessions, subscriptions and
  monitored items, and timeouts for opening a channel and a session.
- Runs on Elixir 1.15 and later (0.1.0 needed 1.18), checked by CI.

### Security

- Event filters whose elements refer to themselves, backwards or past the
  end are refused, and each element is evaluated once, so a filter can't
  loop or grow exponentially.
- Structures nested in ExtensionObjects are decoded at most 100 deep, in
  time linear in their size.
- A secure channel refuses a certificate it doesn't trust, or with a key
  outside 2048 to 4096 bits, before any RSA; so does a client, of a server.
- Unfinished messages together are held to the limit of one.
- Timers, one per session and one per channel token, however many requests
  and renewals come.
- Passwords are compared in constant time; index ranges are refused past 40
  characters; the acceptor survives running out of file descriptors.
- The subscriber holds at most 100 datagrams in its mailbox, and the client
  reads its socket a packet at a time.
- The client takes only the response type a request asks for, keeps the
  durations a server gives within bounds, and treats a plain value that
  doesn't fit a node's type as a mismatch rather than raising.

### Fixed

- A raw UADP dataset for a reader without field types no longer crashes the
  subscriber, and raw field types are looked up per publisher.
- A null or array method argument is a type mismatch, and so is an array
  where Acknowledge, AddComment or ConditionRefresh take one value.
- `add_condition/4` takes a condition type as a node id string.

## 0.1.0

The first release: the binary encoding, UA-TCP and secure channels with
Basic256Sha256, Aes128_Sha256_RsaOaep and Aes256_Sha256_RsaPss, a client, a
server with subscriptions, events and alarms, and PubSub over UDP.
