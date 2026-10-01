# Changelog

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

## 0.1.1

- Runs on Elixir 1.15 and later, checked by CI.

## 0.1.0

The first release: the binary encoding, UA-TCP and secure channels with
Basic256Sha256, Aes128_Sha256_RsaOaep and Aes256_Sha256_RsaPss, a client, a
server with subscriptions, events and alarms, and PubSub over UDP.
