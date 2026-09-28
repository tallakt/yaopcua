defmodule OPCUA.Server.Session do
  @moduledoc false
  # A session on a server connection, kept in the connection process by its
  # authentication token (see OPCUA.Server.Services), with its subscriptions
  # (see OPCUA.Server.Subscriptions).

  alias OPCUA.Server.Session.Subscription

  defstruct [
    :id,
    # The authentication token that requests carry.
    :auth,
    :name,
    # ms without a request before the session ends
    :timeout,
    # For the client to sign when it activates the session.
    :nonce,
    # When the last request came, which the timeout counts from.
    :last,
    activated: false,
    # :anonymous, a user name, or the application URI of a user certificate
    user: nil,
    # Browse continuation points: {references left, max per result} by point.
    continuation: %{},
    subscriptions: %{},
    # Publish requests waiting for something to send, oldest first.
    publishes: [],
    # {subscription id, status} for subscriptions that ended, still to be
    # told in a StatusChangeNotification.
    status_changes: [],
    # {request id, response} still to send, newest first: responses that
    # don't answer the request at hand, such as a Publish answered by a timer.
    outbox: []
  ]

  @type t :: %__MODULE__{subscriptions: %{pos_integer => Subscription.t()}}

  defmodule Subscription do
    @moduledoc false

    alias OPCUA.Server.Session.MonitoredItem

    defstruct [
      :id,
      # ms between publishing cycles
      :interval,
      :keep_alive_count,
      :lifetime_count,
      # Kept but not used; see Subscriptions.revise/2.
      :max_notifications,
      :priority,
      publishing: true,
      items: %{},
      next_item: 0,
      # The sequence number of the next NotificationMessage.
      sequence: 1,
      # Publishing cycles since something was sent, and since a Publish
      # request was there to send it with.
      keep_alive_counter: 0,
      lifetime_counter: 0,
      # Whether it has something to send and no Publish request to send it with.
      late: false,
      # Messages sent and not yet acknowledged, by sequence number.
      retransmit: %{}
    ]

    @type t :: %__MODULE__{items: %{pos_integer => MonitoredItem.t()}}
  end

  defmodule MonitoredItem do
    @moduledoc false

    defstruct [
      :id,
      # :value for an attribute's value, :events for a notifier's events
      :kind,
      # The ReadValueId of what's monitored.
      :read,
      # :disabled, :sampling or :reporting
      :mode,
      # The client's handle, which its notifications carry.
      :handle,
      :queue_size,
      :discard_oldest,
      # A DataChangeFilter, an EventFilter, or nil.
      :filter,
      # Which timestamps a value item reports.
      :timestamps,
      # ms between samples; 0 for event items, which aren't sampled.
      sampling: 0,
      # Notifications waiting to be sent, oldest first, and how many.
      queue: :queue.new(),
      queued: 0,
      # The last value sampled, and when the next sample is due.
      last: nil,
      due: 0
    ]

    @type t :: %__MODULE__{}
  end
end
