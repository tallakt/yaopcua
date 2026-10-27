defmodule OPCUA.PubSub.KeyStore do
  @moduledoc false
  # The keys a publisher or subscriber signs and encrypts with, in an ETS
  # table it can read without asking a process: `{:current, token_id}` and
  # `{token_id, keys}`. The process keeps them there, fetching them from a
  # Security Key Service, and again every half key lifetime.
  #
  # Where the keys come from, as `security:` of Publisher and Subscriber says:
  #
  #   * `keys: [{token_id, bytes}]` - fixed; the highest token is current
  #   * `sks: [server: server, group: id]` - an `OPCUA.Server` in this VM
  #   * `sks: [url: url, group: id] ++ client options` - any server, over a
  #     session that's signed and encrypted

  use GenServer

  require Logger

  alias OPCUA.{NodeIds, Variant}
  alias OPCUA.PubSub.Security

  @publish_subscribe NodeIds.node_id!("PublishSubscribe")
  @get_security_keys NodeIds.node_id!("PublishSubscribe_GetSecurityKeys")

  # Tokens this far behind the current one are still kept, for subscribers
  # that are late.
  @past 2
  @retry 1000
  # Fetches caused by an unknown token are at least this far apart.
  @min_between 2000
  # Other fetches are at least this far apart, whatever times the service
  # gives: each is a session of its own with a service elsewhere.
  @min_fetch 1000
  # Keys asked for: the current one and some to come, which are switched to
  # on time and bridge a service that's away a while. Asking for 0 would get
  # no keys to come (Part 14, 8.3.2). The service may give fewer.
  @key_count 5
  # The longest a timer is set for, about 50 days.
  @max_wait 0xFFFF_FFFF

  def start_link(security), do: GenServer.start_link(__MODULE__, security)

  @doc "The ETS table of the keys."
  def table(store), do: GenServer.call(store, :table)

  @doc "The current token and its keys, or nil before any key is known."
  def current(table) do
    with [{:current, token}] <- :ets.lookup(table, :current),
         [{^token, keys}] <- :ets.lookup(table, token) do
      {token, keys}
    else
      _ -> nil
    end
  end

  @doc "The keys of a token, or nil. Asks for new keys when it isn't known."
  def lookup(table, store, token) do
    case :ets.lookup(table, token) do
      [{^token, keys}] ->
        keys

      [] ->
        send(store, :unknown_token)
        nil
    end
  end

  @doc "Checks the options of `security:`, raising ArgumentError, and fills in defaults."
  def check!(security) do
    mode = Keyword.get(security, :mode, :sign_and_encrypt)
    policy = Keyword.get(security, :policy, :aes128_ctr)

    mode in [:sign, :sign_and_encrypt] ||
      raise ArgumentError, "security :mode is :sign or :sign_and_encrypt, got #{inspect(mode)}"

    policy in Security.all() ||
      raise ArgumentError, "security :policy is one of #{inspect(Security.all())}"

    case {security[:keys], security[:sks]} do
      {keys, nil} when is_list(keys) and keys != [] -> check_keys!(policy, keys)
      {nil, sks} when is_list(sks) -> check_sks!(sks)
      _ -> raise ArgumentError, "security needs :keys or :sks"
    end

    security |> Keyword.put(:mode, mode) |> Keyword.put(:policy, policy)
  end

  defp check_keys!(policy, keys) do
    for {token, bytes} <- keys do
      (is_integer(token) and token > 0 and match?({:ok, _}, Security.split(policy, bytes))) ||
        raise ArgumentError,
              "security :keys are {token_id, bytes} of #{Security.key_length(policy)} bytes"
    end
  end

  defp check_sks!(sks) do
    is_binary(sks[:group]) || raise ArgumentError, "security :sks needs a :group"
    sks[:server] || sks[:url] || raise ArgumentError, "security :sks needs a :server or a :url"

    # The keys are secrets: only over an encrypted session.
    sks[:server] || match?({_, :sign_and_encrypt}, sks_security(sks)) ||
      raise ArgumentError,
            "security keys must be fetched over a :sign_and_encrypt session, " <>
              "not #{inspect(sks[:security])}"
  end

  defp sks_security(sks) do
    case Keyword.get(sks, :security, {:basic256sha256, :sign_and_encrypt}) do
      {_policy, _mode} = both -> both
      :none -> {:none, :none}
      policy -> {policy, :sign_and_encrypt}
    end
  end

  @impl true
  def init(security) do
    table = :ets.new(__MODULE__, [:set, :protected, read_concurrency: true])
    policy = security[:policy]

    state = %{
      table: table,
      policy: policy,
      sks: security[:sks],
      current: nil,
      lifetime: nil,
      asked: nil,
      fetching: false,
      last_fetch: nil,
      failing: false,
      timer: nil,
      refresh: nil
    }

    case security[:keys] do
      nil ->
        send(self(), :fetch)
        {:ok, state}

      keys ->
        for {token, bytes} <- keys do
          {:ok, split} = Security.split(policy, bytes)
          :ets.insert(table, {token, split})
        end

        :ets.insert(table, {:current, keys |> Enum.map(&elem(&1, 0)) |> Enum.max()})
        {:ok, state}
    end
  end

  @impl true
  def handle_call(:table, _from, state), do: {:reply, state.table, state}

  @impl true
  def handle_info(:unknown_token, state) do
    if state.sks != nil and state.fetching == false and
         (state.last_fetch == nil or now() - state.last_fetch >= @min_between),
       do: {:noreply, start_fetch(state)},
       else: {:noreply, state}
  end

  def handle_info(:fetch, %{sks: nil} = state), do: {:noreply, state}
  def handle_info(:fetch, %{fetching: ref} = state) when ref != false, do: {:noreply, state}
  def handle_info(:fetch, state), do: {:noreply, start_fetch(state)}

  # The current key's time is up: the next one, fetched ahead, takes over
  # for a lifetime. A service that gave no key to come is asked now, not at
  # the next refresh, and should it not have moved on yet, again no sooner
  # than @min_fetch.
  def handle_info(:switch, state) do
    next = state.current + 1

    if :ets.member(state.table, next) do
      :ets.insert(state.table, {:current, next})
      timer = Process.send_after(self(), :switch, state.lifetime)
      {:noreply, %{state | current: next, timer: timer}}
    else
      gap = if state.asked == next, do: @min_fetch, else: 0
      {:noreply, fetch_soon(%{state | timer: nil, asked: next}, gap)}
    end
  end

  def handle_info({ref, result}, %{fetching: ref} = state) when is_reference(ref) do
    Process.demonitor(ref, [:flush])
    {:noreply, fetched(result, %{state | fetching: false})}
  end

  def handle_info({:DOWN, ref, :process, _, reason}, %{fetching: ref} = state),
    do: {:noreply, fetched({:error, reason}, %{state | fetching: false})}

  def handle_info(_, state), do: {:noreply, state}

  defp start_fetch(state) do
    sks = state.sks
    policy = state.policy

    task = Task.async(fn -> fetch(sks, policy) end)
    %{state | fetching: task.ref, last_fetch: now()}
  end

  # A fetch now, or once `gap` has passed since the last one.
  defp fetch_soon(%{fetching: false} = state, gap) do
    case state.last_fetch + gap - now() do
      wait when wait > 0 -> fetch_after(state, wait)
      _ -> start_fetch(state)
    end
  end

  defp fetch_soon(state, _gap), do: state

  # The next fetch, in place of the one planned.
  defp fetch_after(state, time) do
    _ = if state.refresh, do: Process.cancel_timer(state.refresh)
    %{state | refresh: Process.send_after(self(), :fetch, time)}
  end

  defp fetched({:ok, %{first: first, keys: keys} = answer}, state) do
    if state.failing, do: Logger.info("OPC UA PubSub got security keys again")

    keys
    |> Enum.with_index(first)
    |> Enum.each(fn {bytes, token} -> :ets.insert(state.table, {token, bytes}) end)

    :ets.insert(state.table, {:current, first})
    :ok = prune(state.table, first)
    _ = if state.timer, do: Process.cancel_timer(state.timer)
    # A moment late, so that the service has moved on by then.
    timer = Process.send_after(self(), :switch, ms(answer.time_to_next_key) + 100)
    state = %{state | current: first, lifetime: ms(answer.key_lifetime), timer: timer}

    # Part 14, 8.3.2: keys are fetched every half key lifetime, so that a
    # subscriber that is late, or a service that was away a moment, don't
    # leave the group without keys.
    fetch_after(%{state | failing: false}, refresh_after(answer.key_lifetime))
  end

  defp fetched({:error, reason}, state) do
    unless state.failing,
      do: Logger.warning("OPC UA PubSub can't get security keys: #{inspect(reason)}")

    fetch_after(%{state | failing: true}, @retry)
  end

  # Half the lifetime, but no sooner than @min_fetch; and a minute if the
  # service gives no lifetime that makes sense.
  defp refresh_after(lifetime) when is_number(lifetime) and lifetime > 0,
    do: max(div(ms(lifetime), 2), @min_fetch)

  defp refresh_after(_), do: 60_000

  # A time the service gives, a Double, as the ms of a timer: a negative
  # time is none, and one past what a timer takes, or NaN or an infinity
  # (atoms here), is the longest a timer takes; the refresh keeps up then.
  defp ms(time) when is_number(time), do: time |> max(0) |> min(@max_wait) |> round()
  defp ms(_), do: @max_wait

  defp now, do: System.monotonic_time(:millisecond)

  # Old tokens go.
  defp prune(table, current) do
    _ =
      for {token, _} <- :ets.tab2list(table), is_integer(token), token < current - @past do
        :ets.delete(table, token)
      end

    :ok
  end

  ## Fetching

  defp fetch(sks, policy) do
    with {:ok, answer} <- get(sks),
         :ok <- same_policy(answer, policy),
         {:ok, keys} <- split(answer.keys, policy) do
      {:ok, %{answer | keys: keys}}
    end
  end

  defp same_policy(%{policy_uri: uri}, policy),
    do: if(uri == Security.uri(policy), do: :ok, else: {:error, {:wrong_policy, uri}})

  defp split([], _), do: {:error, :no_keys}

  defp split(keys, policy) do
    split = Enum.map(keys, &Security.split(policy, &1))

    if Enum.all?(split, &match?({:ok, _}, &1)),
      do: {:ok, Enum.map(split, &elem(&1, 1))},
      else: {:error, :bad_key_length}
  end

  defp get(sks) do
    group = Keyword.fetch!(sks, :group)

    case sks[:server] do
      nil -> get_remote(sks, group)
      server -> get_local(server, group)
    end
  end

  defp get_local(server, group) do
    case OPCUA.Server.security_keys(server, group, 0, @key_count) do
      {:ok, a} ->
        {:ok,
         %{
           policy_uri: Security.uri(a.policy),
           first: a.first_token_id,
           keys: a.keys,
           time_to_next_key: a.time_to_next_key,
           key_lifetime: a.key_lifetime
         }}

      {:error, _} = error ->
        error
    end
  end

  defp get_remote(sks, group) do
    opts =
      sks
      |> Keyword.drop([:group, :server])
      |> Keyword.put_new(:security, {:basic256sha256, :sign_and_encrypt})

    case OPCUA.Client.start(opts) do
      {:ok, client} ->
        try do
          call(client, group)
        after
          OPCUA.Client.close(client)
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp call(client, group) do
    args = [
      %Variant{type: :string, value: group},
      %Variant{type: :uint32, value: 0},
      %Variant{type: :uint32, value: @key_count}
    ]

    case OPCUA.Client.call(client, @publish_subscribe, @get_security_keys, args) do
      {:ok, [uri, first, keys, time_to_next, lifetime]} ->
        {:ok,
         %{
           policy_uri: uri,
           first: first,
           keys: keys,
           time_to_next_key: time_to_next,
           key_lifetime: lifetime
         }}

      {:ok, other} ->
        {:error, {:bad_reply, other}}

      {:error, _} = error ->
        error
    end
  end
end
