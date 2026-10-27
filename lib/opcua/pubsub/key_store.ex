defmodule OPCUA.PubSub.KeyStore do
  @moduledoc false
  # The keys a publisher or subscriber signs and encrypts with, in an ETS
  # table it can read without asking a process: `{:current, token_id}` and
  # `{token_id, keys}`. The process keeps them there, fetching them from a
  # Security Key Service and again when the current key runs out.
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
      switch: nil,
      next: nil,
      fetching: false,
      last_fetch: nil,
      failing: false,
      timer: nil
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
    now = System.monotonic_time(:millisecond)

    if state.sks != nil and state.fetching == false and
         (state.last_fetch == nil or now - state.last_fetch >= @min_between),
       do: {:noreply, start_fetch(state)},
       else: {:noreply, state}
  end

  def handle_info(:fetch, %{sks: nil} = state), do: {:noreply, state}
  def handle_info(:fetch, %{fetching: ref} = state) when ref != false, do: {:noreply, state}
  def handle_info(:fetch, state), do: {:noreply, start_fetch(state)}

  # The current key's time is up: the next token, which was fetched with it,
  # takes over, and new keys are fetched.
  def handle_info(:switch, state) do
    next = state.current && state.current + 1

    if next && :ets.member(state.table, next), do: :ets.insert(state.table, {:current, next})
    state = %{state | current: next || state.current}
    {:noreply, start_fetch(%{state | timer: nil})}
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
    %{state | fetching: task.ref, last_fetch: System.monotonic_time(:millisecond)}
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
    timer = Process.send_after(self(), :switch, round(answer.time_to_next_key) + 100)
    %{state | current: first, timer: timer, failing: false}
  end

  defp fetched({:error, reason}, state) do
    unless state.failing,
      do: Logger.warning("OPC UA PubSub can't get security keys: #{inspect(reason)}")

    Process.send_after(self(), :fetch, @retry)
    %{state | failing: true}
  end

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
    case OPCUA.Server.security_keys(server, group) do
      {:ok, a} ->
        {:ok,
         %{
           policy_uri: Security.uri(a.policy),
           first: a.first_token_id,
           keys: a.keys,
           time_to_next_key: a.time_to_next_key
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
      %Variant{type: :uint32, value: 0}
    ]

    case OPCUA.Client.call(client, @publish_subscribe, @get_security_keys, args) do
      {:ok, [uri, first, keys, time_to_next, _lifetime]} ->
        {:ok, %{policy_uri: uri, first: first, keys: keys, time_to_next_key: time_to_next}}

      {:ok, other} ->
        {:error, {:bad_reply, other}}

      {:error, _} = error ->
        error
    end
  end
end
