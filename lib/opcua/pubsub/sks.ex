defmodule OPCUA.PubSub.SKS do
  @moduledoc """
  A Security Key Service (Part 14, 8.4): generates and rotates the keys of
  security groups, and hands them to the publishers and subscribers of a
  group.

  Each group has a current key, some past keys (so a subscriber that's a
  little late can still read) and some future keys (so that a publisher
  and subscriber can fetch keys once and switch at the same time). Every
  `:key_lifetime` the current key moves on to the next token.

  `OPCUA.Server` runs one, reached by `OPCUA.Server.add_security_group/3`
  and by clients through the `GetSecurityKeys` method of the PublishSubscribe
  object; see there. This module is also usable by itself.

  ## Group options

    * `:policy` - `:aes128_ctr` (the default) or `:aes256_ctr`, see
      `OPCUA.PubSub.Security`
    * `:key_lifetime` - ms a key is current (default one hour)
    * `:future_keys` - keys generated ahead (default 3)
    * `:past_keys` - keys kept after they've expired (default 1)
    * `:users` - the users allowed to get the keys, as the session's user
      name; any user who logged in when not given. `:anonymous` among them
      lets anonymous sessions have the keys too
  """

  use GenServer

  alias OPCUA.PubSub.Security

  @max_token 0xFFFF_FFFF

  @doc "Starts a Security Key Service."
  @spec start_link(keyword) :: GenServer.on_start()
  def start_link(opts \\ []), do: GenServer.start_link(__MODULE__, :ok, opts)

  @doc "Adds a security group. See the module doc for the options."
  @spec add_group(GenServer.server(), String.t(), keyword) :: :ok | {:error, :already_exists}
  def add_group(sks, id, opts \\ []), do: GenServer.call(sks, {:add, id, opts})

  @doc "Removes a security group."
  @spec remove_group(GenServer.server(), String.t()) :: :ok
  def remove_group(sks, id), do: GenServer.call(sks, {:remove, id})

  @doc "Moves a group on to a new key now, such as when a subscriber is removed."
  @spec rotate(GenServer.server(), String.t()) :: :ok | {:error, :bad_not_found}
  def rotate(sks, id), do: GenServer.call(sks, {:rotate, id})

  @doc """
  The keys of a group, as `GetSecurityKeys` gives them (Part 14, 8.3.2):
  `count` keys from the token `starting_token`, from the current one for 0,
  or from the oldest the group has for a token it doesn't have. `count`
  more than there are is all of them from there on, and 0 none to come:
  from the first up to the current one. `user` is checked against the
  group's `:users`; `:local` is code in this VM, which is always allowed.
  """
  @spec keys(GenServer.server(), String.t(), non_neg_integer, non_neg_integer, term) ::
          {:ok,
           %{
             policy: Security.policy(),
             first_token_id: pos_integer,
             keys: [binary],
             time_to_next_key: float,
             key_lifetime: float
           }}
          | {:error, :bad_not_found | :bad_user_access_denied}
  def keys(sks, id, starting_token \\ 0, count \\ 0, user \\ nil),
    do: GenServer.call(sks, {:keys, id, starting_token, count, user})

  @doc "Whether a user may get the keys of a group."
  @spec allowed?(GenServer.server(), String.t(), term) :: boolean
  def allowed?(sks, id, user), do: GenServer.call(sks, {:allowed, id, user})

  @impl true
  def init(:ok), do: {:ok, %{}}

  @impl true
  def handle_call({:add, id, opts}, _from, groups) do
    if Map.has_key?(groups, id) do
      {:reply, {:error, :already_exists}, groups}
    else
      policy = Keyword.get(opts, :policy, :aes128_ctr)
      true = policy in Security.all()
      lifetime = Keyword.get(opts, :key_lifetime, 3_600_000)
      true = is_integer(lifetime) and lifetime > 0
      future = Keyword.get(opts, :future_keys, 3)
      past = Keyword.get(opts, :past_keys, 1)

      group = %{
        policy: policy,
        lifetime: lifetime,
        future: future,
        past: past,
        users: opts[:users],
        current: 1,
        since: now(),
        keys: %{1 => Security.generate(policy)}
      }

      {:reply, :ok, Map.put(groups, id, fill(group))}
    end
  end

  def handle_call({:remove, id}, _from, groups), do: {:reply, :ok, Map.delete(groups, id)}

  def handle_call({:rotate, id}, _from, groups) do
    case groups[id] do
      nil ->
        {:reply, {:error, :bad_not_found}, groups}

      group ->
        {:reply, :ok, Map.put(groups, id, advance(%{group | since: now() - group.lifetime}))}
    end
  end

  def handle_call({:allowed, id, user}, _from, groups) do
    {:reply, match?(%{}, groups[id]) and allowed(groups[id], user), groups}
  end

  def handle_call({:keys, id, starting, count, user}, _from, groups) do
    case groups[id] do
      nil ->
        {:reply, {:error, :bad_not_found}, groups}

      group ->
        if allowed(group, user) do
          group = advance(group)
          {:reply, {:ok, answer(group, starting, count)}, Map.put(groups, id, group)}
        else
          {:reply, {:error, :bad_user_access_denied}, groups}
        end
    end
  end

  defp allowed(_group, :local), do: true
  defp allowed(%{users: nil}, user), do: user != :anonymous
  defp allowed(%{users: users}, user), do: user in users

  defp answer(group, starting, count) do
    oldest = max(group.current - group.past, 1)
    last = group.current + group.future

    first =
      cond do
        starting == 0 -> group.current
        starting in oldest..last//1 -> starting
        true -> oldest
      end

    until = if count == 0, do: max(first, group.current), else: min(first + count - 1, last)

    %{
      policy: group.policy,
      first_token_id: first,
      keys: for(token <- first..until, do: Map.fetch!(group.keys, token)),
      time_to_next_key: max(group.since + group.lifetime - now(), 0) * 1.0,
      key_lifetime: group.lifetime * 1.0
    }
  end

  # Moves on to the token whose time it is, however long nobody asked.
  defp advance(group) do
    elapsed = now() - group.since

    if elapsed >= group.lifetime do
      steps = div(elapsed, group.lifetime)
      current = min(group.current + steps, @max_token - group.future)

      %{group | current: current, since: group.since + steps * group.lifetime}
      |> fill()
    else
      group
    end
  end

  # Future keys up to the count, and none older than the past ones.
  defp fill(group) do
    wanted = (group.current - group.past)..(group.current + group.future)

    keys =
      for token <- wanted, token > 0, into: %{} do
        {token, group.keys[token] || Security.generate(group.policy)}
      end

    %{group | keys: keys}
  end

  defp now, do: System.monotonic_time(:millisecond)
end
