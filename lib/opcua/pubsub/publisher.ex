defmodule OPCUA.PubSub.Publisher do
  @moduledoc """
  Publishes datasets over UDP every interval, as one UADP network message
  per cycle.

  ## Options

    * `:url` - where to send, `opc.udp://host:port`, multicast or unicast
      (required)
    * `:publisher_id` - an integer or a string that identifies this publisher
      on the network (required)
    * `:writer_group_id` - the group the writers belong to (default 1)
    * `:interval` - ms between messages (default 1000), or 0 for a message
      each time `publish/1` is called, such as at the end of a PLC scan
    * `:writers` - the datasets to send, each a keyword list:
      * `:id` - the dataset writer id (required)
      * `:fields` - `{name, type}` for each field, in order (required)
      * `:read` - a function returning the values as a map by name, called
        each cycle; without it the values come from `set/3`
      * `:encoding` - `:variant` (the default), `:raw` (smallest, but the
        subscriber must know the types) or `:data_value`
      * `:key_frames` - send every value each N-th cycle, and only the
        values that changed in between (default 1: every value, every time)
    * `:ttl` - multicast hops (default 1, the local network)
    * `:name` - to register the process

  A field without a value is sent as null, or for raw fields, which can't
  be null, as its type's default (see `OPCUA.Binary.default/1`).
  """

  use GenServer

  require Logger

  alias OPCUA.{DataValue, Variant}
  alias OPCUA.PubSub.UADP
  alias OPCUA.PubSub.UADP.DataSetMessage

  @doc "Starts publishing. See the module doc for the options."
  @spec start_link(keyword) :: GenServer.on_start()
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, Keyword.take(opts, [:name]))

  @doc """
  Sends a message now, with the writers' current values. For a publisher
  with `interval: 0`, which sends nothing otherwise.
  """
  @spec publish(GenServer.server()) :: :ok
  def publish(publisher), do: GenServer.cast(publisher, :publish)

  @doc """
  Sets values of a writer without `:read`, by field name. They're sent from
  the next cycle on. A value that doesn't fit its field's type raises.
  """
  @spec set(GenServer.server(), non_neg_integer, map) :: :ok
  def set(publisher, writer_id, values) do
    case GenServer.call(publisher, {:set, writer_id, values}) do
      :ok -> :ok
      {:raise, exception} -> raise exception
    end
  end

  @impl true
  def init(opts) do
    with {:ok, ip, port} <- OPCUA.PubSub.address(Keyword.fetch!(opts, :url)),
         {:ok, socket} <-
           :gen_udp.open(0, [
             :binary,
             multicast_ttl: Keyword.get(opts, :ttl, 1),
             multicast_loop: true
           ]) do
      writers =
        for writer <- Keyword.fetch!(opts, :writers) do
          %{
            id: Keyword.fetch!(writer, :id),
            fields: Keyword.fetch!(writer, :fields),
            read: writer[:read],
            encoding: Keyword.get(writer, :encoding, :variant),
            key_frames: Keyword.get(writer, :key_frames, 1),
            values: %{},
            sent: nil,
            sequence: 0
          }
        end

      state = %{
        socket: socket,
        ip: ip,
        port: port,
        publisher_id: OPCUA.PubSub.publisher_id(Keyword.fetch!(opts, :publisher_id)),
        writer_group_id: Keyword.get(opts, :writer_group_id, 1),
        interval: Keyword.get(opts, :interval, 1000),
        writers: writers,
        sequence: 0,
        cycle: 0,
        failing: nil
      }

      if state.interval > 0, do: send(self(), :publish)
      {:ok, state}
    end
  end

  @impl true
  def handle_call({:set, id, values}, _from, state) do
    case Enum.find(state.writers, &(&1.id == id)) do
      nil ->
        {:reply, {:raise, ArgumentError.exception("no writer #{id}")}, state}

      writer ->
        try do
          check(writer, values)

          writers =
            for w <- state.writers,
                do: if(w.id == id, do: %{w | values: Map.merge(w.values, values)}, else: w)

          {:reply, :ok, %{state | writers: writers}}
        rescue
          exception in ArgumentError -> {:reply, {:raise, exception}, state}
        end
    end
  end

  @impl true
  def handle_cast(:publish, state), do: {:noreply, send_message(state)}

  @impl true
  def handle_info(:publish, state) do
    Process.send_after(self(), :publish, state.interval)
    {:noreply, send_message(state)}
  end

  defp send_message(state) do
    now = DateTime.utc_now()

    {messages, writers} =
      state.writers |> Enum.map(&message(&1, state.cycle, now)) |> Enum.unzip()

    sequence = rem(state.sequence + 1, 0x10000)

    network = %UADP{
      publisher_id: state.publisher_id,
      writer_group_id: state.writer_group_id,
      network_message_number: 1,
      sequence_number: sequence,
      messages: messages
    }

    # Said once when sending starts failing, and once when it works again,
    # rather than every cycle.
    failing =
      case {:gen_udp.send(state.socket, state.ip, state.port, UADP.encode(network)),
            state.failing} do
        {:ok, nil} ->
          nil

        {:ok, _reason} ->
          Logger.info("OPC UA PubSub sends again")
          nil

        {{:error, reason}, reason} ->
          reason

        {{:error, reason}, _before} ->
          Logger.warning("OPC UA PubSub send failed: #{inspect(reason)}")
          reason
      end

    %{state | writers: writers, sequence: sequence, cycle: state.cycle + 1, failing: failing}
  end

  defp message(writer, cycle, now) do
    values = current(writer)
    sequence = rem(writer.sequence + 1, 0x10000)
    key = writer.sent == nil or rem(cycle, writer.key_frames) == 0

    {type, fields} =
      if key do
        {:key_frame,
         for({name, type} <- writer.fields, do: field(writer.encoding, type, values[name]))}
      else
        changed =
          for {{name, type}, index} <- Enum.with_index(writer.fields),
              values[name] != writer.sent[name],
              do: {index, field(writer.encoding, type, values[name])}

        if changed == [], do: {:keep_alive, []}, else: {:delta_frame, changed}
      end

    message = %DataSetMessage{
      writer_id: writer.id,
      type: type,
      encoding: writer.encoding,
      sequence_number: sequence,
      timestamp: now,
      status: 0,
      fields: fields
    }

    try do
      check(writer, values)
      {message, %{writer | sent: values, sequence: sequence}}
    rescue
      # A value from :read that doesn't fit its type: this writer's message
      # is marked invalid this cycle, rather than stopping the others.
      exception in ArgumentError ->
        Logger.error("OPC UA PubSub writer #{writer.id}: #{Exception.message(exception)}")
        {%{message | valid: false, type: :keep_alive, fields: []}, %{writer | sequence: sequence}}
    end
  end

  # Raises ArgumentError for a value that doesn't fit its field.
  defp check(writer, values) do
    for {name, type} <- writer.fields, Map.has_key?(values, name) do
      UADP.check_field(writer.encoding, field(writer.encoding, type, values[name]))
    end
  end

  defp current(%{read: nil, values: values}), do: values

  defp current(%{read: read} = writer) do
    read.()
  rescue
    exception ->
      Logger.error(
        "OPC UA PubSub read of writer #{writer.id} failed: " <> Exception.message(exception)
      )

      writer.sent || %{}
  end

  defp field(:variant, _type, nil), do: nil
  defp field(:variant, type, value), do: %Variant{type: type, value: value}
  defp field(:data_value, _type, nil), do: %DataValue{}
  defp field(:data_value, type, value), do: %DataValue{value: %Variant{type: type, value: value}}
  defp field(:raw, type, nil), do: {type, OPCUA.Binary.default(type)}
  defp field(:raw, type, value), do: {type, value}
end
