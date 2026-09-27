defmodule OPCUA.PubSub.Subscriber do
  @moduledoc """
  Receives UADP messages over UDP and sends the datasets it's told to read to
  a process:

      {OPCUA.PubSub, reader, {:data, %{"Speed" => 1500, "Running" => true}}}
      {OPCUA.PubSub, reader, :timeout}

  `:data` carries every field by name, after a key frame or a delta frame.
  `:timeout` comes once when a dataset stops arriving, and `:data` again when
  it's back. Messages out of order are dropped.

  ## Options

    * `:url` - where to listen, `opc.udp://host:port`; a multicast address
      is joined (required)
    * `:readers` - the datasets to read, each a keyword list:
      * `:publisher_id`, `:writer_id` - whose dataset (required)
      * `:writer_group_id` - and in which group (default any)
      * `:fields` - `{name, type}` for each field, in order; needed for raw
        fields, and to name the fields (otherwise they're numbered from 0)
      * `:name` - what the messages call the reader (default
        `{publisher_id, writer_id}`)
      * `:timeout` - ms without a message before `:timeout` (default 5000)
    * `:to` - the process to send to (default the process that calls
      `start_link/1`; under a supervisor that's the supervisor, so pass it)
    * `:interface` - the local address to join multicast on (default any)
    * `:name` - to register the process
  """

  use GenServer

  require Logger

  alias OPCUA.{DataValue, StatusCode, Variant}
  alias OPCUA.PubSub.UADP

  @doc "Starts receiving. See the module doc for the options."
  @spec start_link(keyword) :: GenServer.on_start()
  def start_link(opts),
    do:
      GenServer.start_link(
        __MODULE__,
        Keyword.put_new(opts, :to, self()),
        Keyword.take(opts, [:name])
      )

  @impl true
  def init(opts) do
    interface = Keyword.get(opts, :interface, {0, 0, 0, 0})

    with {:ok, ip, port} <- OPCUA.PubSub.address(Keyword.fetch!(opts, :url)),
         # Multicast is joined on any address; unicast listens on the one given.
         listen =
           if(OPCUA.PubSub.multicast?(ip),
             do: [add_membership: {ip, interface}, multicast_loop: true],
             else: [ip: ip]
           ),
         {:ok, socket} <-
           :gen_udp.open(
             port,
             [:binary, active: true, reuseaddr: true, reuseport: true] ++ listen
           ) do
      readers =
        for reader <- Keyword.fetch!(opts, :readers) do
          publisher = Keyword.fetch!(reader, :publisher_id)
          writer = Keyword.fetch!(reader, :writer_id)
          fields = reader[:fields]

          %{
            publisher: publisher_value(publisher),
            group: reader[:writer_group_id],
            writer: writer,
            names: if(fields, do: Enum.map(fields, &elem(&1, 0))),
            types: if(fields, do: Enum.map(fields, &elem(&1, 1))),
            name: Keyword.get(reader, :name, {publisher_value(publisher), writer}),
            timeout: Keyword.get(reader, :timeout, 5000),
            values: nil,
            sequence: nil,
            timer: nil,
            timed_out: false
          }
        end

      # Raw fields can only be read knowing their types.
      raw_types = for r <- readers, r.types, into: %{}, do: {r.writer, r.types}

      {:ok,
       %{socket: socket, readers: readers, raw_types: raw_types, to: Keyword.fetch!(opts, :to)}}
    end
  end

  defp publisher_value({_type, value}), do: value
  defp publisher_value(value), do: value

  @impl true
  def handle_info({:udp, _, _, _, data}, state) do
    case UADP.decode(data, state.raw_types) do
      {:ok, message} ->
        {:noreply, Enum.reduce(message.messages, state, &dataset(message, &1, &2))}

      {:error, _} ->
        {:noreply, state}
    end
  end

  def handle_info({:timeout, index}, state) do
    reader = Enum.at(state.readers, index)
    send(state.to, {OPCUA.PubSub, reader.name, :timeout})
    {:noreply, put_reader(state, index, %{reader | timer: nil, timed_out: true})}
  end

  defp dataset(message, dataset, state) do
    publisher = message.publisher_id && publisher_value(message.publisher_id)

    case Enum.find_index(
           state.readers,
           &(&1.publisher == publisher and &1.writer == dataset.writer_id and
               &1.group in [nil, message.writer_group_id])
         ) do
      nil ->
        state

      index ->
        reader = Enum.at(state.readers, index)

        # A message the publisher marked invalid is skipped.
        if dataset.valid and newer?(reader.sequence, dataset.sequence_number),
          do: put_reader(state, index, receive_dataset(reader, dataset, index, state.to)),
          else: state
    end
  end

  # UInt16 sequence numbers that wrap: newer is up to half the range ahead.
  defp newer?(nil, _), do: true
  defp newer?(_, nil), do: true
  defp newer?(last, sequence), do: rem(sequence - last + 0x10000, 0x10000) in 1..0x7FFF

  defp receive_dataset(reader, dataset, index, to) do
    if reader.timer, do: Process.cancel_timer(reader.timer)
    timer = Process.send_after(self(), {:timeout, index}, reader.timeout)

    reader = %{
      reader
      | sequence: dataset.sequence_number || reader.sequence,
        timer: timer,
        timed_out: false
    }

    values =
      case dataset.type do
        :key_frame ->
          dataset.fields
          |> Enum.with_index()
          |> Map.new(fn {field, i} -> {name(reader, i), value(field)} end)

        :delta_frame when reader.values != nil ->
          Enum.reduce(dataset.fields, reader.values, fn {i, field}, acc ->
            Map.put(acc, name(reader, i), value(field))
          end)

        _ ->
          nil
      end

    if values do
      send(to, {OPCUA.PubSub, reader.name, {:data, values}})
      %{reader | values: values}
    else
      reader
    end
  end

  defp name(%{names: nil}, index), do: index
  defp name(%{names: names}, index), do: Enum.at(names, index, index)

  defp value(%Variant{value: value}), do: value
  defp value(nil), do: nil

  defp value(%DataValue{status: status, value: value}),
    do: if(StatusCode.bad?(status), do: nil, else: value(value))

  defp value({_type, value}), do: value
  defp value(other), do: other

  defp put_reader(state, index, reader),
    do: %{state | readers: List.replace_at(state.readers, index, reader)}
end
