defmodule OPCUA.PubSub.UADP do
  @moduledoc """
  UADP, the binary mapping of PubSub messages (Part 14, 7.2.2), as plain data.

  A network message comes from a publisher and a writer group, and carries
  one or more dataset messages, each from one dataset writer:

      %OPCUA.PubSub.UADP{
        publisher_id: {:uint16, 42},
        writer_group_id: 1,
        sequence_number: 7,
        messages: [%OPCUA.PubSub.UADP.DataSetMessage{writer_id: 1, fields: [...]}]
      }

  Fields are `OPCUA.Variant`s, `OPCUA.DataValue`s, or raw `{type, value}`
  pairs, as each dataset message's `encoding` says. Raw fields carry no type
  on the wire, so `decode/2` needs their types per writer id.

  Not handled: message security, chunked network messages, and discovery
  messages.
  """

  import Bitwise

  alias OPCUA.Binary

  defmodule DataSetMessage do
    @moduledoc """
    One dataset writer's part of a network message.

    `type` is `:key_frame` (every field), `:delta_frame` (`fields` is a list of
    `{index, value}` for the fields that changed), `:event` or `:keep_alive`.
    `status` is the upper 16 bits of an OPC UA status code; 0 is Good.
    """
    defstruct writer_id: 0,
              valid: true,
              type: :key_frame,
              encoding: :variant,
              sequence_number: nil,
              timestamp: nil,
              picoseconds: nil,
              status: nil,
              major_version: nil,
              minor_version: nil,
              fields: []

    @type t :: %__MODULE__{}
  end

  defstruct publisher_id: nil,
            dataset_class_id: nil,
            writer_group_id: nil,
            group_version: nil,
            network_message_number: nil,
            sequence_number: nil,
            timestamp: nil,
            picoseconds: nil,
            payload_header: true,
            messages: []

  @type publisher_id ::
          {:byte | :uint16 | :uint32 | :uint64, non_neg_integer} | {:string, String.t()}
  @type t :: %__MODULE__{publisher_id: publisher_id | nil}

  @publisher_types [:byte, :uint16, :uint32, :uint64, :string]
  @encodings [:variant, :raw, :data_value]
  @message_types [:key_frame, :delta_frame, :event, :keep_alive]

  @doc "Encodes a network message."
  @spec encode(t) :: iodata
  def encode(%__MODULE__{} = m) do
    {publisher_type, publisher} =
      case m.publisher_id do
        nil -> {nil, nil}
        {type, value} -> {type, value}
      end

    group = m.writer_group_id || m.group_version || m.network_message_number || m.sequence_number

    extended =
      publisher_type not in [nil, :byte] or m.dataset_class_id != nil or m.timestamp != nil or
        m.picoseconds != nil

    payload_header = m.payload_header and m.messages != []

    flags =
      1 ||| bit(publisher_type, 0x10) ||| bit(group, 0x20) ||| bit(payload_header, 0x40) |||
        bit(extended, 0x80)

    extended_flags =
      if extended do
        index = Enum.find_index(@publisher_types, &(&1 == (publisher_type || :byte)))

        <<index ||| bit(m.dataset_class_id, 0x08) ||| bit(m.timestamp, 0x20) |||
            bit(m.picoseconds, 0x40)>>
      else
        <<>>
      end

    messages = Enum.map(m.messages, &encode_message/1)

    [
      <<flags>>,
      extended_flags,
      if(publisher_type, do: Binary.encode(publisher, publisher_type), else: []),
      if(m.dataset_class_id, do: Binary.encode(m.dataset_class_id, :guid), else: []),
      if(group, do: group_header(m), else: []),
      if(payload_header,
        do: [<<length(m.messages)>> | Enum.map(m.messages, &<<&1.writer_id::little-16>>)],
        else: []
      ),
      if(m.timestamp, do: Binary.encode(m.timestamp, :date_time), else: []),
      if(m.picoseconds, do: <<m.picoseconds::little-16>>, else: []),
      # With more than one message, their sizes come first.
      if(payload_header and length(messages) > 1,
        do: Enum.map(messages, &<<IO.iodata_length(&1)::little-16>>),
        else: []
      ),
      messages
    ]
  end

  defp bit(nil, _), do: 0
  defp bit(false, _), do: 0
  defp bit(_, value), do: value

  defp group_header(m) do
    flags =
      bit(m.writer_group_id, 0x01) ||| bit(m.group_version, 0x02) |||
        bit(m.network_message_number, 0x04) ||| bit(m.sequence_number, 0x08)

    [
      <<flags>>,
      if(m.writer_group_id, do: <<m.writer_group_id::little-16>>, else: []),
      if(m.group_version, do: <<m.group_version::little-32>>, else: []),
      if(m.network_message_number, do: <<m.network_message_number::little-16>>, else: []),
      if(m.sequence_number, do: <<m.sequence_number::little-16>>, else: [])
    ]
  end

  defp encode_message(%DataSetMessage{} = d) do
    encoding = Enum.find_index(@encodings, &(&1 == d.encoding))
    type = Enum.find_index(@message_types, &(&1 == d.type))
    flags2 = type ||| bit(d.timestamp, 0x10) ||| bit(d.picoseconds, 0x20)

    flags1 =
      bit(d.valid, 0x01) ||| encoding <<< 1 ||| bit(d.sequence_number, 0x08) |||
        bit(d.status, 0x10) |||
        bit(d.major_version, 0x20) ||| bit(d.minor_version, 0x40) ||| bit(flags2 != 0, 0x80)

    [
      <<flags1>>,
      if(flags2 != 0, do: <<flags2>>, else: []),
      if(d.sequence_number, do: <<d.sequence_number::little-16>>, else: []),
      if(d.timestamp, do: Binary.encode(d.timestamp, :date_time), else: []),
      if(d.picoseconds, do: <<d.picoseconds::little-16>>, else: []),
      if(d.status, do: <<d.status::little-16>>, else: []),
      if(d.major_version, do: <<d.major_version::little-32>>, else: []),
      if(d.minor_version, do: <<d.minor_version::little-32>>, else: []),
      fields(d)
    ]
  end

  defp fields(%{type: :keep_alive}), do: []

  defp fields(%{type: :delta_frame, encoding: encoding, fields: fields}) do
    [
      <<length(fields)::little-16>>
      | for({index, value} <- fields, do: [<<index::little-16>>, field(encoding, value)])
    ]
  end

  # Raw fields are just the values, without a count.
  defp fields(%{encoding: :raw, fields: fields}), do: Enum.map(fields, &field(:raw, &1))

  defp fields(%{encoding: encoding, fields: fields}),
    do: [<<length(fields)::little-16>> | Enum.map(fields, &field(encoding, &1))]

  defp field(:variant, value), do: Binary.encode(value, :variant)
  defp field(:data_value, value), do: Binary.encode(value, :data_value)
  defp field(:raw, {type, value}), do: Binary.encode(value, type)

  @doc false
  # Encodes one field, raising ArgumentError if its value doesn't fit.
  def check_field(encoding, value), do: field(encoding, value)

  @doc """
  Decodes a network message. `raw_types` gives the field types of writers
  that send raw fields, by writer id: `%{1 => [:int16, :double]}`. A dataset
  message from a writer with raw fields and no types given keeps its fields
  as a binary.
  """
  @spec decode(binary, %{non_neg_integer => [OPCUA.Binary.type()]}) ::
          {:ok, t} | {:error, :bad_decoding_error}
  def decode(binary, raw_types \\ %{}) do
    {:ok, take(binary, raw_types)}
  rescue
    _ in [OPCUA.DecodeError, MatchError, CaseClauseError, FunctionClauseError, ArgumentError] ->
      {:error, :bad_decoding_error}
  end

  defp take(<<flags, rest::binary>>, raw_types) do
    1 = flags &&& 0x0F

    {extended, rest} = if (flags &&& 0x80) != 0, do: split_byte(rest), else: {0, rest}
    {extended2, rest} = if (extended &&& 0x80) != 0, do: split_byte(rest), else: {0, rest}
    # Chunked, discovery and secured messages aren't handled.
    true = (extended2 &&& 0x1D) == 0 and (extended &&& 0x10) == 0

    publisher_type = known(@publisher_types, extended &&& 0x07)
    {publisher, rest} = optional(rest, flags &&& 0x10, publisher_type)
    {class_id, rest} = optional(rest, extended &&& 0x08, :guid)

    m = %__MODULE__{
      publisher_id: publisher && {publisher_type, publisher},
      dataset_class_id: class_id
    }

    {m, rest} = if (flags &&& 0x20) != 0, do: take_group(m, rest), else: {m, rest}

    {writer_ids, rest} =
      if (flags &&& 0x40) != 0 do
        <<count, rest::binary>> = rest
        <<ids::binary-size(count * 2), rest::binary>> = rest
        {for(<<id::little-16 <- ids>>, do: id), rest}
      else
        {nil, rest}
      end

    {timestamp, rest} = optional(rest, extended &&& 0x20, :date_time)
    {picoseconds, rest} = optional(rest, extended &&& 0x40, :uint16)

    # Promoted fields are skipped; they repeat values from the messages.
    rest =
      if (extended2 &&& 0x02) != 0 do
        <<size::little-16, _::binary-size(size), rest::binary>> = rest
        rest
      else
        rest
      end

    messages = take_messages(rest, writer_ids, raw_types)

    %{
      m
      | timestamp: timestamp,
        picoseconds: picoseconds,
        payload_header: writer_ids != nil,
        messages: messages
    }
  end

  defp split_byte(<<byte, rest::binary>>), do: {byte, rest}

  # A reserved value in a flags field is a malformed message.
  defp known(list, index),
    do: Enum.at(list, index) || raise(OPCUA.DecodeError, "reserved value #{index}")

  defp optional(binary, 0, _), do: {nil, binary}
  defp optional(binary, _, type), do: Binary.take(binary, type)

  defp take_group(m, <<flags, rest::binary>>) do
    {writer_group_id, rest} = optional(rest, flags &&& 0x01, :uint16)
    {group_version, rest} = optional(rest, flags &&& 0x02, :uint32)
    {number, rest} = optional(rest, flags &&& 0x04, :uint16)
    {sequence, rest} = optional(rest, flags &&& 0x08, :uint16)

    {%{
       m
       | writer_group_id: writer_group_id,
         group_version: group_version,
         network_message_number: number,
         sequence_number: sequence
     }, rest}
  end

  # Without a payload header there's one message, of unknown writer.
  defp take_messages(rest, nil, raw_types), do: [take_message(rest, nil, raw_types)]
  defp take_messages(rest, [id], raw_types), do: [take_message(rest, id, raw_types)]

  defp take_messages(rest, ids, raw_types) do
    <<sizes::binary-size(length(ids) * 2), rest::binary>> = rest
    sizes = for <<size::little-16 <- sizes>>, do: size

    {messages, _} =
      Enum.zip(ids, sizes)
      |> Enum.map_reduce(rest, fn {id, size}, rest ->
        <<message::binary-size(size), rest::binary>> = rest
        {take_message(message, id, raw_types), rest}
      end)

    messages
  end

  defp take_message(<<flags1, rest::binary>>, id, raw_types) do
    {flags2, rest} = if (flags1 &&& 0x80) != 0, do: split_byte(rest), else: {0, rest}
    encoding = known(@encodings, flags1 >>> 1 &&& 0x03)
    type = known(@message_types, flags2 &&& 0x0F)
    {sequence, rest} = optional(rest, flags1 &&& 0x08, :uint16)
    {timestamp, rest} = optional(rest, flags2 &&& 0x10, :date_time)
    {picoseconds, rest} = optional(rest, flags2 &&& 0x20, :uint16)
    {status, rest} = optional(rest, flags1 &&& 0x10, :uint16)
    {major, rest} = optional(rest, flags1 &&& 0x20, :uint32)
    {minor, rest} = optional(rest, flags1 &&& 0x40, :uint32)

    %DataSetMessage{
      writer_id: id,
      valid: (flags1 &&& 0x01) != 0,
      type: type,
      encoding: encoding,
      sequence_number: sequence,
      timestamp: timestamp,
      picoseconds: picoseconds,
      status: status,
      major_version: major,
      minor_version: minor,
      fields: take_fields(type, encoding, rest, raw_types[id])
    }
  end

  defp take_fields(:keep_alive, _, _, _), do: []
  defp take_fields(_, :raw, rest, nil), do: rest

  defp take_fields(:delta_frame, encoding, <<count::little-16, rest::binary>>, types) do
    {fields, _} =
      Enum.map_reduce(1..count//1, rest, fn _, rest ->
        {index, rest} = Binary.take(rest, :uint16)
        {value, rest} = take_field(encoding, rest, types && Enum.at(types, index))
        {{index, value}, rest}
      end)

    fields
  end

  defp take_fields(_, :raw, rest, types) do
    {fields, _} = Enum.map_reduce(types, rest, &take_field(:raw, &2, &1))
    fields
  end

  defp take_fields(_, encoding, <<count::little-16, rest::binary>>, _) do
    {fields, _} =
      Enum.map_reduce(1..count//1, rest, fn _, rest -> take_field(encoding, rest, nil) end)

    fields
  end

  defp take_field(:variant, rest, _), do: Binary.take(rest, :variant)
  defp take_field(:data_value, rest, _), do: Binary.take(rest, :data_value)

  # A delta frame can name a raw field past the ones whose types are known.
  defp take_field(:raw, _rest, nil), do: raise(OPCUA.DecodeError, "raw field of unknown type")

  defp take_field(:raw, rest, type) do
    {value, rest} = Binary.take(rest, type)
    {{type, value}, rest}
  end
end
