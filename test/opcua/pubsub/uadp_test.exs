defmodule OPCUA.PubSub.UADPTest do
  use ExUnit.Case, async: true

  alias OPCUA.{DataValue, Variant}
  alias OPCUA.PubSub.UADP
  alias OPCUA.PubSub.UADP.DataSetMessage

  # Captured from asyncua publishing a dataset of Speed (Int16) 2, Level
  # (Double) 2.5, Name (String) "Pump 1" and Running (Boolean) true, as
  # writer 7 in group 3 of publisher 42 (UInt16).
  @asyncua %{
    variant:
      "F1012A000F0300000000000100030001070099100400600D113BBE4EDD01000004000402000B00000000000004400C0600000050756D7020310101",
    data_value:
      "F1012A000F030000000000010003000107000D040004000304020000000000030B000000000000044000000000030C0600000050756D7020310000000003010100000000",
    raw:
      "F1012A000F030000000000010003000107009B100400E0FEA13DBE4EDD010000020000000000000004400600000050756D70203101"
  }

  @types [:int16, :double, :string, :boolean]

  defp round_trip(message, types \\ %{}) do
    bytes = message |> UADP.encode() |> IO.iodata_to_binary()
    {:ok, decoded} = UADP.decode(bytes, types)
    decoded
  end

  test "decodes what asyncua publishes, in each field encoding" do
    for {encoding, hex} <- @asyncua do
      bytes = Base.decode16!(hex)
      assert {:ok, message} = UADP.decode(bytes, %{7 => @types})

      assert %UADP{
               publisher_id: {:uint16, 42},
               writer_group_id: 3,
               sequence_number: 3,
               messages: [dataset]
             } = message

      assert %DataSetMessage{
               writer_id: 7,
               type: :key_frame,
               encoding: ^encoding,
               sequence_number: 4
             } = dataset

      values =
        for field <- dataset.fields do
          case field do
            %Variant{value: value} -> value
            %DataValue{value: %Variant{value: value}} -> value
            {_type, value} -> value
          end
        end

      assert values == [2, 2.5, "Pump 1", true]
    end
  end

  test "encodes Variant and raw fields exactly as asyncua does" do
    for encoding <- [:variant, :raw] do
      bytes = Base.decode16!(@asyncua[encoding])
      {:ok, message} = UADP.decode(bytes, %{7 => @types})
      assert message |> UADP.encode() |> IO.iodata_to_binary() == bytes
    end
  end

  test "round trips every kind of header" do
    message = %UADP{
      publisher_id: {:string, "plc-7"},
      dataset_class_id: "72962B91-FA75-4AE6-8D28-B404DC7DAF63",
      writer_group_id: 9,
      group_version: 123_456,
      network_message_number: 1,
      sequence_number: 65_535,
      timestamp: ~U[2026-09-27 12:00:00.000000Z],
      picoseconds: 7,
      messages: [
        %DataSetMessage{
          writer_id: 1,
          sequence_number: 5,
          timestamp: ~U[2026-09-27 12:00:00.000000Z],
          picoseconds: 3,
          status: 0x8000,
          major_version: 1,
          minor_version: 2,
          fields: [%Variant{type: :int32, value: -5}, nil]
        },
        %DataSetMessage{
          writer_id: 2,
          type: :delta_frame,
          encoding: :data_value,
          fields: [{3, %DataValue{value: %Variant{type: :double, value: 1.5}}}]
        },
        %DataSetMessage{writer_id: 3, type: :keep_alive, sequence_number: 9},
        %DataSetMessage{writer_id: 4, encoding: :raw, fields: [{:uint32, 7}, {:string, "x"}]}
      ]
    }

    assert round_trip(message, %{4 => [:uint32, :string]}) == message
  end

  test "publisher ids of every integer size" do
    for id <- [{:byte, 1}, {:uint16, 300}, {:uint32, 70_000}, {:uint64, Bitwise.bsl(1, 40)}] do
      message = %UADP{
        publisher_id: id,
        writer_group_id: 1,
        messages: [%DataSetMessage{writer_id: 1, fields: []}]
      }

      assert round_trip(message).publisher_id == id
    end
  end

  test "raw fields without their types are kept as bytes" do
    message = %UADP{
      publisher_id: {:byte, 1},
      messages: [%DataSetMessage{writer_id: 1, encoding: :raw, fields: [{:int16, 5}]}]
    }

    assert [%DataSetMessage{fields: <<5, 0>>}] = round_trip(message).messages
  end

  test "malformed or unsupported messages are errors" do
    assert UADP.decode(<<>>) == {:error, :bad_decoding_error}
    assert UADP.decode(<<0x02>>) == {:error, :bad_decoding_error}
    # a chunked message, in the second extended flags
    assert UADP.decode(<<0x91, 0x80, 0x01, 42>>) == {:error, :bad_decoding_error}
    # a dataset claiming more bytes than there are
    assert UADP.decode(<<0x71, 1, 0x01, 1, 0, 2, 1, 0, 2, 0>>) == {:error, :bad_decoding_error}
  end
end
