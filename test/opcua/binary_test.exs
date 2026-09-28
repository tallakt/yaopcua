defmodule OPCUA.BinaryTest do
  use ExUnit.Case, async: true

  alias OPCUA.{
    DataValue,
    DiagnosticInfo,
    ExpandedNodeId,
    ExtensionObject,
    LocalizedText,
    NodeId,
    QualifiedName,
    Variant
  }

  doctest OPCUA.Binary

  defp encode(value, type), do: value |> OPCUA.Binary.encode(type) |> IO.iodata_to_binary()

  # Encodes, checks the bytes, and checks they decode back to the value.
  defp both(value, type, bytes) do
    assert encode(value, type) == bytes
    assert OPCUA.Binary.decode(bytes <> <<0xEE>>, type) == {:ok, value, <<0xEE>>}
  end

  describe "numbers" do
    test "are little-endian, signed where the type is" do
      both(true, :boolean, <<1>>)
      both(-2, :sbyte, <<0xFE>>)
      both(200, :byte, <<200>>)
      both(-2, :int16, <<0xFE, 0xFF>>)
      both(0xBEEF, :uint16, <<0xEF, 0xBE>>)
      both(-2, :int32, <<0xFE, 0xFF, 0xFF, 0xFF>>)
      both(0xDEADBEEF, :uint32, <<0xEF, 0xBE, 0xAD, 0xDE>>)
      both(-2, :int64, <<0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF>>)
      both(0xFFFF_FFFF_FFFF_FFFF, :uint64, <<0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF>>)
      both(1.5, :float, <<0, 0, 0xC0, 0x3F>>)
      both(1.5, :double, <<0, 0, 0, 0, 0, 0, 0xF8, 0x3F>>)
    end

    test "any non-zero byte is true" do
      assert OPCUA.Binary.decode(<<7>>, :boolean) == {:ok, true, ""}
    end

    test "floats that aren't numbers become atoms" do
      both(:nan, :float, <<0, 0, 0xC0, 0xFF>>)
      both(:infinity, :float, <<0, 0, 0x80, 0x7F>>)
      both(:neg_infinity, :double, <<0, 0, 0, 0, 0, 0, 0xF0, 0xFF>>)
      # any NaN payload is NaN
      assert OPCUA.Binary.decode(<<1, 0, 0x80, 0x7F>>, :float) == {:ok, :nan, ""}
    end

    test "a value out of range raises instead of wrapping around" do
      assert_raise ArgumentError, fn -> encode(256, :byte) end
      assert_raise ArgumentError, fn -> encode(-1, :uint32) end
      assert_raise ArgumentError, fn -> encode(0x8000, :int16) end
      assert_raise ArgumentError, fn -> encode(1.0, :int32) end
    end
  end

  describe "strings" do
    test "have an Int32 length, and -1 is null" do
      both("Hot水", :string, <<6, 0, 0, 0, "Hot", 0xE6, 0xB0, 0xB4>>)
      both("", :string, <<0, 0, 0, 0>>)
      both(nil, :string, <<0xFF, 0xFF, 0xFF, 0xFF>>)
      both(<<1, 2>>, :byte_string, <<2, 0, 0, 0, 1, 2>>)
      both("<a/>", :xml_element, <<4, 0, 0, 0, "<a/>">>)
    end

    test "a length past the end of the message is an error" do
      assert OPCUA.Binary.decode(<<9, 0, 0, 0, "abc">>, :string) == {:error, :bad_decoding_error}
    end
  end

  describe "DateTime" do
    test "counts 100 ns ticks from 1601" do
      # 116444736000000000 ticks from 1601-01-01 to 1970-01-01
      both(
        ~U[1970-01-01 00:00:00.000000Z],
        :date_time,
        <<0x00, 0x80, 0x3E, 0xD5, 0xDE, 0xB1, 0x9D, 0x01>>
      )
    end

    test "keeps microseconds and drops the last 100 ns digit" do
      ticks = 116_444_736_000_000_000 + 1_234_567

      assert OPCUA.Binary.decode(<<ticks::little-64>>, :date_time) ==
               {:ok, ~U[1970-01-01 00:00:00.123456Z], ""}
    end

    test "0 is nil, and the end of time is the largest Int64" do
      both(nil, :date_time, <<0::64>>)
      assert encode(~U[9999-12-31 23:59:59Z], :date_time) == <<0x7FFF_FFFF_FFFF_FFFF::little-64>>

      assert {:ok, ~U[9999-12-31 23:59:59.999999Z], ""} =
               OPCUA.Binary.decode(<<0x7FFF_FFFF_FFFF_FFFF::little-64>>, :date_time)

      assert encode(~U[1500-01-01 00:00:00Z], :date_time) == <<0::64>>
      assert OPCUA.Binary.decode(<<-5::little-signed-64>>, :date_time) == {:ok, nil, ""}
    end
  end

  test "a Guid is its text form, laid out as in Windows" do
    both(
      "72962B91-FA75-4AE6-8D28-B404DC7DAF63",
      :guid,
      <<0x91, 0x2B, 0x96, 0x72, 0x75, 0xFA, 0xE6, 0x4A, 0x8D, 0x28, 0xB4, 0x04, 0xDC, 0x7D, 0xAF,
        0x63>>
    )

    assert encode("72962b91-fa75-4ae6-8d28-b404dc7daf63", :guid) ==
             encode("72962B91-FA75-4AE6-8D28-B404DC7DAF63", :guid)
  end

  describe "NodeId" do
    test "uses the shortest form that fits" do
      both(%NodeId{ns: 0, id: 72}, :node_id, <<0, 72>>)
      both(%NodeId{ns: 5, id: 1025}, :node_id, <<1, 5, 1, 4>>)
      both(%NodeId{ns: 0, id: 1025}, :node_id, <<1, 0, 1, 4>>)
      both(%NodeId{ns: 300, id: 7}, :node_id, <<2, 44, 1, 7, 0, 0, 0>>)
      both(%NodeId{ns: 1, id: 70_000}, :node_id, <<2, 1, 0, 0x70, 0x11, 0x01, 0x00>>)
      both(%NodeId{ns: 1, id: "Hot"}, :node_id, <<3, 1, 0, 3, 0, 0, 0, "Hot">>)
      both(%NodeId{ns: 1, id: {:opaque, <<9, 8>>}}, :node_id, <<5, 1, 0, 2, 0, 0, 0, 9, 8>>)

      both(
        %NodeId{ns: 2, id: {:guid, "72962B91-FA75-4AE6-8D28-B404DC7DAF63"}},
        :node_id,
        <<4, 2, 0, 0x91, 0x2B, 0x96, 0x72, 0x75, 0xFA, 0xE6, 0x4A, 0x8D, 0x28, 0xB4, 0x04, 0xDC,
          0x7D, 0xAF, 0x63>>
      )
    end

    test "the null node id is nil" do
      both(nil, :node_id, <<0, 0>>)
      assert OPCUA.Binary.decode(<<2, 0, 0, 0, 0, 0, 0>>, :node_id) == {:ok, nil, ""}
    end

    test "an unknown form is an error" do
      assert OPCUA.Binary.decode(<<6, 0, 0>>, :node_id) == {:error, :bad_decoding_error}
    end
  end

  test "an ExpandedNodeId flags its namespace URI and server index in the first byte" do
    both(%ExpandedNodeId{ns: 0, id: 72}, :expanded_node_id, <<0, 72>>)

    both(
      %ExpandedNodeId{id: 72, namespace_uri: "urn:a", server_index: 2},
      :expanded_node_id,
      <<0xC0, 72, 5, 0, 0, 0, "urn:a", 2, 0, 0, 0>>
    )

    both(
      %ExpandedNodeId{ns: 3, id: "x", server_index: 1},
      :expanded_node_id,
      <<0x43, 3, 0, 1, 0, 0, 0, "x", 1, 0, 0, 0>>
    )

    both(nil, :expanded_node_id, <<0, 0>>)
  end

  test "a StatusCode is a UInt32, and can be given by name" do
    both(0x80340000, :status_code, <<0, 0, 0x34, 0x80>>)
    assert encode(:bad_node_id_unknown, :status_code) == <<0, 0, 0x34, 0x80>>
  end

  test "a QualifiedName is a namespace index and a name" do
    both(%QualifiedName{ns: 2, name: "Speed"}, :qualified_name, <<2, 0, 5, 0, 0, 0, "Speed">>)
    both(nil, :qualified_name, <<0, 0, 0xFF, 0xFF, 0xFF, 0xFF>>)
  end

  test "a LocalizedText flags which of locale and text it has" do
    both(%LocalizedText{text: "Hi"}, :localized_text, <<2, 2, 0, 0, 0, "Hi">>)

    both(
      %LocalizedText{locale: "en", text: "Hi"},
      :localized_text,
      <<3, 2, 0, 0, 0, "en", 2, 0, 0, 0, "Hi">>
    )

    both(nil, :localized_text, <<0>>)
  end

  describe "Variant" do
    test "a scalar is its type id and the value" do
      both(%Variant{type: :int32, value: 42}, :variant, <<6, 42, 0, 0, 0>>)
      both(%Variant{type: :string, value: nil}, :variant, <<12, 0xFF, 0xFF, 0xFF, 0xFF>>)
      both(nil, :variant, <<0>>)
    end

    test "an array sets the top bit, and dimensions the next" do
      both(%Variant{type: :int16, value: [1, 2]}, :variant, <<0x80 + 4, 2, 0, 0, 0, 1, 0, 2, 0>>)

      both(
        %Variant{type: :byte, value: [1, 2, 3, 4], dimensions: [2, 2]},
        :variant,
        <<0xC3, 4, 0, 0, 0, 1, 2, 3, 4, 2, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0>>
      )

      # a null array has no elements
      assert OPCUA.Binary.decode(<<0x86, 0xFF, 0xFF, 0xFF, 0xFF>>, :variant) ==
               {:ok, %Variant{type: :int32, value: []}, ""}
    end

    test "can hold variants, data values and extension objects" do
      both(
        %Variant{type: :variant, value: [%Variant{type: :boolean, value: true}, nil]},
        :variant,
        <<0x80 + 24, 2, 0, 0, 0, 1, 1, 0>>
      )

      both(
        %Variant{type: :data_value, value: %DataValue{value: %Variant{type: :byte, value: 7}}},
        :variant,
        <<23, 1, 3, 7>>
      )
    end

    test "a type id past 25 is an error" do
      assert OPCUA.Binary.decode(<<30, 0>>, :variant) == {:error, :bad_decoding_error}
    end

    test "raises on a type that isn't built in" do
      assert_raise ArgumentError, fn -> encode(%Variant{type: :int, value: 1}, :variant) end
    end
  end

  describe "DataValue" do
    test "flags the fields it has, in the spec's order" do
      value = %DataValue{
        value: %Variant{type: :byte, value: 7},
        status: 0x80340000,
        source_timestamp: ~U[1970-01-01 00:00:00.000000Z],
        source_picoseconds: 5,
        server_timestamp: ~U[1970-01-01 00:00:00.000000Z],
        server_picoseconds: 6
      }

      epoch = <<0x00, 0x80, 0x3E, 0xD5, 0xDE, 0xB1, 0x9D, 0x01>>

      both(
        value,
        :data_value,
        <<0x3F, 3, 7, 0, 0, 0x34, 0x80>> <> epoch <> <<5, 0>> <> epoch <> <<6, 0>>
      )
    end

    test "leaves out a Good status and zero picoseconds" do
      both(%DataValue{value: %Variant{type: :byte, value: 7}}, :data_value, <<0x01, 3, 7>>)
      both(%DataValue{}, :data_value, <<0>>)
      assert OPCUA.Binary.decode(<<0x02, 0, 0, 0, 0>>, :data_value) == {:ok, %DataValue{}, ""}
    end
  end

  test "a DiagnosticInfo flags its fields, and may nest" do
    info = %DiagnosticInfo{
      symbolic_id: 1,
      locale: 2,
      additional_info: "x",
      inner_diagnostic_info: %DiagnosticInfo{inner_status_code: 0x80340000}
    }

    both(
      info,
      :diagnostic_info,
      <<0x59, 1, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, "x", 0x20, 0, 0, 0x34, 0x80>>
    )

    both(nil, :diagnostic_info, <<0>>)
  end

  describe "ExtensionObject" do
    test "one of a type this library doesn't know keeps its body" do
      value = %ExtensionObject{
        type_id: %NodeId{ns: 2, id: 5001},
        encoding: :binary,
        body: <<1, 2, 3>>
      }

      both(value, :extension_object, <<1, 2, 0x89, 0x13, 1, 3, 0, 0, 0, 1, 2, 3>>)
    end

    test "an XML body is kept as text" do
      value = %ExtensionObject{type_id: %NodeId{ns: 2, id: 5}, encoding: :xml, body: "<v/>"}
      both(value, :extension_object, <<1, 2, 5, 0, 2, 4, 0, 0, 0, "<v/>">>)
    end

    test "one with no body keeps its type id, and the null one is nil" do
      both(%ExtensionObject{type_id: %NodeId{ns: 2, id: 5}}, :extension_object, <<1, 2, 5, 0, 0>>)
      both(nil, :extension_object, <<0, 0, 0>>)
    end

    test "a known structure's body may be longer than this release expects" do
      body = <<9, 0, 0, 0, "anonymous", "extra">>
      bytes = <<1, 0, 65, 1, 1, byte_size(body)::little-32>> <> body

      assert OPCUA.Binary.decode(bytes, :extension_object) ==
               {:ok, %OPCUA.Types.AnonymousIdentityToken{policy_id: "anonymous"}, ""}
    end
  end

  describe "arrays" do
    test "have an Int32 count, and -1 is null" do
      both([1, 2], {:array, :uint16}, <<2, 0, 0, 0, 1, 0, 2, 0>>)
      both([], {:array, :uint16}, <<0, 0, 0, 0>>)
      both(nil, {:array, :uint16}, <<0xFF, 0xFF, 0xFF, 0xFF>>)
    end

    test "a count longer than the message fails without allocating it" do
      assert OPCUA.Binary.decode(<<0xFF, 0xFF, 0xFF, 0x7F, 1, 2>>, {:array, :byte}) ==
               {:error, :bad_decoding_error}
    end
  end

  test "values nested more than 100 deep are rejected" do
    nested =
      Enum.reduce(
        1..101,
        %Variant{type: :byte, value: 1},
        &%Variant{type: :variant, value: [&2 || &1]}
      )

    bytes = encode(nested, :variant)
    assert OPCUA.Binary.decode(bytes, :variant) == {:error, :bad_decoding_error}

    info =
      Enum.reduce(
        1..101,
        %DiagnosticInfo{symbolic_id: 1},
        &%DiagnosticInfo{inner_diagnostic_info: &2 || &1}
      )

    assert OPCUA.Binary.decode(encode(info, :diagnostic_info), :diagnostic_info) ==
             {:error, :bad_decoding_error}

    shallow =
      Enum.reduce(
        1..99,
        %Variant{type: :byte, value: 1},
        &%Variant{type: :variant, value: [&2 || &1]}
      )

    assert {:ok, ^shallow, ""} = OPCUA.Binary.decode(encode(shallow, :variant), :variant)
  end

  test "truncated input is an error for every built-in type" do
    for type <- OPCUA.Binary.builtins(),
        type not in [:variant, :data_value, :diagnostic_info, :localized_text] do
      assert OPCUA.Binary.decode(<<>>, type) == {:error, :bad_decoding_error}, inspect(type)
    end

    assert OPCUA.Binary.decode(<<6, 1, 2>>, :variant) == {:error, :bad_decoding_error}
    assert OPCUA.Binary.decode(<<1>>, :data_value) == {:error, :bad_decoding_error}
    assert OPCUA.Binary.decode(<<2, 1>>, :localized_text) == {:error, :bad_decoding_error}
  end

  test "every built-in type's default encodes, as a scalar and in a variant" do
    for type <- OPCUA.Binary.builtins() do
      value = OPCUA.Binary.default(type)
      assert {:ok, _, ""} = OPCUA.Binary.decode(encode(value, type), type), inspect(type)
      assert encode(%Variant{type: type, value: value}, :variant)
    end
  end

  test "decoded strings don't hold on to the message they came from" do
    message = <<5, 0, 0, 0, "Speed">> <> :binary.copy(<<0>>, 100_000)
    {:ok, text, _} = OPCUA.Binary.decode(message, :string)
    assert :binary.referenced_byte_size(text) < 100
  end
end
