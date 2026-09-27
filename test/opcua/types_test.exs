defmodule OPCUA.TypesTest do
  use ExUnit.Case, async: true

  alias OPCUA.Types

  # See test/vectors/generate_asyncua.py.
  @vectors Path.expand("../vectors/asyncua.txt", __DIR__)

  defp vectors do
    for line <- File.stream!(@vectors) do
      [name, prefixed | hex] = line |> String.trim() |> String.split(" ")
      {name, prefixed == "1", Base.decode16!(Enum.join(hex), case: :lower)}
    end
  end

  # asyncua writes a DataValue's status even when it's Good, and yaopcua leaves
  # it out, which the spec treats as the same value. Where a structure holds a
  # DataValue, the re-encoding is compared by value instead of by bytes.
  defp data_value?(%OPCUA.DataValue{}), do: true
  defp data_value?(%{} = map), do: map |> Map.values() |> Enum.any?(&data_value?/1)
  defp data_value?(list) when is_list(list), do: Enum.any?(list, &data_value?/1)
  defp data_value?(_), do: false

  test "decodes what asyncua encodes, and encodes it back the same" do
    checked =
      for {name, prefixed, bytes} <- vectors(),
          module = Module.concat(Types, name),
          # asyncua splits requests into helper structures that aren't in the spec
          Code.ensure_loaded?(module) do
        body =
          if prefixed do
            {:ok, %OPCUA.NodeId{ns: 0, id: id}, body} = OPCUA.Binary.decode(bytes, :node_id)
            assert id == module.encoding_id(), name
            body
          else
            bytes
          end

        assert {:ok, value, ""} = OPCUA.Binary.decode(body, module), name
        again = value |> module.encode() |> IO.iodata_to_binary()

        if data_value?(value) do
          assert {:ok, ^value, ""} = OPCUA.Binary.decode(again, module), name
        else
          assert again == body, name
        end

        name
      end

    # Most of the spec's structures, each with three random fillings.
    assert length(Enum.uniq(checked)) > 330
  end

  test "every structure encodes its defaults and decodes them again" do
    for {:module, module} <- modules(), function_exported?(module, :type_id, 0) do
      once = module |> struct() |> module.encode() |> IO.iodata_to_binary()
      {:ok, value, ""} = OPCUA.Binary.decode(once, module)
      assert value |> module.encode() |> IO.iodata_to_binary() == once, inspect(module)
    end
  end

  defp modules do
    {:ok, modules} = :application.get_key(:yaopcua, :modules)

    for module <- modules,
        match?("Elixir.OPCUA.Types." <> _, Atom.to_string(module)),
        do: {:module, module}
  end

  test "structures know their ids, and the registry finds them by encoding id" do
    assert Types.ReadRequest.type_id() == 629
    assert Types.ReadRequest.encoding_id() == 631
    assert Types.by_encoding(631) == Types.ReadRequest
    assert Types.by_encoding(1) == nil
  end

  test "fields are the spec's in snake case, with array counts folded in" do
    assert %Types.ReadRequest{
             max_age: +0.0,
             timestamps_to_return: :source,
             nodes_to_read: nil,
             request_header: nil
           } =
             %Types.ReadRequest{}
  end

  test "enumerations are atoms, and a number the release doesn't know stays a number" do
    assert Types.NodeClass.encode(:variable) |> IO.iodata_to_binary() == <<2, 0, 0, 0>>
    assert Types.NodeClass.decode(<<2, 0, 0, 0, 9>>) == {:variable, <<9>>}
    assert Types.NodeClass.decode(<<3, 0, 0, 0>>) == {3, ""}
    assert Types.NodeClass.encode(3) |> IO.iodata_to_binary() == <<3, 0, 0, 0>>
    assert_raise ArgumentError, fn -> Types.NodeClass.encode(:nope) end
  end

  test "option sets are integers, with helpers for the flag names" do
    assert Types.PermissionType.flags(0b101) == [:browse, :write_attribute]
    assert Types.PermissionType.mask([:browse, :write_attribute]) == 0b101
    assert Types.PermissionType.encode([:browse]) |> IO.iodata_to_binary() == <<1, 0, 0, 0>>
    assert Types.PermissionType.decode(<<5, 0, 0, 0>>) == {5, ""}
  end

  test "a structure field left nil encodes as that structure's defaults" do
    assert Types.ReadValueId.encode(nil) |> IO.iodata_to_binary() ==
             Types.ReadValueId.encode(%Types.ReadValueId{}) |> IO.iodata_to_binary()
  end

  test "a known structure inside an ExtensionObject decodes into its struct" do
    token = %Types.AnonymousIdentityToken{policy_id: "anonymous"}
    bytes = OPCUA.Binary.encode(token, :extension_object) |> IO.iodata_to_binary()
    assert <<1, 0, 65, 1, 1, 13::little-32, _::binary>> = bytes
    assert OPCUA.Binary.decode(bytes, :extension_object) == {:ok, token, ""}
  end
end
