defmodule OPCUA.Schema do
  @moduledoc """
  The OPC Foundation definition files yaopcua is built from.

  `schema/` holds unmodified copies of files from one release tag of the
  Foundation's [UA-Nodeset](https://github.com/OPCFoundation/UA-Nodeset)
  repository, and `mix opcua.schema TAG` swaps in another release. The modules
  that need the files read them while compiling; a running system never opens
  them.
  """

  # The bsd is XML. xmerl is only needed while compiling, so it is put on the
  # code path here rather than listed as a runtime dependency.
  Mix.ensure_application!(:xmerl)

  @dir Path.expand("../../schema", __DIR__)
  @external_resource Path.join(@dir, "VERSION")
  @version @dir |> Path.join("VERSION") |> File.read!() |> String.trim()

  @doc ~S'The UA-Nodeset release the schema comes from, e.g. `"UA-1.05.07-2026-07-30"`.'
  def version, do: @version

  @doc false
  def path(file), do: Path.join(@dir, file)

  @doc false
  # `{name, id, node_class}` for every node of namespace 0.
  def node_ids do
    for line <- lines("NodeIds.csv") do
      [name, id, class] = String.split(line, ",")
      {name, String.to_integer(id), class}
    end
  end

  @doc false
  # `{name, code, description}` for every status code.
  def status_codes do
    for line <- lines("StatusCode.csv") do
      [name, "0x" <> code, text] = String.split(line, ",", parts: 3)
      {atom(name), String.to_integer(code, 16), String.trim(text, "\"")}
    end
  end

  @doc false
  def attribute_ids do
    for line <- lines("AttributeIds.csv") do
      [name, id] = String.split(line, ",")
      {atom(name), String.to_integer(id)}
    end
  end

  @doc false
  # The structures and enumerations of Opc.Ua.Types.bsd, minus the built-in
  # types it also describes (NodeId, Variant, DataValue, ...), which
  # OPCUA.Binary encodes by hand. A structure is
  #
  #     %{kind: :struct, name: "ReadRequest", module: OPCUA.Types.ReadRequest,
  #       doc: nil, fields: [%{name: :max_age, type: :double, default: 0.0}, ...]}
  #
  # where a field type is a built-in type atom, a module of OPCUA.Types, or
  # `{:array, type}` with the `NoOfX` count folded in.
  def types do
    path = path("Opc.Ua.Types.bsd") |> String.to_charlist()

    {:ok, {raw, nil, false}, _} =
      :xmerl_sax_parser.file(path, event_fun: &event/3, event_state: {[], nil, false})

    enums = for %{kind: :enum} = t <- raw, into: %{}, do: {t.name, t}

    for t <- Enum.reverse(raw), t = normalize(t, enums), do: t
  end

  defp event({:startElement, _, ~c"StructuredType", _, attrs}, _, {done, nil, false}),
    do:
      {done,
       %{
         kind: :struct,
         name: attr(attrs, "Name"),
         base: attr(attrs, "BaseType"),
         fields: [],
         doc: nil
       }, false}

  defp event({:startElement, _, ~c"EnumeratedType", _, attrs}, _, {done, nil, false}) do
    bits = String.to_integer(attr(attrs, "LengthInBits"))
    option_set = attr(attrs, "IsOptionSet") == "true"

    {done,
     %{
       kind: :enum,
       name: attr(attrs, "Name"),
       bits: bits,
       option_set: option_set,
       values: [],
       doc: nil
     }, false}
  end

  defp event({:startElement, _, ~c"Field", _, attrs}, _, {done, %{kind: :struct} = t, false}) do
    field = %{
      name: attr(attrs, "Name"),
      type: attr(attrs, "TypeName"),
      length_field: attr(attrs, "LengthField")
    }

    {done, %{t | fields: [field | t.fields]}, false}
  end

  defp event(
         {:startElement, _, ~c"EnumeratedValue", _, attrs},
         _,
         {done, %{kind: :enum} = t, false}
       ) do
    value = {attr(attrs, "Name"), String.to_integer(attr(attrs, "Value"))}
    {done, %{t | values: [value | t.values]}, false}
  end

  defp event({:startElement, _, ~c"Documentation", _, _}, _, {done, t, false}),
    do: {done, t, true}

  defp event({:characters, text}, _, {done, %{} = t, true}),
    do: {done, %{t | doc: (t.doc || "") <> List.to_string(text)}, true}

  defp event({:endElement, _, ~c"Documentation", _}, _, {done, t, true}), do: {done, t, false}

  defp event({:endElement, _, name, _}, _, {done, %{} = t, false})
       when name in [~c"StructuredType", ~c"EnumeratedType"],
       do:
         {[%{t | fields_or_values(t) => Enum.reverse(Map.fetch!(t, fields_or_values(t)))} | done],
          nil, false}

  defp event(_, _, state), do: state

  defp fields_or_values(%{kind: :struct}), do: :fields
  defp fields_or_values(%{kind: :enum}), do: :values

  defp attr(attrs, name) do
    Enum.find_value(attrs, fn {_, _, key, value} ->
      if List.to_string(key) == name, do: List.to_string(value)
    end)
  end

  # Built-in types have no base type in the bsd.
  defp normalize(%{kind: :struct, base: nil}, _), do: nil

  defp normalize(%{kind: :struct} = t, enums) do
    counts = for f <- t.fields, f.length_field, do: f.length_field

    fields =
      for f <- t.fields, f.name not in counts do
        type = if f.length_field, do: {:array, type(f.type)}, else: type(f.type)
        %{name: atom(f.name), type: type, default: default(type, f.type, enums)}
      end

    names = Enum.map(fields, & &1.name)

    if names != Enum.uniq(names),
      do: raise("#{t.name} has two fields with the same snake case name")

    %{kind: :struct, name: t.name, module: module(t.name), doc: doc(t.doc), fields: fields}
  end

  # NodeIdType is the 6-bit tag inside a NodeId's first byte, handled in OPCUA.Binary.
  defp normalize(%{kind: :enum, bits: bits}, _) when bits not in [8, 16, 32], do: nil

  defp normalize(%{kind: :enum} = t, _) do
    values = for {name, value} <- t.values, do: {atom(name), value}

    %{
      kind: :enum,
      name: t.name,
      module: module(t.name),
      doc: doc(t.doc),
      bits: t.bits,
      option_set: t.option_set,
      values: values
    }
  end

  @builtins %{
    "opc:Boolean" => :boolean,
    "opc:SByte" => :sbyte,
    "opc:Byte" => :byte,
    "opc:Int16" => :int16,
    "opc:UInt16" => :uint16,
    "opc:Int32" => :int32,
    "opc:UInt32" => :uint32,
    "opc:Int64" => :int64,
    "opc:UInt64" => :uint64,
    "opc:Float" => :float,
    "opc:Double" => :double,
    "opc:String" => :string,
    "opc:CharArray" => :string,
    "opc:DateTime" => :date_time,
    "opc:Guid" => :guid,
    "opc:ByteString" => :byte_string,
    "ua:XmlElement" => :xml_element,
    "ua:NodeId" => :node_id,
    "ua:ExpandedNodeId" => :expanded_node_id,
    "ua:StatusCode" => :status_code,
    "ua:QualifiedName" => :qualified_name,
    "ua:LocalizedText" => :localized_text,
    "ua:ExtensionObject" => :extension_object,
    "ua:DataValue" => :data_value,
    "ua:Variant" => :variant,
    "ua:DiagnosticInfo" => :diagnostic_info
  }

  defp type("tns:" <> name), do: module(name)
  defp type(name), do: Map.fetch!(@builtins, name)

  defp default({:array, _}, _, _), do: nil
  defp default(:boolean, _, _), do: false
  defp default(type, _, _) when type in [:float, :double], do: 0.0

  defp default(type, _, _)
       when type in [
              :sbyte,
              :byte,
              :int16,
              :uint16,
              :int32,
              :uint32,
              :int64,
              :uint64,
              :status_code
            ],
       do: 0

  defp default(_, "tns:" <> name, enums) do
    case enums do
      %{^name => %{option_set: true}} ->
        0

      %{^name => %{values: values}} ->
        values |> List.keyfind(0, 1, hd(values)) |> elem(0) |> atom()

      _ ->
        nil
    end
  end

  defp default(_, _, _), do: nil

  defp module(name), do: Module.concat(OPCUA.Types, name)

  @doc false
  def atom(name), do: name |> Macro.underscore() |> String.to_atom()

  @doc false
  # How a field type reads in the generated docs.
  def describe({:array, type}), do: "list of " <> describe(type)

  def describe(type) do
    case Atom.to_string(type) do
      "Elixir." <> name -> "`#{name}`"
      _ -> "`#{inspect(type)}`"
    end
  end

  defp doc(nil), do: nil
  defp doc(text), do: text |> String.split() |> Enum.join(" ")

  defp lines(file), do: file |> path() |> File.read!() |> String.split(["\r\n", "\n"], trim: true)
end
