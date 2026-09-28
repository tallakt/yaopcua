defmodule OPCUA.Binary do
  @moduledoc """
  The OPC UA binary encoding (Part 6, section 5.2).

  `encode/2` turns a value into iodata and `decode/2` reads one back. Both take
  the value's type, which is one of:

    * a built-in type: `:boolean`, `:sbyte`, `:byte`, `:int16`, `:uint16`,
      `:int32`, `:uint32`, `:int64`, `:uint64`, `:float`, `:double`,
      `:string`, `:date_time`, `:guid`, `:byte_string`, `:xml_element`,
      `:node_id`, `:expanded_node_id`, `:status_code`, `:qualified_name`,
      `:localized_text`, `:extension_object`, `:data_value`, `:variant` or
      `:diagnostic_info`
    * a structure or enumeration module of `OPCUA.Types`
    * `{:array, type}`, a list of that type; `nil` is the null array

  ```
  iex> OPCUA.Binary.encode(%OPCUA.NodeId{ns: 2, id: 1025}, :node_id) |> IO.iodata_to_binary()
  <<1, 2, 1, 4>>
  iex> OPCUA.Binary.decode(<<1, 2, 1, 4, 99>>, :node_id)
  {:ok, %OPCUA.NodeId{ns: 2, id: 1025}, <<99>>}
  ```

  What the values look like:

    * Integers and floats are numbers. A float that isn't a number is `:nan`,
      `:infinity` or `:neg_infinity`.
    * String, ByteString and XmlElement are binaries, and `nil` when null.
      XML is carried as text and never parsed.
    * DateTime is a UTC `DateTime`. OPC UA counts 100 ns ticks and `DateTime`
      stops at microseconds, so the last digit is dropped. 0 is `nil`, and
      anything from 9999-12-31 23:59:59 on is the spec's end of time.
    * Guid is a string: `"72962B91-FA75-4AE6-8D28-B404DC7DAF63"`.
    * StatusCode is an integer; `encode/2` also takes a name from
      `OPCUA.StatusCode`, such as `:bad_node_id_unknown`.
    * The rest are `OPCUA.NodeId`, `OPCUA.ExpandedNodeId`,
      `OPCUA.QualifiedName`, `OPCUA.LocalizedText`, `OPCUA.Variant`,
      `OPCUA.DataValue` and `OPCUA.DiagnosticInfo`. An ExtensionObject is the
      `OPCUA.Types` structure it holds, or an `OPCUA.ExtensionObject` for a
      type this library doesn't know.

  The null value of a NodeId, ExpandedNodeId, QualifiedName, LocalizedText,
  ExtensionObject, Variant or DiagnosticInfo decodes as `nil`, and `nil`
  encodes as it.
  """

  import Bitwise

  alias OPCUA.{
    DataValue,
    DecodeError,
    DiagnosticInfo,
    ExpandedNodeId,
    ExtensionObject,
    LocalizedText,
    NodeId,
    QualifiedName,
    Variant
  }

  @builtins ~w(boolean sbyte byte int16 uint16 int32 uint32 int64 uint64 float double string date_time guid
               byte_string xml_element node_id expanded_node_id status_code qualified_name localized_text
               extension_object data_value variant diagnostic_info)a

  @type builtin ::
          :boolean
          | :sbyte
          | :byte
          | :int16
          | :uint16
          | :int32
          | :uint32
          | :int64
          | :uint64
          | :float
          | :double
          | :string
          | :date_time
          | :guid
          | :byte_string
          | :xml_element
          | :node_id
          | :expanded_node_id
          | :status_code
          | :qualified_name
          | :localized_text
          | :extension_object
          | :data_value
          | :variant
          | :diagnostic_info

  @type type :: builtin | module | {:array, type}

  # A built-in type's id (Part 6, table 1) is its position in @builtins, from 1.
  @type_ids @builtins |> Enum.with_index(1) |> Map.new()
  @type_names Map.new(@type_ids, fn {name, id} -> {id, name} end)

  @strings [:string, :byte_string, :xml_element]

  # 1601-01-01, where OPC UA time starts, to 1970-01-01, in 100 ns ticks.
  @epoch 116_444_736_000_000_000
  @end_ticks DateTime.to_unix(~U[9999-12-31 23:59:59Z]) * 10_000_000 + @epoch
  @end_of_time ~U[9999-12-31 23:59:59.999999Z]

  # How deep variants, data values and diagnostic infos may nest in each other.
  @max_depth 100

  @doc false
  def builtins, do: @builtins

  @doc "The built-in type with this id (1 to 25), or `nil`."
  @spec type_name(non_neg_integer) :: builtin | nil
  def type_name(id), do: Map.get(@type_names, id)

  @doc "The id (1 to 25) of a built-in type."
  @spec type_id(builtin) :: pos_integer
  def type_id(type), do: Map.fetch!(@type_ids, type)

  @doc """
  The value a built-in type has when none is given: 0, 0.0 or false for the
  numbers, StatusCode and Boolean, and `nil`, which encodes as the null
  value, for the rest.
  """
  @spec default(builtin) :: term
  def default(type) when type in [:float, :double], do: 0.0
  def default(:boolean), do: false

  def default(type)
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

  def default(type) when type in @builtins, do: nil

  @doc """
  Encodes `value` as `type`.

  Raises `ArgumentError` when the value doesn't fit, such as 300 as a `:byte`.
  """
  @spec encode(term, type) :: iodata
  def encode(value, type)

  def encode(true, :boolean), do: <<1>>
  def encode(false, :boolean), do: <<0>>
  def encode(v, :sbyte) when v in -0x80..0x7F, do: <<v::signed>>
  def encode(v, :byte) when v in 0..0xFF, do: <<v>>
  def encode(v, :int16) when v in -0x8000..0x7FFF, do: <<v::little-signed-16>>
  def encode(v, :uint16) when v in 0..0xFFFF, do: <<v::little-16>>
  def encode(v, :int32) when v in -0x8000_0000..0x7FFF_FFFF, do: <<v::little-signed-32>>
  def encode(v, :uint32) when v in 0..0xFFFF_FFFF, do: <<v::little-32>>

  def encode(v, :int64) when v in -0x8000_0000_0000_0000..0x7FFF_FFFF_FFFF_FFFF,
    do: <<v::little-signed-64>>

  def encode(v, :uint64) when v in 0..0xFFFF_FFFF_FFFF_FFFF, do: <<v::little-64>>

  def encode(v, :float) when is_number(v), do: <<v::little-float-32>>
  def encode(:nan, :float), do: <<0xFFC00000::little-32>>
  def encode(:infinity, :float), do: <<0x7F800000::little-32>>
  def encode(:neg_infinity, :float), do: <<0xFF800000::little-32>>
  def encode(v, :double) when is_number(v), do: <<v::little-float-64>>
  def encode(:nan, :double), do: <<0xFFF8000000000000::little-64>>
  def encode(:infinity, :double), do: <<0x7FF0000000000000::little-64>>
  def encode(:neg_infinity, :double), do: <<0xFFF0000000000000::little-64>>

  def encode(nil, type) when type in @strings, do: <<-1::little-signed-32>>
  def encode(v, type) when type in @strings and is_binary(v), do: [<<byte_size(v)::little-32>>, v]

  def encode(nil, :date_time), do: <<0::64>>

  def encode(%DateTime{} = v, :date_time) do
    case DateTime.to_unix(v, :microsecond) * 10 + @epoch do
      ticks when ticks >= @end_ticks -> <<0x7FFF_FFFF_FFFF_FFFF::little-64>>
      ticks when ticks <= 0 -> <<0::64>>
      ticks -> <<ticks::little-64>>
    end
  end

  def encode(nil, :guid), do: <<0::128>>

  def encode(
        <<a::binary-8, ?-, b::binary-4, ?-, c::binary-4, ?-, d::binary-4, ?-, e::binary-12>>,
        :guid
      ),
      do:
        <<parse_hex(a)::little-32, parse_hex(b)::little-16, parse_hex(c)::little-16,
          parse_hex(d)::16, parse_hex(e)::48>>

  def encode(nil, :node_id), do: <<0, 0>>
  def encode(%NodeId{ns: ns, id: id}, :node_id), do: node_id(ns, id, 0)

  def encode(nil, :expanded_node_id), do: <<0, 0>>

  def encode(%ExpandedNodeId{} = e, :expanded_node_id) do
    uri = if e.namespace_uri, do: 0x80, else: 0
    server = if e.server_index != 0, do: 0x40, else: 0

    [
      node_id(e.ns, e.id, uri ||| server),
      if(uri != 0, do: encode(e.namespace_uri, :string), else: []),
      if(server != 0, do: encode(e.server_index, :uint32), else: [])
    ]
  end

  def encode(v, :status_code) when is_atom(v), do: encode(OPCUA.StatusCode.code(v), :uint32)
  def encode(v, :status_code), do: encode(v, :uint32)

  def encode(nil, :qualified_name), do: encode(%QualifiedName{}, :qualified_name)

  def encode(%QualifiedName{ns: ns, name: name}, :qualified_name),
    do: [encode(ns, :uint16), encode(name, :string)]

  def encode(nil, :localized_text), do: <<0>>

  def encode(%LocalizedText{locale: locale, text: text}, :localized_text) do
    mask = if(locale, do: 0x01, else: 0) ||| if(text, do: 0x02, else: 0)

    [
      <<mask>>,
      if(locale, do: encode(locale, :string), else: []),
      if(text, do: encode(text, :string), else: [])
    ]
  end

  def encode(nil, :extension_object), do: <<0, 0, 0>>

  def encode(%ExtensionObject{type_id: id, encoding: nil}, :extension_object),
    do: [encode(id, :node_id), <<0>>]

  def encode(%ExtensionObject{type_id: id, encoding: :binary, body: body}, :extension_object),
    do: [encode(id, :node_id), <<1>>, encode(body, :byte_string)]

  def encode(%ExtensionObject{type_id: id, encoding: :xml, body: body}, :extension_object),
    do: [encode(id, :node_id), <<2>>, encode(body, :xml_element)]

  def encode(%module{} = value, :extension_object) do
    body = module.encode(value)

    [
      encode(%NodeId{id: module.encoding_id()}, :node_id),
      <<1, IO.iodata_length(body)::little-32>>,
      body
    ]
  end

  def encode(%DataValue{} = v, :data_value) do
    # Field order and mask bits from DataValue in Opc.Ua.Types.bsd.
    fields = [
      {0x01, v.value != nil, :variant, v.value},
      {0x02, v.status not in [nil, 0, :good], :status_code, v.status},
      {0x04, v.source_timestamp != nil, :date_time, v.source_timestamp},
      {0x10, v.source_picoseconds not in [nil, 0], :uint16, v.source_picoseconds},
      {0x08, v.server_timestamp != nil, :date_time, v.server_timestamp},
      {0x20, v.server_picoseconds not in [nil, 0], :uint16, v.server_picoseconds}
    ]

    mask = for {bit, true, _, _} <- fields, reduce: 0, do: (acc -> acc ||| bit)
    [<<mask>> | for({_, true, type, value} <- fields, do: encode(value, type))]
  end

  def encode(nil, :data_value), do: <<0>>
  def encode(nil, :variant), do: <<0>>

  def encode(%Variant{type: type, value: values, dimensions: dimensions}, :variant)
      when is_list(values) do
    dims = if dimensions, do: 0x40, else: 0

    [
      <<0x80 ||| dims ||| variant_type(type)>>,
      encode(values, {:array, type}),
      if(dimensions, do: encode(dimensions, {:array, :int32}), else: [])
    ]
  end

  def encode(%Variant{type: type, value: value}, :variant),
    do: [<<variant_type(type)>>, encode(value, type)]

  def encode(nil, :diagnostic_info), do: <<0>>

  def encode(%DiagnosticInfo{} = d, :diagnostic_info) do
    # Field order and mask bits from DiagnosticInfo in Opc.Ua.Types.bsd.
    fields = [
      {0x01, d.symbolic_id, :int32},
      {0x02, d.namespace_uri, :int32},
      {0x08, d.locale, :int32},
      {0x04, d.localized_text, :int32},
      {0x10, d.additional_info, :string},
      {0x20, d.inner_status_code, :status_code},
      {0x40, d.inner_diagnostic_info, :diagnostic_info}
    ]

    mask = for {bit, value, _} <- fields, value != nil, reduce: 0, do: (acc -> acc ||| bit)
    [<<mask>> | for({_, value, type} <- fields, value != nil, do: encode(value, type))]
  end

  def encode(nil, {:array, _}), do: <<-1::little-signed-32>>

  def encode(list, {:array, type}) when is_list(list),
    do: [<<length(list)::little-32>> | Enum.map(list, &encode(&1, type))]

  def encode(value, module) when is_atom(module) and module not in @builtins,
    do: module.encode(value)

  def encode(value, type),
    do: raise(ArgumentError, "cannot encode #{inspect(value)} as #{inspect(type)}")

  defp parse_hex(digits), do: String.to_integer(digits, 16)

  defp node_id(0, id, flags) when id in 0..0xFF, do: <<flags, id>>

  defp node_id(ns, id, flags) when ns in 0..0xFF and id in 0..0xFFFF,
    do: <<flags ||| 1, ns, id::little-16>>

  defp node_id(ns, id, flags) when ns in 0..0xFFFF and id in 0..0xFFFF_FFFF,
    do: <<flags ||| 2, ns::little-16, id::little-32>>

  defp node_id(ns, id, flags) when ns in 0..0xFFFF and is_binary(id),
    do: [<<flags ||| 3, ns::little-16>>, encode(id, :string)]

  defp node_id(ns, {:guid, guid}, flags) when ns in 0..0xFFFF,
    do: [<<flags ||| 4, ns::little-16>>, encode(guid, :guid)]

  defp node_id(ns, {:opaque, bytes}, flags) when ns in 0..0xFFFF,
    do: [<<flags ||| 5, ns::little-16>>, encode(bytes, :byte_string)]

  defp node_id(ns, id, _),
    do: raise(ArgumentError, "not a node id: ns #{inspect(ns)}, id #{inspect(id)}")

  defp variant_type(type) do
    case @type_ids do
      %{^type => id} -> id
      _ -> raise ArgumentError, "not a built-in type: #{inspect(type)}"
    end
  end

  @doc """
  Decodes a `type` off the front of `binary`, returning it and the bytes after it.

  Returns `{:error, :bad_decoding_error}` when the bytes aren't a valid
  encoding of the type.
  """
  @spec decode(binary, type) :: {:ok, term, binary} | {:error, :bad_decoding_error}
  def decode(binary, type) do
    {value, rest} = take(binary, type)
    {:ok, value, rest}
  rescue
    DecodeError -> {:error, :bad_decoding_error}
  end

  @doc """
  Like `decode/2`, but returns `{value, rest}` and raises `OPCUA.DecodeError`
  on malformed bytes. The generated decoders are built from this.
  """
  @spec take(binary, type) :: {term, binary}
  def take(binary, type)

  def take(<<v, rest::binary>>, :boolean), do: {v != 0, rest}
  def take(<<v::signed, rest::binary>>, :sbyte), do: {v, rest}
  def take(<<v, rest::binary>>, :byte), do: {v, rest}
  def take(<<v::little-signed-16, rest::binary>>, :int16), do: {v, rest}
  def take(<<v::little-16, rest::binary>>, :uint16), do: {v, rest}
  def take(<<v::little-signed-32, rest::binary>>, :int32), do: {v, rest}
  def take(<<v::little-32, rest::binary>>, :uint32), do: {v, rest}
  def take(<<v::little-signed-64, rest::binary>>, :int64), do: {v, rest}
  def take(<<v::little-64, rest::binary>>, :uint64), do: {v, rest}

  # A NaN or infinity doesn't match a float segment, so it falls to the second clause.
  def take(<<v::little-float-32, rest::binary>>, :float), do: {v, rest}

  def take(<<bits::little-32, rest::binary>>, :float),
    do: {not_a_number(bits, 0x7F800000, 0xFF800000), rest}

  def take(<<v::little-float-64, rest::binary>>, :double), do: {v, rest}

  def take(<<bits::little-64, rest::binary>>, :double),
    do: {not_a_number(bits, 0x7FF0000000000000, 0xFFF0000000000000), rest}

  def take(<<n::little-signed-32, rest::binary>>, type) when type in @strings and n < 0,
    do: {nil, rest}

  # Copied, so a string kept for long doesn't hold on to the whole message.
  def take(<<n::little-signed-32, v::binary-size(n), rest::binary>>, type) when type in @strings,
    do: {:binary.copy(v), rest}

  def take(<<ticks::little-signed-64, rest::binary>>, :date_time), do: {date_time(ticks), rest}

  def take(<<a::little-32, b::little-16, c::little-16, d::16, e::48, rest::binary>>, :guid) do
    parts = [{a, 8}, {b, 4}, {c, 4}, {d, 4}, {e, 12}]
    {Enum.map_join(parts, "-", fn {n, digits} -> format_hex(n, digits) end), rest}
  end

  def take(<<_flags::2, type::6, rest::binary>>, :node_id) do
    case node_id_body(type, rest) do
      {0, 0, rest} -> {nil, rest}
      {ns, id, rest} -> {%NodeId{ns: ns, id: id}, rest}
    end
  end

  def take(<<uri::1, server::1, type::6, rest::binary>>, :expanded_node_id) do
    {ns, id, rest} = node_id_body(type, rest)
    {namespace_uri, rest} = optional(rest, uri, :string, nil)
    {server_index, rest} = optional(rest, server, :uint32, 0)

    case {ns, id, namespace_uri, server_index} do
      {0, 0, nil, 0} ->
        {nil, rest}

      _ ->
        {%ExpandedNodeId{
           ns: ns,
           id: id,
           namespace_uri: namespace_uri,
           server_index: server_index
         }, rest}
    end
  end

  def take(binary, :status_code), do: take(binary, :uint32)

  def take(<<ns::little-16, rest::binary>>, :qualified_name) do
    case take(rest, :string) do
      {nil, rest} when ns == 0 -> {nil, rest}
      {name, rest} -> {%QualifiedName{ns: ns, name: name}, rest}
    end
  end

  def take(<<_::6, text::1, locale::1, rest::binary>>, :localized_text) do
    {locale, rest} = optional(rest, locale, :string, nil)
    {text, rest} = optional(rest, text, :string, nil)
    if locale || text, do: {%LocalizedText{locale: locale, text: text}, rest}, else: {nil, rest}
  end

  def take(binary, :extension_object) do
    {type_id, rest} = take(binary, :node_id)

    case rest do
      <<0, rest::binary>> ->
        {type_id && %ExtensionObject{type_id: type_id}, rest}

      <<1, rest::binary>> ->
        {body, rest} = take(rest, :byte_string)
        {structure(type_id, body), rest}

      <<2, rest::binary>> ->
        {body, rest} = take(rest, :xml_element)
        {%ExtensionObject{type_id: type_id, encoding: :xml, body: body}, rest}

      _ ->
        raise DecodeError, "bad ExtensionObject encoding"
    end
  end

  def take(binary, :data_value), do: data_value(binary, 1)
  def take(binary, :variant), do: variant(binary, 1)
  def take(binary, :diagnostic_info), do: diagnostic_info(binary, 1)

  def take(_, type) when type in @builtins,
    do: raise(DecodeError, "too short or malformed for #{type}")

  def take(binary, {:array, type}), do: array(binary, &take(&1, type))

  def take(binary, module) when is_atom(module), do: module.decode(binary)

  defp not_a_number(bits, bits, _), do: :infinity
  defp not_a_number(bits, _, bits), do: :neg_infinity
  defp not_a_number(_, _, _), do: :nan

  # Less than a microsecond after 1601 rounds to the start, which is null too.
  defp date_time(ticks) when ticks < 10, do: nil
  defp date_time(ticks) when ticks >= @end_ticks, do: @end_of_time

  defp date_time(ticks),
    do: DateTime.from_unix!(Integer.floor_div(ticks - @epoch, 10), :microsecond)

  defp format_hex(n, digits), do: n |> Integer.to_string(16) |> String.pad_leading(digits, "0")

  defp node_id_body(0, <<id, rest::binary>>), do: {0, id, rest}
  defp node_id_body(1, <<ns, id::little-16, rest::binary>>), do: {ns, id, rest}
  defp node_id_body(2, <<ns::little-16, id::little-32, rest::binary>>), do: {ns, id, rest}

  defp node_id_body(3, <<ns::little-16, rest::binary>>) do
    # A null string is no identifier; it couldn't be encoded again either.
    case take(rest, :string) do
      {nil, _} -> raise DecodeError, "NodeId with a null string"
      {id, rest} -> {ns, id, rest}
    end
  end

  defp node_id_body(4, <<ns::little-16, rest::binary>>) do
    {guid, rest} = take(rest, :guid)
    {ns, {:guid, guid}, rest}
  end

  defp node_id_body(5, <<ns::little-16, rest::binary>>) do
    {bytes, rest} = take(rest, :byte_string)
    {ns, {:opaque, bytes}, rest}
  end

  defp node_id_body(_, _), do: raise(DecodeError, "bad NodeId")

  defp optional(binary, 1, type, _), do: take(binary, type)
  defp optional(binary, 0, _, default), do: {default, binary}

  defp structure(%NodeId{ns: 0, id: id} = type_id, body) when is_binary(body) do
    case OPCUA.Types.by_encoding(id) do
      nil ->
        %ExtensionObject{type_id: type_id, encoding: :binary, body: body}

      module ->
        # A newer server may append fields this release doesn't know; they're ignored.
        {value, _} = take(body, module)
        value
    end
  end

  defp structure(type_id, body),
    do: %ExtensionObject{type_id: type_id, encoding: :binary, body: body}

  defp too_deep(depth) when depth > @max_depth,
    do: raise(DecodeError, "values nested more than #{@max_depth} deep")

  defp too_deep(_), do: :ok

  defp data_value(
         <<_::2, server_ps::1, source_ps::1, server_ts::1, source_ts::1, status::1, value::1,
           rest::binary>>,
         depth
       ) do
    too_deep(depth)
    {value, rest} = if value == 1, do: variant(rest, depth + 1), else: {nil, rest}
    {status, rest} = optional(rest, status, :status_code, 0)
    {source_timestamp, rest} = optional(rest, source_ts, :date_time, nil)
    {source_picoseconds, rest} = optional(rest, source_ps, :uint16, 0)
    {server_timestamp, rest} = optional(rest, server_ts, :date_time, nil)
    {server_picoseconds, rest} = optional(rest, server_ps, :uint16, 0)

    value = %DataValue{
      value: value,
      status: status,
      source_timestamp: source_timestamp,
      source_picoseconds: source_picoseconds,
      server_timestamp: server_timestamp,
      server_picoseconds: server_picoseconds
    }

    {value, rest}
  end

  defp data_value(_, _), do: raise(DecodeError, "too short for data_value")

  defp variant(<<0, rest::binary>>, _), do: {nil, rest}

  defp variant(<<array::1, dimensions::1, id::6, rest::binary>>, depth) do
    too_deep(depth)
    type = type_name(id) || raise DecodeError, "unknown built-in type #{id} in a Variant"
    take = &element(&1, type, depth + 1)

    if array == 1 do
      {values, rest} = array(rest, take)
      {dimensions, rest} = if dimensions == 1, do: take(rest, {:array, :int32}), else: {nil, rest}
      {%Variant{type: type, value: values || [], dimensions: dimensions}, rest}
    else
      {value, rest} = take.(rest)
      {%Variant{type: type, value: value}, rest}
    end
  end

  defp variant(_, _), do: raise(DecodeError, "too short for variant")

  defp element(binary, :variant, depth), do: variant(binary, depth)
  defp element(binary, :data_value, depth), do: data_value(binary, depth)
  defp element(binary, :diagnostic_info, depth), do: diagnostic_info(binary, depth)
  defp element(binary, type, _), do: take(binary, type)

  defp diagnostic_info(
         <<_::1, inner::1, inner_status::1, info::1, locale::1, text::1, uri::1, symbolic::1,
           rest::binary>>,
         depth
       ) do
    too_deep(depth)
    {symbolic_id, rest} = optional(rest, symbolic, :int32, nil)
    {namespace_uri, rest} = optional(rest, uri, :int32, nil)
    {locale, rest} = optional(rest, locale, :int32, nil)
    {localized_text, rest} = optional(rest, text, :int32, nil)
    {additional_info, rest} = optional(rest, info, :string, nil)
    {inner_status_code, rest} = optional(rest, inner_status, :status_code, nil)

    {inner_diagnostic_info, rest} =
      if inner == 1, do: diagnostic_info(rest, depth + 1), else: {nil, rest}

    value = %DiagnosticInfo{
      symbolic_id: symbolic_id,
      namespace_uri: namespace_uri,
      locale: locale,
      localized_text: localized_text,
      additional_info: additional_info,
      inner_status_code: inner_status_code,
      inner_diagnostic_info: inner_diagnostic_info
    }

    if value == %DiagnosticInfo{}, do: {nil, rest}, else: {value, rest}
  end

  defp diagnostic_info(_, _), do: raise(DecodeError, "too short for diagnostic_info")

  defp array(<<n::little-signed-32, rest::binary>>, _) when n < 0, do: {nil, rest}

  # Every element takes at least one byte, so a longer count is a lie.
  defp array(<<n::little-signed-32, rest::binary>>, take) when n <= byte_size(rest),
    do: elements(rest, n, take, [])

  defp array(_, _), do: raise(DecodeError, "array count longer than the message")

  defp elements(rest, 0, _, acc), do: {Enum.reverse(acc), rest}

  defp elements(binary, n, take, acc) do
    {value, rest} = take.(binary)
    elements(rest, n - 1, take, [value | acc])
  end
end
