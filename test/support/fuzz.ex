defmodule OPCUA.Fuzz do
  @moduledoc false
  # StreamData generators for the fuzz and property tests: valid values of
  # every built-in type and generated structure, and mutations of valid
  # encodings. Nesting stops at a few levels, so recursive types stay small.

  import StreamData

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

  @max_depth 3

  @doc "Every generated structure module."
  def structs do
    {:ok, modules} = :application.get_key(:yaopcua, :modules)
    for m <- modules, Code.ensure_loaded?(m), function_exported?(m, :__fields__, 0), do: m
  end

  @doc "The structures that can sit in an ExtensionObject: those with a binary encoding."
  def encodable_structs, do: for(m <- structs(), m.encoding_id() != nil, do: m)

  @doc "The request structures of the services: those with a request header."
  def requests,
    do: for(m <- encodable_structs(), Keyword.has_key?(m.__fields__(), :request_header), do: m)

  @doc "A valid value of `type`: a built-in type atom, a generated module, or {:array, type}."
  def value(type, depth \\ 0)

  def value(:boolean, _), do: boolean()
  def value(:sbyte, _), do: integer(-0x80..0x7F)
  def value(:byte, _), do: integer(0..0xFF)
  def value(:int16, _), do: integer(-0x8000..0x7FFF)
  def value(:uint16, _), do: integer(0..0xFFFF)

  def value(:int32, _),
    do:
      one_of([integer(), integer(-0x8000_0000..0x7FFF_FFFF)])
      |> map(&clamp(&1, -0x8000_0000, 0x7FFF_FFFF))

  def value(:uint32, _), do: one_of([integer(0..1000), integer(0..0xFFFF_FFFF)])
  def value(:int64, _), do: integer(-0x8000_0000_0000_0000..0x7FFF_FFFF_FFFF_FFFF)
  def value(:uint64, _), do: integer(0..0xFFFF_FFFF_FFFF_FFFF)
  def value(:status_code, _), do: value(:uint32, 0)

  def value(:float, _) do
    one_of([
      map(float(min: -1.0e30, max: 1.0e30), &float32/1),
      member_of([:nan, :infinity, :neg_infinity])
    ])
  end

  def value(:double, _), do: one_of([float(), member_of([:nan, :infinity, :neg_infinity])])

  def value(:string, _),
    do: one_of([constant(nil), string(:utf8, max_length: 16), binary(max_length: 16)])

  def value(:byte_string, _), do: one_of([constant(nil), binary(max_length: 24)])
  def value(:xml_element, _), do: one_of([constant(nil), string(:printable, max_length: 16)])

  # From 1601 to the end of 9999, in microseconds from 1970.
  def value(:date_time, _) do
    one_of([
      constant(nil),
      map(
        integer(-11_644_473_600_000_000..253_402_300_799_000_000),
        &DateTime.from_unix!(&1, :microsecond)
      )
    ])
  end

  def value(:guid, _), do: map(binary(length: 16), &guid/1)
  def value(:node_id, _), do: one_of([constant(nil), node_id()])

  def value(:expanded_node_id, _) do
    one_of([
      constant(nil),
      map(
        {node_id(), one_of([constant(nil), string(:utf8, max_length: 12)]),
         one_of([constant(0), integer(0..0xFFFF_FFFF)])},
        fn {n, uri, server} ->
          %ExpandedNodeId{ns: n.ns, id: n.id, namespace_uri: uri, server_index: server}
        end
      )
    ])
  end

  def value(:qualified_name, _),
    do:
      one_of([
        constant(nil),
        map({integer(0..0xFFFF), value(:string)}, fn {ns, name} ->
          %QualifiedName{ns: ns, name: name}
        end)
      ])

  def value(:localized_text, _) do
    one_of([
      constant(nil),
      map({value(:string), value(:string)}, fn {locale, text} ->
        %LocalizedText{locale: locale, text: text}
      end)
    ])
  end

  def value(:extension_object, depth) when depth >= @max_depth, do: constant(nil)

  def value(:extension_object, depth) do
    raw =
      map(
        {integer(1..0xFFFF), integer(0..0xFFFF_FFFF), member_of([nil, :binary, :xml]),
         binary(max_length: 16)},
        fn {ns, id, encoding, body} ->
          %ExtensionObject{
            type_id: %NodeId{ns: ns, id: id},
            encoding: encoding,
            body: if(encoding, do: body)
          }
        end
      )

    one_of([constant(nil), raw, bind(member_of(encodable_structs()), &value(&1, depth + 1))])
  end

  def value(:data_value, depth) do
    fields = {
      one_of([constant(nil), value(:variant, depth + 1)]),
      value(:status_code),
      value(:date_time),
      integer(0..0xFFFF),
      value(:date_time),
      integer(0..0xFFFF)
    }

    map(fields, fn {v, status, source, source_ps, server, server_ps} ->
      %DataValue{
        value: v,
        status: status,
        source_timestamp: source,
        source_picoseconds: source_ps,
        server_timestamp: server,
        server_picoseconds: server_ps
      }
    end)
  end

  def value(:variant, depth) when depth >= @max_depth, do: constant(nil)

  def value(:variant, depth) do
    types = OPCUA.Binary.builtins()

    scalar =
      bind(member_of(types), fn type ->
        map(value(type, depth + 1), &%Variant{type: type, value: &1})
      end)

    array =
      bind(member_of(types), fn type ->
        bind(list_of(value(type, depth + 1), max_length: 4), fn list ->
          map(
            member_of([nil, [length(list)]]),
            &%Variant{type: type, value: list, dimensions: &1}
          )
        end)
      end)

    one_of([constant(nil), scalar, array])
  end

  def value(:diagnostic_info, depth) when depth >= @max_depth, do: constant(nil)

  def value(:diagnostic_info, depth) do
    optional = fn generator -> one_of([constant(nil), generator]) end

    fields = {
      optional.(value(:int32)),
      optional.(value(:int32)),
      optional.(value(:int32)),
      optional.(value(:int32)),
      optional.(string(:utf8, max_length: 12)),
      optional.(value(:status_code)),
      value(:diagnostic_info, depth + 1)
    }

    info =
      map(fields, fn {symbolic, uri, locale, text, info, status, inner} ->
        %DiagnosticInfo{
          symbolic_id: symbolic,
          namespace_uri: uri,
          locale: locale,
          localized_text: text,
          additional_info: info,
          inner_status_code: status,
          inner_diagnostic_info: inner
        }
      end)

    one_of([constant(nil), info])
  end

  def value({:array, _}, depth) when depth >= @max_depth, do: member_of([nil, []])

  def value({:array, type}, depth),
    do: one_of([constant(nil), list_of(value(type, depth + 1), max_length: 3)])

  def value(module, depth) when is_atom(module) do
    cond do
      function_exported?(module, :__fields__, 0) ->
        fields = for {name, type} <- module.__fields__(), do: map(value(type, depth), &{name, &1})
        fields |> fixed_list() |> map(&struct(module, &1))

      function_exported?(module, :flags, 1) ->
        integer(0..0xFF)

      true ->
        case Keyword.keys(module.values()) do
          [] -> integer(0..10)
          names -> member_of(names)
        end
    end
  end

  defp node_id do
    identifier =
      one_of([
        integer(0..0xFF),
        integer(0..0xFFFF_FFFF),
        string(:utf8, max_length: 12),
        map(binary(length: 16), &{:guid, guid(&1)}),
        map(binary(max_length: 12), &{:opaque, &1})
      ])

    map({one_of([constant(0), integer(0..0xFFFF)]), identifier}, fn {ns, id} ->
      %NodeId{ns: ns, id: id}
    end)
  end

  defp guid(bytes), do: bytes |> OPCUA.Binary.take(:guid) |> elem(0)

  defp float32(x) do
    case <<x::float-32>> do
      <<f::float-32>> -> f
      _ -> :infinity
    end
  end

  defp clamp(x, low, high), do: x |> max(low) |> min(high)

  @doc """
  A mutation of `bytes`, as a fuzzer would make: flipped bits, bytes set to
  edge values, bytes inserted or deleted, lengths made huge, or a cut short.
  """
  def mutate(bytes) when byte_size(bytes) == 0, do: binary(max_length: 8)

  def mutate(bytes) do
    size = byte_size(bytes)
    at = integer(0..(size - 1))

    one_of([
      map({at, integer(0..7)}, fn {i, bit} ->
        update(bytes, i, &Bitwise.bxor(&1, Bitwise.bsl(1, bit)))
      end),
      map({at, member_of([0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF])}, fn {i, b} ->
        update(bytes, i, fn _ -> b end)
      end),
      map({integer(0..size), binary(min_length: 1, max_length: 8)}, fn {i, extra} ->
        binary_part(bytes, 0, i) <> extra <> binary_part(bytes, i, size - i)
      end),
      map({at, integer(1..8)}, fn {i, n} ->
        binary_part(bytes, 0, i) <> binary_part(bytes, min(i + n, size), size - min(i + n, size))
      end),
      map(
        {integer(0..max(size - 4, 0)),
         member_of([0x7FFF_FFFF, 0xFFFF_FFFF, 0x8000_0000, 0xFFFF, 0x1000_0000])},
        fn {i, n} ->
          if size >= 4 and i + 4 <= size,
            do:
              binary_part(bytes, 0, i) <>
                <<n::little-32>> <> binary_part(bytes, i + 4, size - i - 4),
            else: bytes
        end
      ),
      map(at, &binary_part(bytes, 0, &1))
    ])
  end

  @doc "Several mutations in a row."
  def mutations(bytes, times \\ 3), do: bind(integer(1..times), &mutate_times(bytes, &1))

  defp mutate_times(bytes, 0), do: constant(bytes)
  defp mutate_times(bytes, n), do: bind(mutate(bytes), &mutate_times(&1, n - 1))

  defp update(bytes, i, fun) do
    <<before::binary-size(i), b, rest::binary>> = bytes
    before <> <<fun.(b)>> <> rest
  end

  @doc """
  How many cases each property runs: FUZZ_RUNS (100 by default), or with
  FUZZ_SECONDS set, as many as fit in that many seconds. `shares` splits it
  between the parts of a property that checks several things in turn.

  They go into `check all` as literal options, which is the only way it
  takes them: `max_runs: runs(), max_run_time: run_time()`.
  """
  def runs(shares \\ 1) do
    case System.get_env("FUZZ_SECONDS") do
      nil -> max(div(String.to_integer(System.get_env("FUZZ_RUNS", "100")), shares), 1)
      _ -> 1_000_000_000
    end
  end

  @doc "How long each property may run, in ms, or nil for no limit. See `runs/1`."
  def run_time(shares \\ 1) do
    case System.get_env("FUZZ_SECONDS") do
      nil -> nil
      seconds -> div(String.to_integer(seconds) * 1000, shares)
    end
  end
end
