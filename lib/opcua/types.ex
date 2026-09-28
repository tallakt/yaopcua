defmodule OPCUA.Types do
  @moduledoc """
  The structures and enumerations of the OPC UA base namespace, one module
  each: `OPCUA.Types.ReadRequest`, `OPCUA.Types.NodeClass` and so on.

  They're generated while compiling, from `schema/Opc.Ua.Types.bsd` and
  `schema/NodeIds.csv` of the release in `OPCUA.Schema.version/0`.

    * Field names are the spec's, in snake case. The `NoOfX` count before an
      array is folded into the array, which is a list, or `nil` for the null
      array.
    * A field that holds another structure may be left `nil`; it encodes as
      that structure's defaults.
    * Enumerations are atoms. A number this release doesn't know decodes as
      the integer.
    * Option sets are integers, with `flags/1` and `mask/1` on their module to
      convert to and from a list of names.

  Each module has `encode/1` and `decode/1` (see `OPCUA.Binary`), and each
  structure has `type_id/0` and `encoding_id/0`.
  """

  @external_resource OPCUA.Schema.path("Opc.Ua.Types.bsd")
  @external_resource OPCUA.Schema.path("NodeIds.csv")

  ids = Map.new(OPCUA.Schema.node_ids(), fn {name, id, _class} -> {name, id} end)
  types = OPCUA.Schema.types()
  version = OPCUA.Schema.version()

  location = Macro.Env.location(__ENV__)

  for %{kind: :enum, option_set: false} = t <- types do
    doc = """
    The #{t.name} enumeration, from #{version}.#{if t.doc, do: "\n\n" <> t.doc}

    Values: #{Enum.map_join(t.values, ", ", fn {name, value} -> "`#{inspect(name)}` (#{value})" end)}.
    """

    names = Enum.reduce(Keyword.keys(t.values), quote(do: integer), &{:|, [], [&1, &2]})

    clauses =
      for {name, number} <- t.values do
        quote do
          defp number(unquote(name)), do: unquote(number)
          defp name(unquote(number)), do: unquote(name)
        end
      end

    body =
      quote do
        @moduledoc unquote(doc)

        @type t :: unquote(names)

        @doc "The names and numbers the spec defines, in its order."
        def values, do: unquote(t.values)

        @doc "Encodes a name, or a number."
        def encode(value), do: OPCUA.Binary.encode(number(value), :int32)

        @doc "Decodes off the front of a binary, returning the name (or the number, if unknown) and the rest."
        def decode(binary) do
          {n, rest} = OPCUA.Binary.take(binary, :int32)
          {name(n), rest}
        end

        unquote_splicing(clauses)

        defp number(n) when is_integer(n), do: n

        defp number(value),
          do: raise(ArgumentError, "#{inspect(value)} is not a #{inspect(__MODULE__)}")

        defp name(n), do: n
      end

    Module.create(t.module, body, location)
  end

  for %{kind: :enum, option_set: true} = t <- types do
    doc = """
    The #{t.name} option set, from #{version}: an integer whose bits are these
    flags.#{if t.doc, do: "\n\n" <> t.doc}

    Flags: #{Enum.map_join(t.values, ", ", fn {name, value} -> "`#{inspect(name)}` (#{value})" end)}.
    """

    base = %{8 => :byte, 16 => :uint16, 32 => :uint32}[t.bits]

    body =
      quote do
        @moduledoc unquote(doc)

        import Bitwise

        @type t :: non_neg_integer

        @doc "The flag names and bit values the spec defines, in its order."
        def values, do: unquote(t.values)

        @doc "Encodes an integer, or a list of flag names."
        def encode(flags) when is_list(flags), do: encode(mask(flags))
        def encode(n), do: OPCUA.Binary.encode(n, unquote(base))

        @doc "Decodes off the front of a binary, returning the integer and the rest."
        def decode(binary), do: OPCUA.Binary.take(binary, unquote(base))

        @doc "The names of the flags set in `n`."
        def flags(n), do: for({name, bit} <- values(), bit != 0, (n &&& bit) == bit, do: name)

        @doc "The integer with these flags set."
        def mask(flags), do: Enum.reduce(flags, 0, &(Keyword.fetch!(values(), &1) ||| &2))
      end

    Module.create(t.module, body, location)
  end

  for %{kind: :struct} = t <- types do
    doc = """
    The #{t.name} structure, from #{version}.#{if t.doc, do: "\n\n" <> t.doc}

    #{Enum.map_join(t.fields, "\n", fn f -> "  * `#{f.name}`: #{OPCUA.Schema.describe(f.type)}" end)}
    """

    vars = for f <- t.fields, do: {f.name, Macro.var(f.name, __MODULE__)}
    binary = Macro.var(:binary, __MODULE__)

    encodes =
      for {f, {_, var}} <- Enum.zip(t.fields, vars),
          do: quote(do: OPCUA.Binary.encode(unquote(var), unquote(f.type)))

    takes =
      for {f, {_, var}} <- Enum.zip(t.fields, vars),
          do:
            quote(
              do:
                {unquote(var), unquote(binary)} =
                  OPCUA.Binary.take(unquote(binary), unquote(f.type))
            )

    body =
      quote do
        @moduledoc unquote(doc)

        defstruct unquote(Macro.escape(for f <- t.fields, do: {f.name, f.default}))

        @type t :: %__MODULE__{}

        @doc "The node id of this data type, in namespace 0."
        def type_id, do: unquote(ids[t.name])

        @doc false
        # The fields and their types, in encoding order: for generating
        # values in tests, and for tools.
        def __fields__, do: unquote(Macro.escape(for f <- t.fields, do: {f.name, f.type}))

        @doc "The node id of this type's binary encoding, which tags it on the wire, in namespace 0."
        def encoding_id, do: unquote(ids[t.name <> "_Encoding_DefaultBinary"])

        @doc "Encodes the structure; `nil` encodes the defaults."
        def encode(nil), do: encode(%__MODULE__{})
        def encode(%__MODULE__{unquote_splicing(vars)}), do: unquote(encodes)

        @doc "Decodes the structure off the front of a binary, returning it and the rest. Raises `OPCUA.DecodeError`."
        def decode(unquote(binary)) do
          unquote_splicing(takes)
          {%__MODULE__{unquote_splicing(vars)}, unquote(binary)}
        end
      end

    Module.create(t.module, body, location)
  end

  @doc "The structure module that a node id in namespace 0 tags on the wire, or `nil`."
  @spec by_encoding(non_neg_integer) :: module | nil
  def by_encoding(encoding_id)

  for %{kind: :struct} = t <- types, id = ids[t.name <> "_Encoding_DefaultBinary"] do
    def by_encoding(unquote(id)), do: unquote(t.module)
  end

  def by_encoding(_), do: nil
end
