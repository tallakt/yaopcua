defmodule OPCUA.Server.NodeSet do
  @moduledoc false
  # Reads a NodeSet2 XML file, the OPC Foundation's format for publishing an
  # address space, into OPCUA.Server.Node structs and their values. Only used
  # while compiling: the server itself never reads XML.

  alias OPCUA.{LocalizedText, NodeId, QualifiedName, Variant}
  alias OPCUA.Server.Node

  @classes %{
    "UAObject" => :object,
    "UAVariable" => :variable,
    "UAMethod" => :method,
    "UAObjectType" => :object_type,
    "UAVariableType" => :variable_type,
    "UAReferenceType" => :reference_type,
    "UADataType" => :data_type,
    "UAView" => :view
  }

  @scalars %{
    "Boolean" => :boolean,
    "SByte" => :sbyte,
    "Byte" => :byte,
    "Int16" => :int16,
    "UInt16" => :uint16,
    "Int32" => :int32,
    "UInt32" => :uint32,
    "Int64" => :int64,
    "UInt64" => :uint64,
    "Float" => :float,
    "Double" => :double,
    "String" => :string,
    "DateTime" => :date_time,
    "Guid" => :guid,
    "ByteString" => :byte_string,
    "NodeId" => :node_id,
    "QualifiedName" => :qualified_name,
    "LocalizedText" => :localized_text,
    "StatusCode" => :status_code,
    "ExtensionObject" => :extension_object
  }

  @doc false
  # Returns `[{node, value}]`, where value is an `OPCUA.Variant` or nil. Each
  # node has all its references, forward and inverse, whichever end of the
  # reference the file listed it on.
  def read(path) do
    # xmerl is only needed while compiling, so it's put on the code path here
    # rather than listed as a runtime dependency.
    Mix.ensure_application!(:xmerl)
    {"UANodeSet", _, children, _} = tree(path)

    aliases =
      for {"Aliases", _, list, _} <- children,
          {"Alias", %{"Alias" => name}, _, id} <- list,
          into: %{},
          do: {name, id}

    structs =
      for %{kind: kind, name: name} = t <- OPCUA.Schema.types(), into: %{}, do: {name, {kind, t}}

    raw =
      for {name, attrs, kids, _} <- children, class = @classes[name] do
        node(class, attrs, kids, aliases, structs)
      end

    # Each reference once, as source -> target, in the order the file has them.
    links =
      Enum.uniq(
        for {node, _, refs} <- raw, {type, target, forward} <- refs do
          if forward, do: {node.node_id, type, target}, else: {target, type, node.node_id}
        end
      )

    forward = Enum.group_by(links, &elem(&1, 0), fn {_, type, target} -> {type, target, true} end)

    inverse =
      Enum.group_by(links, &elem(&1, 2), fn {source, type, _} -> {type, source, false} end)

    for {node, value, _} <- raw do
      refs = Map.get(forward, node.node_id, []) ++ Map.get(inverse, node.node_id, [])
      {%{node | references: refs}, value}
    end
  end

  defp node(class, attrs, kids, aliases, structs) do
    id = fn name, default -> if text = attrs[name], do: node_id(text, aliases), else: default end

    int = fn name, default ->
      if text = attrs[name], do: String.to_integer(text), else: default
    end

    bool = fn name, default -> if text = attrs[name], do: text == "true", else: default end

    attributes =
      case class do
        :variable ->
          access = int.("AccessLevel", 1)

          %{
            data_type: id.("DataType", %NodeId{id: 24}),
            value_rank: int.("ValueRank", -1),
            array_dimensions: dimensions(attrs["ArrayDimensions"]),
            access_level: access,
            user_access_level: int.("UserAccessLevel", access),
            minimum_sampling_interval: float(attrs["MinimumSamplingInterval"] || "0"),
            historizing: bool.("Historizing", false)
          }

        :variable_type ->
          %{
            data_type: id.("DataType", %NodeId{id: 24}),
            value_rank: int.("ValueRank", -1),
            array_dimensions: dimensions(attrs["ArrayDimensions"]),
            is_abstract: bool.("IsAbstract", false)
          }

        :object ->
          %{event_notifier: int.("EventNotifier", 0)}

        :view ->
          %{
            event_notifier: int.("EventNotifier", 0),
            contains_no_loops: bool.("ContainsNoLoops", false)
          }

        :method ->
          %{executable: bool.("Executable", true), user_executable: bool.("UserExecutable", true)}

        :reference_type ->
          %{
            is_abstract: bool.("IsAbstract", false),
            symmetric: bool.("Symmetric", false),
            inverse_name: text(kids, "InverseName")
          }

        type when type in [:object_type, :data_type] ->
          %{is_abstract: bool.("IsAbstract", false)}
      end

    refs =
      for {"References", _, list, _} <- kids, {"Reference", ref, _, target} <- list do
        {node_id(ref["ReferenceType"], aliases), node_id(target, aliases),
         ref["IsForward"] != "false"}
      end

    node = %Node{
      node_id: node_id(attrs["NodeId"], aliases),
      class: class,
      browse_name: qualified_name(attrs["BrowseName"]),
      display_name: text(kids, "DisplayName"),
      description: text(kids, "Description"),
      attributes: attributes
    }

    value =
      case for({"Value", _, [element], _} <- kids, do: element) do
        [element] -> value(element, structs, aliases)
        [] -> nil
      end

    {node, value, refs}
  end

  defp node_id(text, aliases),
    do: NodeId.parse!(Map.get(aliases, String.trim(text), String.trim(text)))

  defp qualified_name(text) do
    case Integer.parse(text) do
      {ns, ":" <> name} -> %QualifiedName{ns: ns, name: name}
      _ -> %QualifiedName{ns: 0, name: text}
    end
  end

  defp text(kids, name) do
    case for({^name, attrs, _, text} <- kids, do: {attrs, text}) do
      [{attrs, text} | _] -> %LocalizedText{locale: attrs["Locale"], text: text}
      [] -> nil
    end
  end

  defp dimensions(nil), do: nil

  defp dimensions(text),
    do: text |> String.split(",") |> Enum.map(&(&1 |> String.trim() |> String.to_integer()))

  defp float(text) do
    {value, _} = Float.parse(text)
    value
  end

  defp value({"ListOf" <> name, _, items, _}, structs, aliases) do
    type = Map.fetch!(@scalars, name)
    %Variant{type: type, value: Enum.map(items, &scalar(type, &1, structs, aliases))}
  end

  defp value({name, _, _, _} = element, structs, aliases) do
    type = Map.fetch!(@scalars, name)
    %Variant{type: type, value: scalar(type, element, structs, aliases)}
  end

  defp scalar(:boolean, {_, _, _, text}, _, _), do: String.trim(text) == "true"

  defp scalar(type, {_, _, _, text}, _, _)
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
       do: text |> String.trim() |> String.to_integer()

  defp scalar(type, {_, _, _, text}, _, _) when type in [:float, :double],
    do: float(String.trim(text))

  defp scalar(:string, {_, _, _, text}, _, _), do: text

  defp scalar(:date_time, {_, _, _, text}, _, _),
    do: text |> String.trim() |> DateTime.from_iso8601() |> elem(1)

  defp scalar(:byte_string, {_, _, _, text}, _, _),
    do: text |> String.replace(~r/\s/, "") |> Base.decode64!()

  defp scalar(:guid, {_, _, kids, _}, _, _), do: child_text(kids, "String")

  defp scalar(:node_id, {_, _, kids, _}, _, aliases),
    do: node_id(child_text(kids, "Identifier"), aliases)

  defp scalar(:qualified_name, {_, _, kids, _}, _, _),
    do: %QualifiedName{
      ns: String.to_integer(child_text(kids, "NamespaceIndex") || "0"),
      name: child_text(kids, "Name")
    }

  defp scalar(:localized_text, {_, _, kids, _}, _, _),
    do: %LocalizedText{locale: child_text(kids, "Locale"), text: child_text(kids, "Text")}

  defp scalar(:extension_object, {_, _, kids, _}, structs, aliases) do
    [{"Body", _, [{name, _, fields, _}], _}] = for {"Body", _, _, _} = body <- kids, do: body
    structure(name, fields, structs, aliases)
  end

  defp structure(name, kids, structs, aliases) do
    {:struct, %{module: module, fields: fields}} = Map.fetch!(structs, name)

    values =
      for field <- fields do
        xml = field.name |> Atom.to_string() |> Macro.camelize()

        case for({^xml, _, _, _} = element <- kids, do: element) do
          [element] -> {field.name, field_value(field.type, element, structs, aliases)}
          [] -> {field.name, field.default}
        end
      end

    struct!(module, values)
  end

  defp field_value({:array, type}, {_, _, items, _}, structs, aliases),
    do: Enum.map(items, &field_value(type, &1, structs, aliases))

  defp field_value(type, element, structs, aliases) when is_atom(type) do
    case Atom.to_string(type) do
      "Elixir.OPCUA.Types." <> name ->
        case structs[name] do
          # An enumeration is written as Name_Number.
          {:enum, _} ->
            element
            |> elem(3)
            |> String.split("_")
            |> List.last()
            |> String.to_integer()
            |> then(&elem(type.decode(<<&1::little-signed-32>>), 0))

          {:struct, _} ->
            structure(name, elem(element, 2), structs, aliases)
        end

      _ ->
        scalar(type, element, structs, aliases)
    end
  end

  defp child_text(kids, name) do
    case for({^name, _, _, text} <- kids, do: text) do
      [text | _] -> text
      [] -> nil
    end
  end

  # The whole document as {name, attributes, children, text} tuples.
  defp tree(path) do
    {:ok, {[root], []}, _} =
      :xmerl_sax_parser.file(String.to_charlist(path), event_fun: &event/3, event_state: {[], []})

    root
  end

  defp event({:startElement, _, name, _, attrs}, _, {done, stack}) do
    attrs =
      for {_, _, key, value} <- attrs, into: %{}, do: {List.to_string(key), List.to_string(value)}

    {done, [{List.to_string(name), attrs, [], []} | stack]}
  end

  defp event({:characters, chars}, _, {done, [{name, attrs, kids, text} | stack]}),
    do: {done, [{name, attrs, kids, [text | chars]} | stack]}

  defp event({:endElement, _, _, _}, _, {done, [{name, attrs, kids, text} | stack]}) do
    element = {name, attrs, Enum.reverse(kids), text |> IO.chardata_to_string()}

    case stack do
      [{parent, parent_attrs, siblings, parent_text} | rest] ->
        {done, [{parent, parent_attrs, [element | siblings], parent_text} | rest]}

      [] ->
        {[element | done], []}
    end
  end

  defp event(_, _, state), do: state
end
