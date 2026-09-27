defmodule OPCUA.TablesTest do
  use ExUnit.Case, async: true

  alias OPCUA.{AttributeId, NodeIds, StatusCode}

  doctest StatusCode
  doctest NodeIds
  doctest AttributeId

  test "the schema says which release it comes from" do
    assert OPCUA.Schema.version() =~ ~r/^UA-1\.05\.\d+-\d{4}-\d{2}-\d{2}$/
  end

  test "status codes by name and number, ignoring the low flag bits" do
    assert StatusCode.name(0) == :good
    assert StatusCode.name(0x80340000 + 0x0400) == :bad_node_id_unknown
    assert StatusCode.description(0x80340000) =~ "node id"
    assert StatusCode.name(0x8FFF0000) == nil

    assert StatusCode.good?(0) and StatusCode.uncertain?(0x40000000) and
             StatusCode.bad?(0x80000000)

    refute StatusCode.bad?(0x40000000)
    assert_raise ArgumentError, fn -> StatusCode.code(:bad_nonsense) end
  end

  test "namespace 0 node ids by name" do
    assert NodeIds.id("Server") == 2253
    assert NodeIds.id("NoSuchNode") == nil
    assert_raise ArgumentError, fn -> NodeIds.id!("NoSuchNode") end
    assert NodeIds.id!("ObjectsFolder") == 85
  end

  test "attribute ids" do
    assert AttributeId.id(:node_id) == 1
    assert AttributeId.id(:access_level_ex) == 27
    assert length(AttributeId.names()) == 27
    assert AttributeId.name(99) == nil
    assert_raise ArgumentError, fn -> AttributeId.id(:nope) end
  end
end
