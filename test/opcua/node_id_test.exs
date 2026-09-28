defmodule OPCUA.NodeIdTest do
  use ExUnit.Case, async: true

  alias OPCUA.{ExpandedNodeId, NodeId}

  doctest NodeId
  doctest OPCUA.QualifiedName

  test "parses and prints every kind of identifier" do
    for text <- [
          "i=2256",
          "ns=3;s=Pump1.Speed",
          "ns=1;i=70000",
          "ns=2;g=72962B91-FA75-4AE6-8D28-B404DC7DAF63",
          "ns=4;b=AQID"
        ] do
      assert text |> NodeId.parse!() |> to_string() == text
    end

    assert NodeId.parse("ns=4;b=AQID") == {:ok, %NodeId{ns: 4, id: {:opaque, <<1, 2, 3>>}}}

    assert NodeId.parse("ns=2;g=72962b91-fa75-4ae6-8d28-b404dc7daf63") ==
             NodeId.parse("ns=2;g=72962B91-FA75-4AE6-8D28-B404DC7DAF63")
  end

  test "a string identifier may hold anything, even semicolons" do
    assert NodeId.parse!("ns=1;s=a;b=c") == %NodeId{ns: 1, id: "a;b=c"}
    assert NodeId.parse!("s=") == %NodeId{ns: 0, id: ""}
  end

  test "rejects text that isn't a node id" do
    for text <- [
          "",
          "85",
          "ns=1",
          "ns=x;i=1",
          "ns=70000;i=1",
          "i=-1",
          "i=4294967296",
          "i=1x",
          "g=nope",
          "b=!!",
          "x=1"
        ] do
      assert NodeId.parse(text) == {:error, :invalid_node_id}, text
    end

    assert_raise ArgumentError, fn -> NodeId.parse!("nope") end
  end

  test "an expanded node id prints its server and namespace URI" do
    assert to_string(%ExpandedNodeId{ns: 2, id: 5}) == "ns=2;i=5"

    assert to_string(%ExpandedNodeId{id: "x", namespace_uri: "urn:plant", server_index: 1}) ==
             "svr=1;nsu=urn:plant;s=x"
  end
end
