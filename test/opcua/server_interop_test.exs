defmodule OPCUA.ServerInteropTest do
  # asyncua's client against the server. See test_helper.exs.
  use ExUnit.Case, async: true

  @moduletag :interop

  alias OPCUA.Server

  test "asyncua's client reads, writes, browses, calls, subscribes, acknowledges alarms and logs in" do
    server = start_supervised!({Server, port: 0, users: %{"operator" => "secret"}})
    2 = Server.namespace(server, "urn:plant")
    :ok = Server.add_object(server, "ns=2;s=Pump1", "Pump1")

    :ok =
      Server.add_variable(server, "ns=2;s=Pump1.Speed", "Speed",
        parent: "ns=2;s=Pump1",
        type: :int16,
        value: 1500,
        writable: true
      )

    :ok =
      Server.add_variable(server, "ns=2;s=Pump1.Temp", "Temp",
        parent: "ns=2;s=Pump1",
        type: :double,
        read: fn -> 21.5 end
      )

    :ok =
      Server.add_variable(server, "ns=2;s=Tank.Levels", "Levels",
        type: :double,
        value: [1.0, 2.5]
      )

    :ok =
      Server.add_method(server, "ns=2;s=Pump1.Multiply", "Multiply",
        parent: "ns=2;s=Pump1",
        inputs: [{"a", :int32}, {"b", :int32}],
        outputs: [{"product", :int32}],
        call: fn [a, b] -> {:ok, [a * b]} end
      )

    test = self()

    :ok =
      Server.add_condition(server, "ns=2;s=Pump1.Overload", "Overload",
        source: "ns=2;s=Pump1",
        severity: 700,
        message: "Pump 1 overload",
        acknowledge: fn comment -> send(test, {:acknowledged, comment}) && :ok end
      )

    :ok =
      Server.add_method(server, "ns=2;s=Pump1.Trip", "Trip",
        parent: "ns=2;s=Pump1",
        call: fn [] ->
          Server.condition(server, "ns=2;s=Pump1.Overload", active: true) && {:ok, []}
        end
      )

    # More children than one browse returns, so asyncua must use BrowseNext.
    :ok = Server.add_folder(server, "ns=2;s=Many", "Many")

    for i <- 1..1500,
        do:
          :ok =
            Server.add_variable(server, "ns=2;s=Many.#{i}", "Item#{i}",
              parent: "ns=2;s=Many",
              type: :int32,
              value: i
            )

    script = Path.expand("../support/asyncua_client.py", __DIR__)
    url = "opc.tcp://127.0.0.1:#{Server.port(server)}"

    {output, 0} =
      System.cmd(System.fetch_env!("ASYNCUA_PYTHON"), [script, url], stderr_to_stdout: true)

    seen =
      output |> String.split("\n") |> Enum.find(&String.starts_with?(&1, "{")) |> JSON.decode!()

    assert seen == %{
             "namespaces" => ["http://opcfoundation.org/UA/", "urn:yaopcua:server", "urn:plant"],
             "objects" => ["Aliases", "Levels", "Locations", "Many", "Pump1", "Server"],
             "speed" => 1500,
             "speed_after" => 1234,
             "display_name" => "Speed",
             "data_type" => "i=4",
             "levels" => [1.0, 2.5],
             "read_only" => "BadNotWritable",
             "multiply" => 42,
             "path" => "ns=2;s=Pump1.Speed",
             "state" => "Running",
             "many" => 1500,
             "subscription" => [1234, 777],
             "alarm" => %{
               "condition" => "ns=2;s=Pump1.Overload",
               "message" => "Pump 1 overload",
               "severity" => 700,
               "active" => true,
               "acked" => false,
               "acked_after" => true,
               "comment" => "from asyncua"
             },
             "user_read" => 21.5
           }

    assert Server.get(server, "ns=2;s=Pump1.Speed").value.value == 777
    assert_received {:acknowledged, "from asyncua"}
  end
end
