defmodule OPCUA.ServerInteropTest do
  # asyncua's client against the server. See test_helper.exs.
  use ExUnit.Case, async: true

  @moduletag :interop

  alias OPCUA.Server

  test "asyncua's client reads, writes, browses, calls, subscribes, acknowledges alarms and logs in" do
    server = start_supervised!({Server, port: 0, users: %{"operator" => "secret"}})
    :ok = OPCUA.Plant.add(server, self())

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
