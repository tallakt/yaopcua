defmodule OPCUA.Plant do
  @moduledoc false
  # The nodes the interop tests' clients look for on yaopcua's server, as
  # asyncua_client.py and open62541_peer.c expect them. Acknowledging the
  # alarm sends `{:acknowledged, comment}` to `test`.

  alias OPCUA.Server

  def add(server, test) do
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

    # More children than one browse returns, so a client must use BrowseNext.
    :ok = Server.add_folder(server, "ns=2;s=Many", "Many")

    for i <- 1..1500,
        do:
          :ok =
            Server.add_variable(server, "ns=2;s=Many.#{i}", "Item#{i}",
              parent: "ns=2;s=Many",
              type: :int32,
              value: i
            )

    :ok
  end
end
