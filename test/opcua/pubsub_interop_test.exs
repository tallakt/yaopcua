defmodule OPCUA.PubSubInteropTest do
  # PubSub with asyncua over UDP on localhost, both ways. See test_helper.exs.
  use ExUnit.Case, async: false

  @moduletag :interop

  alias OPCUA.PubSub.{Publisher, Subscriber}

  @fields [{"Speed", :int16}, {"Level", :double}, {"Name", :string}, {"Running", :boolean}]

  defp port do
    {:ok, socket} = :gen_udp.open(0)
    {:ok, port} = :inet.port(socket)
    :gen_udp.close(socket)
    port
  end

  defp python, do: System.fetch_env!("ASYNCUA_PYTHON")
  defp script, do: Path.expand("../support/asyncua_pubsub.py", __DIR__)

  for encoding <- ["variant", "datavalue", "raw"] do
    test "yaopcua subscribes to asyncua publishing #{encoding} fields" do
      port = port()

      start_supervised!(
        {Subscriber,
         to: self(),
         url: "opc.udp://127.0.0.1:#{port}",
         readers: [[publisher_id: 42, writer_group_id: 3, writer_id: 7, fields: @fields]]}
      )

      {_, 0} =
        System.cmd(python(), [script(), "publish", "#{port}", unquote(encoding), "0.6"],
          stderr_to_stdout: true
        )

      received =
        Stream.repeatedly(fn ->
          receive do
            {OPCUA.PubSub, {42, 7}, {:data, values}} -> values
          after
            200 -> :done
          end
        end)
        |> Enum.take_while(&(&1 != :done))

      # asyncua counts Speed up by one each cycle.
      speeds = for %{"Speed" => speed} <- received, speed != nil, do: speed
      assert length(speeds) >= 5
      assert speeds == Enum.to_list(hd(speeds)..List.last(speeds))
      assert %{"Level" => 2.5, "Name" => "Pump 1", "Running" => true} = List.last(received)
    end
  end

  test "asyncua subscribes to yaopcua publishing variant and raw fields" do
    port = port()
    args = [script(), "subscribe", "#{port}", "1.0"]

    subscriber =
      Port.open({:spawn_executable, python()}, [
        :binary,
        :exit_status,
        :stderr_to_stdout,
        line: 4096,
        args: args
      ])

    await(subscriber, &(&1 == "ready"))

    start_supervised!(
      {Publisher,
       url: "opc.udp://127.0.0.1:#{port}",
       publisher_id: {:uint16, 42},
       interval: 50,
       writers: [
         [
           id: 1,
           fields: @fields,
           read: fn ->
             %{"Speed" => 1500, "Level" => 2.5, "Name" => "Pump 1", "Running" => true}
           end
         ],
         [
           id: 2,
           fields: @fields,
           encoding: :raw,
           read: fn -> %{"Speed" => 7, "Level" => 0.5, "Name" => "raw", "Running" => false} end
         ]
       ]}
    )

    assert await(subscriber, &String.starts_with?(&1, "{")) |> JSON.decode!() == %{
             "1" => %{"Speed" => 1500, "Level" => 2.5, "Name" => "Pump 1", "Running" => true},
             "2" => %{"Speed" => 7, "Level" => 0.5, "Name" => "raw", "Running" => false}
           }
  end

  defp await(port, match) do
    receive do
      {^port, {:data, {:eol, line}}} -> if match.(line), do: line, else: await(port, match)
      {^port, {:data, _}} -> await(port, match)
      {^port, {:exit_status, status}} -> flunk("asyncua exited with #{status}")
    after
      15_000 -> flunk("asyncua didn't answer")
    end
  end
end
