defmodule OPCUA.PubSubTest do
  use ExUnit.Case, async: true

  alias OPCUA.PubSub.{Publisher, Subscriber, UADP}

  @fields [{"Speed", :int16}, {"Level", :double}, {"Name", :string}, {"Running", :boolean}]
  @values %{"Speed" => 1500, "Level" => 2.5, "Name" => "Pump 1", "Running" => true}

  defp url do
    {:ok, socket} = :gen_udp.open(0)
    {:ok, port} = :inet.port(socket)
    :gen_udp.close(socket)
    "opc.udp://127.0.0.1:#{port}"
  end

  defp data(name, timeout \\ 1000) do
    receive do
      {OPCUA.PubSub, ^name, {:data, values}} -> values
    after
      timeout -> flunk("no data for #{inspect(name)}")
    end
  end

  # The next data that has this value, skipping older ones.
  defp data_with(name, key, value) do
    case data(name) do
      %{^key => ^value} = values -> values
      _ -> data_with(name, key, value)
    end
  end

  for encoding <- [:variant, :raw, :data_value] do
    test "sends a dataset in #{encoding} fields" do
      url = url()

      start_supervised!(
        {Subscriber,
         to: self(), url: url, readers: [[publisher_id: 42, writer_id: 1, fields: @fields]]}
      )

      start_supervised!(
        {Publisher,
         url: url,
         publisher_id: 42,
         interval: 20,
         writers: [[id: 1, fields: @fields, encoding: unquote(encoding), read: fn -> @values end]]}
      )

      assert data({42, 1}) == @values
    end
  end

  test "values set by the application, with delta frames between key frames" do
    url = url()

    start_supervised!(
      {Subscriber,
       to: self(),
       url: url,
       readers: [[publisher_id: "plc-1", writer_id: 3, fields: @fields, name: :pump]]}
    )

    publisher =
      start_supervised!(
        {Publisher,
         url: url,
         publisher_id: "plc-1",
         interval: 20,
         writers: [[id: 3, fields: @fields, key_frames: 10]]}
      )

    :ok = Publisher.set(publisher, 3, @values)
    assert data_with(:pump, "Speed", 1500) == @values

    # A delta frame carries only Speed; the subscriber keeps the rest.
    :ok = Publisher.set(publisher, 3, %{"Speed" => 1600})
    assert data_with(:pump, "Speed", 1600) == %{@values | "Speed" => 1600}

    assert_raise ArgumentError, fn -> Publisher.set(publisher, 3, %{"Speed" => 70_000}) end
    assert_raise ArgumentError, fn -> Publisher.set(publisher, 9, %{}) end
  end

  test "fields are numbered when the reader doesn't name them" do
    url = url()

    start_supervised!(
      {Subscriber, to: self(), url: url, readers: [[publisher_id: 1, writer_id: 1]]}
    )

    start_supervised!(
      {Publisher,
       url: url,
       publisher_id: 1,
       interval: 20,
       writers: [
         [id: 1, fields: [{"A", :int32}, {"B", :string}], read: fn -> %{"A" => 1, "B" => "b"} end]
       ]}
    )

    assert data({1, 1}) == %{0 => 1, 1 => "b"}
  end

  test "only the datasets asked for, from the publisher and group asked for" do
    url = url()

    start_supervised!(
      {Subscriber,
       to: self(),
       url: url,
       readers: [[publisher_id: 2, writer_group_id: 5, writer_id: 1, fields: @fields]]}
    )

    for {id, publisher, group} <- [{:wrong_publisher, 3, 5}, {:wrong_group, 2, 6}, {:right, 2, 5}] do
      start_supervised!(
        {Publisher,
         url: url,
         publisher_id: publisher,
         writer_group_id: group,
         interval: 20,
         writers: [[id: 1, fields: @fields, read: fn -> %{"Name" => to_string(id)} end]]},
        id: id
      )
    end

    for _ <- 1..5, do: assert(data({2, 1})["Name"] == "right")
  end

  test "a dataset that stops arriving times out, once" do
    url = url()

    start_supervised!(
      {Subscriber,
       to: self(),
       url: url,
       readers: [[publisher_id: 1, writer_id: 1, fields: @fields, timeout: 100]]}
    )

    start_supervised!(
      {Publisher,
       url: url,
       publisher_id: 1,
       interval: 20,
       writers: [[id: 1, fields: @fields, read: fn -> @values end]]},
      id: :publisher
    )

    assert data({1, 1})
    stop_supervised!(:publisher)
    assert_receive {OPCUA.PubSub, {1, 1}, :timeout}, 1000
    refute_receive {OPCUA.PubSub, {1, 1}, :timeout}, 300
  end

  test "a message older than the last one is dropped" do
    url = url()

    start_supervised!(
      {Subscriber,
       to: self(), url: url, readers: [[publisher_id: 1, writer_id: 1, fields: [{"N", :int32}]]]}
    )

    {:ok, ip, port} = OPCUA.PubSub.address(url)
    {:ok, socket} = :gen_udp.open(0)

    send_message = fn sequence, n ->
      message = %UADP{
        publisher_id: {:byte, 1},
        writer_group_id: 1,
        messages: [
          %UADP.DataSetMessage{
            writer_id: 1,
            sequence_number: sequence,
            fields: [%OPCUA.Variant{type: :int32, value: n}]
          }
        ]
      }

      :ok = :gen_udp.send(socket, ip, port, UADP.encode(message))
    end

    send_message.(10, 10)
    assert data({1, 1}) == %{"N" => 10}
    send_message.(9, 9)
    send_message.(11, 11)
    assert data({1, 1}) == %{"N" => 11}
    # From 11, 65535 is more than half the range ahead, so it counts as older.
    send_message.(65_535, 65_535)
    refute_receive {OPCUA.PubSub, {1, 1}, {:data, _}}, 200
  end

  test "sequence numbers wrap around" do
    url = url()

    start_supervised!(
      {Subscriber,
       to: self(), url: url, readers: [[publisher_id: 1, writer_id: 1, fields: [{"N", :int32}]]]}
    )

    {:ok, ip, port} = OPCUA.PubSub.address(url)
    {:ok, socket} = :gen_udp.open(0)

    for sequence <- [65_534, 65_535, 0, 1] do
      message = %UADP{
        publisher_id: {:byte, 1},
        messages: [
          %UADP.DataSetMessage{
            writer_id: 1,
            sequence_number: sequence,
            fields: [%OPCUA.Variant{type: :int32, value: sequence}]
          }
        ]
      }

      :ok = :gen_udp.send(socket, ip, port, UADP.encode(message))
      assert data({1, 1}) == %{"N" => sequence}
    end
  end

  test "a value from :read that doesn't fit marks that writer's message invalid, not the others" do
    url = url()

    start_supervised!(
      {Subscriber,
       to: self(),
       url: url,
       readers: [
         [publisher_id: 1, writer_id: 1, fields: [{"N", :byte}]],
         [publisher_id: 1, writer_id: 2, fields: [{"N", :byte}]]
       ]}
    )

    ExUnit.CaptureLog.capture_log(fn ->
      start_supervised!(
        {Publisher,
         url: url,
         publisher_id: 1,
         interval: 20,
         writers: [
           [id: 1, fields: [{"N", :byte}], read: fn -> %{"N" => 300} end],
           [id: 2, fields: [{"N", :byte}], read: fn -> %{"N" => 3} end]
         ]}
      )

      assert data({1, 2}) == %{"N" => 3}
      refute_receive {OPCUA.PubSub, {1, 1}, {:data, _}}, 200
    end)
  end

  test "multicast reaches every subscriber on the port" do
    url = "opc.udp://239.255.42.#{:rand.uniform(200)}:#{48_500 + :rand.uniform(400)}"

    start_supervised!(
      {Subscriber,
       to: self(),
       url: url,
       readers: [[publisher_id: 1, writer_id: 1, fields: @fields, name: :one]]},
      id: :one
    )

    start_supervised!(
      {Subscriber,
       to: self(),
       url: url,
       readers: [[publisher_id: 1, writer_id: 1, fields: @fields, name: :two]]},
      id: :two
    )

    start_supervised!(
      {Publisher,
       url: url,
       publisher_id: 1,
       interval: 20,
       writers: [[id: 1, fields: @fields, read: fn -> @values end]]}
    )

    assert data(:one) == @values
    assert data(:two) == @values
  end
end
