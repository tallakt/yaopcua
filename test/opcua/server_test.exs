defmodule OPCUA.ServerTest do
  # The server, through yaopcua's own client.
  use ExUnit.Case, async: true

  alias OPCUA.{Client, DataValue, NodeId, Server, Variant}
  alias OPCUA.Types

  setup do
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
      Server.add_variable(server, "ns=2;s=Levels", "Levels",
        type: :double,
        value: [1.0, 2.0, 3.0, 4.0]
      )

    :ok =
      Server.add_method(server, "ns=2;s=Pump1.Multiply", "Multiply",
        parent: "ns=2;s=Pump1",
        inputs: [{"a", :int32}, {"b", :int32}],
        outputs: [{"product", :int32}],
        call: fn
          [_, 0] -> {:error, :bad_out_of_range}
          [_, 13] -> raise "unlucky"
          [a, b] -> {:ok, [a * b]}
        end
      )

    url = "opc.tcp://127.0.0.1:#{Server.port(server)}"
    %{server: server, url: url, client: start_supervised!({Client, url: url})}
  end

  test "offers one endpoint without security, for anonymous and username logins", %{url: url} do
    assert {:ok, [endpoint]} = Client.endpoints(url)
    assert endpoint.security_policy_uri == OPCUA.SecureChannel.none()
    assert Enum.map(endpoint.user_identity_tokens, & &1.token_type) == [:anonymous, :user_name]
    assert endpoint.server.application_type == :server
  end

  test "clients read values, stored or from a function", %{client: client} do
    assert Client.read(client, "ns=2;s=Pump1.Speed") == {:ok, 1500}
    assert Client.read(client, "ns=2;s=Pump1.Temp") == {:ok, 21.5}
    assert Client.read(client, "ns=2;s=Levels") == {:ok, [1.0, 2.0, 3.0, 4.0]}
    assert Client.read(client, "ns=2;s=Nope") == {:error, :bad_node_id_unknown}
  end

  test "a value function that raises is Bad for that value only", %{
    server: server,
    client: client
  } do
    :ok =
      Server.add_variable(server, "ns=2;s=Broken", "Broken",
        type: :int32,
        read: fn -> raise "no" end
      )

    :ok = Server.add_variable(server, "ns=2;s=Wrong", "Wrong", type: :byte, read: fn -> 300 end)

    ExUnit.CaptureLog.capture_log(fn ->
      assert {:ok, [broken, wrong, speed]} =
               Client.read_many(client, ["ns=2;s=Broken", "ns=2;s=Wrong", "ns=2;s=Pump1.Speed"])

      assert OPCUA.StatusCode.name(broken.status) == :bad_internal_error
      assert OPCUA.StatusCode.name(wrong.status) == :bad_internal_error
      assert speed.value.value == 1500
    end)
  end

  test "reads other attributes", %{client: client} do
    assert Client.read(client, "ns=2;s=Pump1.Speed", :browse_name) ==
             {:ok, %OPCUA.QualifiedName{ns: 2, name: "Speed"}}

    assert Client.read(client, "ns=2;s=Pump1.Speed", :node_class) == {:ok, 2}
    assert Client.read(client, "ns=2;s=Pump1.Speed", :data_type) == {:ok, %NodeId{id: 4}}
    assert Client.read(client, "ns=2;s=Pump1.Speed", :access_level) == {:ok, 3}
    assert Client.read(client, "ns=2;s=Levels", :value_rank) == {:ok, 1}
    assert Client.read(client, "ns=2;s=Pump1", :value) == {:error, :bad_attribute_id_invalid}
    assert Client.read(client, "ns=2;s=Pump1", :event_notifier) == {:ok, 0}
  end

  test "reads part of an array", %{client: client} do
    read = fn range ->
      request = %Types.ReadRequest{
        nodes_to_read: [
          %Types.ReadValueId{
            node_id: NodeId.parse!("ns=2;s=Levels"),
            attribute_id: 13,
            index_range: range
          }
        ]
      }

      {:ok, %{results: [result]}} = Client.request(client, request)
      if result.status == 0, do: result.value.value, else: OPCUA.StatusCode.name(result.status)
    end

    assert read.("1") == [2.0]
    assert read.("1:2") == [2.0, 3.0]
    assert read.("2:9") == [3.0, 4.0]
    assert read.("9") == :bad_index_range_no_data
    assert read.("x") == :bad_index_range_invalid
  end

  test "the standard nodes describe the server", %{client: client} do
    assert {:ok, %Types.ServerStatusDataType{state: :running, current_time: %DateTime{}}} =
             Client.read(client, "i=2256")

    assert Client.read(client, "i=2259") == {:ok, 0}

    assert {:ok, ["http://opcfoundation.org/UA/", "urn:yaopcua:server", "urn:plant"]} =
             Client.read(client, "i=2255")

    assert {:ok, refs} = Client.browse(client, "i=85")
    assert "Pump1" in Enum.map(refs, & &1.browse_name.name)
    assert "Server" in Enum.map(refs, & &1.browse_name.name)
  end

  test "clients write writable values of the right type", %{server: server, client: client} do
    assert Client.write(client, "ns=2;s=Pump1.Speed", 1600) == :ok

    assert %DataValue{value: %Variant{type: :int16, value: 1600}, source_timestamp: %DateTime{}} =
             Server.get(server, "ns=2;s=Pump1.Speed")

    assert Client.write(client, "ns=2;s=Pump1.Speed", %Variant{type: :double, value: 1.0}) ==
             {:error, :bad_type_mismatch}

    assert Client.write(client, "ns=2;s=Pump1.Temp", %Variant{type: :double, value: 1.0}) ==
             {:error, :bad_not_writable}

    assert Client.write(client, "ns=2;s=Nope", %Variant{type: :double, value: 1.0}) ==
             {:error, :bad_node_id_unknown}
  end

  test "a write function sees each write first, and may refuse it", %{
    server: server,
    client: client
  } do
    test = self()

    :ok =
      Server.add_variable(server, "ns=2;s=Setpoint", "Setpoint",
        type: :double,
        writable: true,
        write: fn
          value when value > 100 -> {:error, :bad_out_of_range}
          value -> send(test, {:written, value}) && :ok
        end
      )

    assert Client.write(client, "ns=2;s=Setpoint", 50.0) == :ok
    assert_received {:written, 50.0}
    assert Client.write(client, "ns=2;s=Setpoint", 500.0) == {:error, :bad_out_of_range}
    assert Client.read(client, "ns=2;s=Setpoint") == {:ok, 50.0}
  end

  test "the application sets values; one that doesn't fit raises", %{
    server: server,
    client: client
  } do
    assert Server.set(server, "ns=2;s=Pump1.Speed", 1700) == :ok
    assert Client.read(client, "ns=2;s=Pump1.Speed") == {:ok, 1700}

    space = Server.space(server)
    assert Server.set(space, "ns=2;s=Pump1.Speed", 1800) == :ok
    assert Client.read(client, "ns=2;s=Pump1.Speed") == {:ok, 1800}

    assert_raise ArgumentError, fn -> Server.set(server, "ns=2;s=Pump1.Speed", 1.5) end
    assert_raise ArgumentError, fn -> Server.set(server, "ns=2;s=Pump1.Speed", 70_000) end
    assert_raise ArgumentError, fn -> Server.set(server, "ns=2;s=Nope", 1) end
  end

  test "browses children, and pages many of them with continuation points", %{
    server: server,
    client: client
  } do
    assert {:ok, refs} = Client.browse(client, "ns=2;s=Pump1")

    assert Enum.map(refs, &{&1.browse_name.name, &1.node_class}) == [
             {"Speed", :variable},
             {"Temp", :variable},
             {"Multiply", :method}
           ]

    assert %OPCUA.ExpandedNodeId{id: 63} = hd(refs).type_definition

    :ok = Server.add_folder(server, "ns=2;s=Many", "Many")

    for i <- 1..250,
        do:
          :ok =
            Server.add_variable(server, "ns=2;s=Many.#{i}", "Item#{i}",
              parent: "ns=2;s=Many",
              type: :int32,
              value: i
            )

    assert {:ok, many} = Client.browse(client, "ns=2;s=Many", max_references: 100)
    assert Enum.map(many, & &1.browse_name.name) == for(i <- 1..250, do: "Item#{i}")
  end

  test "browses inverse references", %{client: client} do
    assert {:ok, [parent]} = Client.browse(client, "ns=2;s=Pump1.Speed", direction: :inverse)
    assert parent.node_id == %OPCUA.ExpandedNodeId{ns: 2, id: "Pump1"}
    refute parent.is_forward
  end

  test "translates browse paths to node ids", %{client: client} do
    path = fn names ->
      %Types.BrowsePath{
        starting_node: %NodeId{id: 85},
        relative_path: %Types.RelativePath{
          elements:
            for(
              name <- names,
              do: %Types.RelativePathElement{
                include_subtypes: true,
                target_name: %OPCUA.QualifiedName{ns: 2, name: name}
              }
            )
        }
      }
    end

    request = %Types.TranslateBrowsePathsToNodeIdsRequest{
      browse_paths: [path.(["Pump1", "Speed"]), path.(["Pump1", "Nope"])]
    }

    assert {:ok, %{results: [found, missing]}} = Client.request(client, request)
    assert [%{target_id: %OPCUA.ExpandedNodeId{ns: 2, id: "Pump1.Speed"}}] = found.targets
    assert OPCUA.StatusCode.name(missing.status_code) == :bad_no_match
  end

  test "calls methods, checking their arguments", %{client: client} do
    assert Client.call(client, "ns=2;s=Pump1", "ns=2;s=Pump1.Multiply", [6, 7]) == {:ok, [42]}

    assert Client.call(client, "ns=2;s=Pump1", "ns=2;s=Pump1.Multiply", [6]) ==
             {:error, :bad_arguments_missing}

    assert Client.call(client, "ns=2;s=Pump1", "ns=2;s=Pump1.Multiply", [6, 7, 8]) ==
             {:error, :bad_too_many_arguments}

    assert Client.call(client, "ns=2;s=Pump1", "ns=2;s=Pump1.Multiply", [6, 7.0]) ==
             {:error, :bad_invalid_argument}

    assert Client.call(client, "ns=2;s=Pump1", "ns=2;s=Pump1.Multiply", [6, 0]) ==
             {:error, :bad_out_of_range}

    assert Client.call(client, "i=85", "ns=2;s=Pump1.Multiply", [6, 7]) ==
             {:error, :bad_method_invalid}

    assert ExUnit.CaptureLog.capture_log(fn ->
             assert Client.call(client, "ns=2;s=Pump1", "ns=2;s=Pump1.Multiply", [6, 13]) ==
                      {:error, :bad_internal_error}
           end) =~ "unlucky"

    assert {:ok, [%Types.Argument{name: "a"}, %Types.Argument{name: "b"}]} =
             Client.read(client, "ns=2;s=Pump1.Multiply.InputArguments")
  end

  test "a method from namespace 0 the server doesn't implement says so", %{client: client} do
    # Server.GetMonitoredItems
    assert Client.call(client, "i=2253", "i=11492", [%Variant{type: :uint32, value: 1}]) ==
             {:error, :bad_not_implemented}
  end

  test "logs in with a username, and refuses a wrong password", %{url: url} do
    assert {:ok, client} = Client.start(url: url, user: {"operator", "secret"})
    assert Client.read(client, "ns=2;s=Pump1.Speed") == {:ok, 1500}
    Client.close(client)

    assert Client.start(url: url, user: {"operator", "wrong"}) ==
             {:error, :bad_user_access_denied}
  end

  test "refuses anonymous logins when told to" do
    server = start_supervised!({Server, port: 0, anonymous: false}, id: :closed)
    url = "opc.tcp://127.0.0.1:#{Server.port(server)}"
    assert {:ok, [%{user_identity_tokens: []}]} = Client.endpoints(url)
    assert Client.start(url: url) == {:error, :bad_identity_token_rejected}
  end

  test "answers a service it doesn't have with a fault", %{client: client} do
    assert Client.request(client, %Types.QueryFirstRequest{}) ==
             {:error, :bad_service_unsupported}
  end

  test "refuses to add a node twice, or under a parent that isn't there", %{server: server} do
    assert Server.add_object(server, "ns=2;s=Pump1", "Pump1") == {:error, :bad_node_id_exists}

    assert Server.add_object(server, "ns=2;s=Pump2", "Pump2", parent: "ns=2;s=Nope") ==
             {:error, :bad_parent_node_id_invalid}
  end

  test "the client keeps an idle session alive", %{url: url} do
    client = start_supervised!({Client, url: url, session_timeout: 1000}, id: :idle)
    assert :sys.get_state(client).session_timeout == 1000.0
    Process.sleep(2500)
    assert Client.read(client, "ns=2;s=Pump1.Speed") == {:ok, 1500}
  end

  test "a session the client stops keeping alive expires", %{url: url} do
    {:ok, client} = Client.start(url: url, session_timeout: 1000)
    ref = Process.monitor(client)
    :sys.suspend(client)
    Process.sleep(1500)
    :sys.resume(client)
    assert_receive {:DOWN, ^ref, :process, _, {:shutdown, :bad_session_id_invalid}}, 3000
  end

  test "renews the secure channel, and closes one that isn't renewed", %{url: url} do
    client = start_supervised!({Client, url: url, channel_lifetime: 1000}, id: :renewing)
    first = :sys.get_state(client).token.token_id
    Process.sleep(1500)
    assert Client.read(client, "ns=2;s=Pump1.Speed") == {:ok, 1500}
    assert :sys.get_state(client).token.token_id != first

    {:ok, lazy} = Client.start(url: url, channel_lifetime: 1000)
    ref = Process.monitor(lazy)
    :sys.suspend(lazy)
    Process.sleep(1500)
    :sys.resume(lazy)
    assert_receive {:DOWN, ^ref, :process, _, {:shutdown, _}}, 3000
  end

  describe "subscriptions" do
    defp next(sub, timeout \\ 2000) do
      receive do
        {Client, ^sub, message} -> message
      after
        timeout -> flunk("no message from subscription #{sub}")
      end
    end

    defp none(sub, timeout \\ 300) do
      receive do
        {Client, ^sub, message} -> flunk("unexpected #{inspect(message)}")
      after
        timeout -> :ok
      end
    end

    # Publish requests sent by hand, to see what the server does with them.
    defp publish(client, acks \\ []) do
      Client.request(client, %Types.PublishRequest{subscription_acknowledgements: acks}, 3000)
    end

    defp raw_subscription(client, keep_alive, lifetime) do
      request = %Types.CreateSubscriptionRequest{
        requested_publishing_interval: 50.0,
        requested_max_keep_alive_count: keep_alive,
        requested_lifetime_count: lifetime,
        publishing_enabled: true
      }

      {:ok, %{subscription_id: id}} = Client.request(client, request)
      id
    end

    test "sends the current value, then changes the application makes", %{
      server: server,
      client: client
    } do
      {:ok, sub} = Client.subscribe(client, ["ns=2;s=Pump1.Speed"], interval: 50)
      assert {:value, "ns=2;s=Pump1.Speed", %DataValue{value: %Variant{value: 1500}}} = next(sub)

      :ok = Server.set(server, "ns=2;s=Pump1.Speed", 1510)

      assert {:value, _, %DataValue{value: %Variant{value: 1510}, source_timestamp: %DateTime{}}} =
               next(sub)

      # the same value again is no change
      :ok = Server.set(server, "ns=2;s=Pump1.Speed", 1510)
      none(sub)
    end

    test "changes within one interval arrive as the latest", %{server: server, client: client} do
      {:ok, sub} = Client.subscribe(client, ["ns=2;s=Pump1.Speed"], interval: 200)
      assert {:value, _, _} = next(sub)
      for v <- [1, 2, 3], do: :ok = Server.set(server, "ns=2;s=Pump1.Speed", v)
      assert {:value, _, %DataValue{value: %Variant{value: 3}}} = next(sub)
      none(sub)
    end

    test "a larger queue keeps each change", %{server: server, client: client} do
      {:ok, sub} =
        Client.subscribe(client, ["ns=2;s=Pump1.Speed"], interval: 300, sampling: 10, queue: 10)

      assert {:value, _, _} = next(sub)

      for v <- [1, 2, 3] do
        :ok = Server.set(server, "ns=2;s=Pump1.Speed", v)
        Process.sleep(40)
      end

      values = for _ <- 1..3, do: next(sub) |> elem(2) |> Map.get(:value) |> Map.get(:value)
      assert values == [1, 2, 3]
    end

    test "a function value is sampled", %{server: server, client: client} do
      counter = :counters.new(1, [])

      :ok =
        Server.add_variable(server, "ns=2;s=Ticks", "Ticks",
          type: :uint32,
          read: fn -> :counters.get(counter, 1) end
        )

      {:ok, sub} = Client.subscribe(client, ["ns=2;s=Ticks"], interval: 50)
      assert {:value, _, %DataValue{value: %Variant{value: 0}}} = next(sub)
      :counters.add(counter, 1, 5)
      assert {:value, _, %DataValue{value: %Variant{value: 5}}} = next(sub)
    end

    test "a deadband leaves out small changes", %{server: server, client: client} do
      :ok = Server.add_variable(server, "ns=2;s=Level", "Level", type: :double, value: 0.0)

      {:ok, sub} =
        Client.subscribe(client, ["ns=2;s=Level"], interval: 50, deadband: {:absolute, 1.0})

      assert {:value, _, _} = next(sub)
      :ok = Server.set(server, "ns=2;s=Level", 0.5)
      none(sub)
      :ok = Server.set(server, "ns=2;s=Level", 2.0)
      assert {:value, _, %DataValue{value: %Variant{value: 2.0}}} = next(sub)

      # A percent deadband needs an EURange, which these variables don't have.
      {:ok, percent} = Client.subscribe(client, ["ns=2;s=Level"], deadband: {:percent, 5.0})
      assert {:value, _, %DataValue{status: status}} = next(percent)
      assert OPCUA.StatusCode.name(status) == :bad_monitored_item_filter_unsupported
    end

    test "a node that can't be monitored gets one message with its status", %{client: client} do
      {:ok, sub} = Client.subscribe(client, ["ns=2;s=Nope"], interval: 50)
      assert {:value, "ns=2;s=Nope", %DataValue{status: status}} = next(sub)
      assert OPCUA.StatusCode.name(status) == :bad_node_id_unknown
      none(sub)
    end

    test "unsubscribing stops the messages", %{server: server, client: client} do
      {:ok, sub} = Client.subscribe(client, ["ns=2;s=Pump1.Speed"], interval: 50)
      assert {:value, _, _} = next(sub)
      assert Client.unsubscribe(client, sub) == :ok
      :ok = Server.set(server, "ns=2;s=Pump1.Speed", 7)
      none(sub)
      assert Client.unsubscribe(client, sub) == {:error, :bad_subscription_id_invalid}
    end

    test "sends a keep-alive when there is nothing to report", %{client: client} do
      sub = raw_subscription(client, 2, 10)
      started = System.monotonic_time(:millisecond)

      assert {:ok, %Types.PublishResponse{subscription_id: ^sub, notification_message: message}} =
               publish(client)

      assert message.notification_data in [nil, []]
      assert message.sequence_number == 1
      assert (System.monotonic_time(:millisecond) - started) in 50..400
    end

    test "keeps sent notifications until they're acknowledged, for Republish", %{client: client} do
      sub = raw_subscription(client, 10, 30)

      item = %Types.MonitoredItemCreateRequest{
        item_to_monitor: %Types.ReadValueId{
          node_id: NodeId.parse!("ns=2;s=Pump1.Speed"),
          attribute_id: 13
        },
        monitoring_mode: :reporting,
        requested_parameters: %Types.MonitoringParameters{
          client_handle: 1,
          sampling_interval: -1.0,
          queue_size: 1
        }
      }

      {:ok, _} =
        Client.request(client, %Types.CreateMonitoredItemsRequest{
          subscription_id: sub,
          timestamps_to_return: :both,
          items_to_create: [item]
        })

      assert {:ok,
              %{
                notification_message: %{sequence_number: 1} = message,
                available_sequence_numbers: [1]
              }} = publish(client)

      assert {:ok, %{notification_message: ^message}} =
               Client.request(client, %Types.RepublishRequest{
                 subscription_id: sub,
                 retransmit_sequence_number: 1
               })

      ack = %Types.SubscriptionAcknowledgement{subscription_id: sub, sequence_number: 1}
      assert {:ok, %{results: [0]}} = publish(client, [ack])

      assert Client.request(client, %Types.RepublishRequest{
               subscription_id: sub,
               retransmit_sequence_number: 1
             }) ==
               {:error, :bad_message_not_available}
    end

    test "a subscription nobody publishes for expires", %{client: client} do
      sub = raw_subscription(client, 1, 3)
      Process.sleep(400)

      assert {:ok,
              %{
                subscription_id: ^sub,
                notification_message: %{
                  notification_data: [%Types.StatusChangeNotification{status: status}]
                }
              }} = publish(client)

      assert OPCUA.StatusCode.name(status) == :bad_timeout
      assert publish(client) == {:error, :bad_no_subscription}
    end

    test "the client's subscriber hears when the server drops a subscription", %{url: url} do
      {:ok, client} = Client.start(url: url)
      {:ok, sub} = Client.subscribe(client, ["ns=2;s=Pump1.Speed"], interval: 50, keep_alive: 100)
      assert {:value, _, _} = next(sub)
      :sys.suspend(client)
      Process.sleep(1500)
      :sys.resume(client)
      assert next(sub) == {:status, :bad_timeout}
      refute Map.has_key?(:sys.get_state(client).subscriptions, sub)
      Client.close(client)
    end

    test "a Publish without subscriptions is refused", %{client: client} do
      assert publish(client) == {:error, :bad_no_subscription}
    end

    test "closing the session ends its subscriptions", %{url: url, server: server} do
      {:ok, client} = Client.start(url: url)
      {:ok, _} = Client.subscribe(client, ["ns=2;s=Pump1.Speed"], interval: 50)
      Client.close(client)
      Process.sleep(100)
      # The server is still fine for others.
      other = start_supervised!({Client, url: url}, id: :other)

      assert Client.read(other, "ns=2;s=Pump1.Speed") ==
               {:ok, Server.get(server, "ns=2;s=Pump1.Speed").value.value}
    end
  end

  describe "events and alarms" do
    @alarm_fields [
      "EventId",
      "EventType",
      "ConditionId",
      "Message",
      "Severity",
      "ActiveState/Id",
      "AckedState/Id",
      "EnabledState/Id",
      "Retain",
      "Comment"
    ]

    setup %{server: server} do
      test = self()

      :ok =
        Server.add_condition(server, "ns=2;s=Pump1.Overload", "Overload",
          source: "ns=2;s=Pump1",
          severity: 700,
          message: "Pump 1 overload",
          acknowledge: fn
            "no" -> {:error, :bad_user_access_denied}
            comment -> send(test, {:acknowledged, comment}) && :ok
          end
        )

      :ok
    end

    defp event(sub, timeout \\ 2000) do
      receive do
        {Client, ^sub, {:event, event}} -> event
      after
        timeout -> flunk("no event from subscription #{sub}")
      end
    end

    defp no_event(sub, timeout \\ 300) do
      receive do
        {Client, ^sub, {:event, event}} -> flunk("unexpected #{inspect(event)}")
      after
        timeout -> :ok
      end
    end

    test "an event from the application reaches subscribers with the fields they asked for", %{
      server: server,
      client: client
    } do
      {:ok, sub} =
        Client.subscribe_events(client,
          fields: ["Message", "Severity", "SourceNode", "2:Batch", "ConditionId"],
          interval: 50
        )

      :ok =
        Server.event(server,
          message: "Shift change",
          severity: 100,
          fields: [{"2:Batch", %Variant{type: :string, value: "B-17"}}]
        )

      assert event(sub) == %{
               "Message" => %OPCUA.LocalizedText{text: "Shift change"},
               "Severity" => 100,
               "SourceNode" => %NodeId{id: 2253},
               "2:Batch" => "B-17",
               "ConditionId" => nil
             }
    end

    test "an alarm goes from active to acknowledged to normal", %{server: server, client: client} do
      {:ok, sub} = Client.subscribe_events(client, fields: @alarm_fields, interval: 50)
      :ok = Server.condition(server, "ns=2;s=Pump1.Overload", active: true)

      active = event(sub)

      assert %{
               "EventType" => %NodeId{id: 10637},
               "ConditionId" => %NodeId{ns: 2, id: "Pump1.Overload"},
               "Message" => %OPCUA.LocalizedText{text: "Pump 1 overload"},
               "Severity" => 700,
               "ActiveState/Id" => true,
               "AckedState/Id" => false,
               "Retain" => true
             } = active

      assert Client.acknowledge(client, active["ConditionId"], "not the event id") ==
               {:error, :bad_event_id_unknown}

      assert Client.acknowledge(client, active["ConditionId"], active["EventId"], "on it") == :ok
      assert_received {:acknowledged, "on it"}

      acked = event(sub)

      assert %{
               "ActiveState/Id" => true,
               "AckedState/Id" => true,
               "Retain" => true,
               "Comment" => %{text: "on it"}
             } = acked

      assert Client.acknowledge(client, acked["ConditionId"], acked["EventId"]) ==
               {:error, :bad_condition_branch_already_acked}

      :ok = Server.condition(server, "ns=2;s=Pump1.Overload", active: false)
      assert %{"ActiveState/Id" => false, "AckedState/Id" => true, "Retain" => false} = event(sub)
    end

    test "an alarm that returns to normal unacknowledged stays retained", %{
      server: server,
      client: client
    } do
      {:ok, sub} = Client.subscribe_events(client, fields: @alarm_fields, interval: 50)
      :ok = Server.condition(server, "ns=2;s=Pump1.Overload", active: true)
      assert %{"Retain" => true} = event(sub)
      :ok = Server.condition(server, "ns=2;s=Pump1.Overload", active: false)
      assert %{"ActiveState/Id" => false, "AckedState/Id" => false, "Retain" => true} = event(sub)
    end

    test "the application may refuse an acknowledgement", %{server: server, client: client} do
      {:ok, sub} = Client.subscribe_events(client, fields: @alarm_fields, interval: 50)
      :ok = Server.condition(server, "ns=2;s=Pump1.Overload", active: true)
      active = event(sub)

      assert Client.acknowledge(client, active["ConditionId"], active["EventId"], "no") ==
               {:error, :bad_user_access_denied}

      no_event(sub)
      assert Client.read(client, "ns=2;s=Pump1.Overload.AckedState.Id") == {:ok, false}
    end

    test "the same state again sends no event", %{server: server, client: client} do
      {:ok, sub} = Client.subscribe_events(client, fields: ["Message"], interval: 50)
      :ok = Server.condition(server, "ns=2;s=Pump1.Overload", active: true)
      assert event(sub)
      :ok = Server.condition(server, "ns=2;s=Pump1.Overload", active: true)
      no_event(sub)
    end

    test "ConditionRefresh sends the standing alarms between two markers", %{
      server: server,
      client: client
    } do
      :ok = Server.add_condition(server, "ns=2;s=Pump1.Dry", "Dry", source: "ns=2;s=Pump1")
      :ok = Server.condition(server, "ns=2;s=Pump1.Overload", active: true)

      {:ok, sub} =
        Client.subscribe_events(client, fields: ["EventType", "ConditionId"], interval: 50)

      assert Client.refresh(client, sub) == :ok

      assert event(sub) == %{"EventType" => %NodeId{id: 2787}, "ConditionId" => nil}

      assert event(sub) == %{
               "EventType" => %NodeId{id: 10637},
               "ConditionId" => %NodeId{ns: 2, id: "Pump1.Overload"}
             }

      assert event(sub) == %{"EventType" => %NodeId{id: 2788}, "ConditionId" => nil}
      no_event(sub)

      assert Client.refresh(client, 999_999) == {:error, :bad_subscription_id_invalid}
    end

    test "a refresh of a filtered subscription still carries the markers", %{
      server: server,
      client: client
    } do
      :ok = Server.condition(server, "ns=2;s=Pump1.Overload", active: true)

      {:ok, sub} =
        Client.subscribe_events(client, fields: ["EventType"], of_type: "i=2915", interval: 50)

      assert Client.refresh(client, sub) == :ok
      assert Enum.map(1..3, fn _ -> event(sub)["EventType"].id end) == [2787, 10637, 2788]
    end

    test "filters events by type, or by a where clause", %{server: server, client: client} do
      {:ok, alarms} =
        Client.subscribe_events(client, fields: ["Message"], of_type: "i=2915", interval: 50)

      severe = %OPCUA.Types.ContentFilter{
        elements: [
          %Types.ContentFilterElement{
            filter_operator: :greater_than_or_equal,
            filter_operands: [
              %Types.SimpleAttributeOperand{
                type_definition_id: %NodeId{id: 2041},
                browse_path: [%OPCUA.QualifiedName{name: "Severity"}],
                attribute_id: 13
              },
              %Types.LiteralOperand{value: %Variant{type: :uint16, value: 600}}
            ]
          }
        ]
      }

      {:ok, high} =
        Client.subscribe_events(client, fields: ["Message"], where: severe, interval: 50)

      :ok = Server.event(server, message: "low", severity: 100)
      :ok = Server.event(server, message: "high", severity: 900)
      :ok = Server.condition(server, "ns=2;s=Pump1.Overload", active: true)

      assert event(alarms) == %{"Message" => %OPCUA.LocalizedText{text: "Pump 1 overload"}}
      no_event(alarms)
      assert event(high) == %{"Message" => %OPCUA.LocalizedText{text: "high"}}
      assert event(high) == %{"Message" => %OPCUA.LocalizedText{text: "Pump 1 overload"}}
      no_event(high)
    end

    test "a source reports its own alarms, not the server's other events", %{
      server: server,
      client: client
    } do
      {:ok, pump} =
        Client.subscribe_events(client, source: "ns=2;s=Pump1", fields: ["Message"], interval: 50)

      :ok = Server.event(server, message: "elsewhere")
      :ok = Server.condition(server, "ns=2;s=Pump1.Overload", active: true)
      assert event(pump) == %{"Message" => %OPCUA.LocalizedText{text: "Pump 1 overload"}}
      no_event(pump)

      {:ok, not_notifier} =
        Client.subscribe_events(client, source: "ns=2;s=Pump1.Speed", interval: 50)

      assert_receive {Client, ^not_notifier, {:status, :bad_attribute_id_invalid}}, 2000
    end

    test "a condition can be disabled, enabled and commented on", %{
      server: server,
      client: client
    } do
      {:ok, sub} = Client.subscribe_events(client, fields: @alarm_fields, interval: 50)
      :ok = Server.condition(server, "ns=2;s=Pump1.Overload", active: true)
      active = event(sub)
      condition = active["ConditionId"]

      assert Client.call(client, condition, "i=9029", [
               %Variant{type: :byte_string, value: active["EventId"]},
               %OPCUA.LocalizedText{text: "checking"}
             ]) == {:ok, []}

      commented = event(sub)
      assert commented["Comment"].text == "checking"

      assert Client.call(client, condition, "i=9028", []) == {:ok, []}
      assert %{"EnabledState/Id" => false, "Retain" => false} = event(sub)

      assert Client.call(client, condition, "i=9028", []) ==
               {:error, :bad_condition_already_disabled}

      assert Client.acknowledge(client, condition, commented["EventId"]) |> elem(0) == :error

      assert Client.call(client, condition, "i=9027", []) == {:ok, []}
      assert %{"EnabledState/Id" => true, "Retain" => true} = event(sub)
    end

    test "conditions are found from their source, and their state can be read", %{
      server: server,
      client: client
    } do
      assert {:ok, [ref]} = Client.browse(client, "ns=2;s=Pump1", reference_type: "i=9006")
      assert ref.browse_name.name == "Overload"
      assert ref.type_definition == %OPCUA.ExpandedNodeId{id: 10637}

      :ok = Server.condition(server, "ns=2;s=Pump1.Overload", active: true, severity: 900)
      assert Client.read(client, "ns=2;s=Pump1.Overload.ActiveState.Id") == {:ok, true}

      assert Client.read(client, "ns=2;s=Pump1.Overload.ActiveState") ==
               {:ok, %OPCUA.LocalizedText{locale: "en", text: "Active"}}

      assert Client.read(client, "ns=2;s=Pump1.Overload.Severity") == {:ok, 900}
      assert Client.read(client, "ns=2;s=Pump1.Overload.Retain") == {:ok, true}
    end

    test "refuses conditions it doesn't have", %{server: server} do
      assert Server.condition(server, "ns=2;s=Nope", active: true) ==
               {:error, :bad_node_id_unknown}

      assert Server.add_condition(server, "ns=2;s=X", "X", source: "ns=2;s=Nope") ==
               {:error, :bad_parent_node_id_invalid}
    end
  end
end
