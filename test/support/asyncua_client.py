# Runs asyncua's client against a yaopcua server for the interop tests, and
# prints what it saw as JSON. The server is set up by server_interop_test.exs.
import asyncio, json, sys
from asyncua import Client, ua


async def main(url):
    out = {}
    async with Client(url) as client:
        out["namespaces"] = await client.get_namespace_array()
        objects = client.nodes.objects
        out["objects"] = sorted([(await n.read_browse_name()).Name for n in await objects.get_children()])

        speed = client.get_node("ns=2;s=Pump1.Speed")
        out["speed"] = await speed.read_value()
        await speed.write_value(ua.DataValue(ua.Variant(1234, ua.VariantType.Int16)))
        out["speed_after"] = await speed.read_value()
        out["display_name"] = (await speed.read_display_name()).Text
        out["data_type"] = (await speed.read_data_type()).to_string()
        out["levels"] = await client.get_node("ns=2;s=Tank.Levels").read_value()

        try:
            await client.get_node("ns=2;s=Pump1.Temp").write_value(ua.DataValue(ua.Variant(1.0, ua.VariantType.Double)))
            out["read_only"] = "written"
        except ua.UaStatusCodeError as e:
            out["read_only"] = ua.StatusCodes.__dict__.get("BadNotWritable") == e.code and "BadNotWritable" or hex(e.code)

        pump = client.get_node("ns=2;s=Pump1")
        out["multiply"] = await pump.call_method("2:Multiply", ua.Variant(6, ua.VariantType.Int32), ua.Variant(7, ua.VariantType.Int32))
        out["path"] = (await objects.get_child(["2:Pump1", "2:Speed"])).nodeid.to_string()
        status = await client.get_node(ua.ObjectIds.Server_ServerStatus).read_value()
        out["state"] = status.State.name
        out["many"] = len(await client.get_node("ns=2;s=Many").get_children())

    # A subscription: the current value first, then the change this client makes.
    class Changes:
        def __init__(self):
            self.values = []

        def datachange_notification(self, node, value, data):
            self.values.append(value)

    async with Client(url) as client:
        speed = client.get_node("ns=2;s=Pump1.Speed")
        changes = Changes()
        subscription = await client.create_subscription(50, changes)
        await subscription.subscribe_data_change(speed)
        await asyncio.sleep(0.3)
        await speed.write_value(ua.DataValue(ua.Variant(777, ua.VariantType.Int16)))
        await asyncio.sleep(0.3)
        await subscription.delete()
        out["subscription"] = changes.values

    # An alarm: tripped through a method, then acknowledged by this client.
    async with Client(url) as client:
        events = []

        class Events:
            def event_notification(self, event):
                events.append(event)

        subscription = await client.create_subscription(50, Events())
        await subscription.subscribe_events(client.nodes.server, ua.ObjectIds.OffNormalAlarmType)
        await client.get_node("ns=2;s=Pump1").call_method("2:Trip")
        await asyncio.sleep(0.3)
        alarm = events[-1]
        acknowledge = ua.NodeId(ua.ObjectIds.AcknowledgeableConditionType_Acknowledge)
        await client.get_node(alarm.NodeId).call_method(acknowledge, ua.Variant(alarm.EventId, ua.VariantType.ByteString), ua.LocalizedText("from asyncua"))
        await asyncio.sleep(0.3)
        acked = events[-1]
        await subscription.delete()
        out["alarm"] = {
            "condition": alarm.NodeId.to_string(),
            "message": alarm.Message.Text,
            "severity": alarm.Severity,
            "active": getattr(alarm, "ActiveState/Id"),
            "acked": getattr(alarm, "AckedState/Id"),
            "acked_after": getattr(acked, "AckedState/Id"),
            "comment": acked.Comment.Text,
        }

    user = Client(url)
    user.set_user("operator")
    user.set_password("secret")
    async with user:
        out["user_read"] = await user.get_node("ns=2;s=Pump1.Temp").read_value()

    print(json.dumps(out))


asyncio.run(main(sys.argv[1]))
