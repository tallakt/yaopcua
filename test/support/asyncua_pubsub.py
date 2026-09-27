# asyncua's PubSub for yaopcua's interop tests, over unicast UDP on localhost.
#
#   publish PORT ENCODING SECONDS: publishes the "Plant" dataset (writer 7 in
#     group 3 of publisher 42) with Speed counting up, in variant, datavalue or
#     raw encoding.
#   subscribe PORT SECONDS: reads writers 1 and 2 of group 1 of publisher 42,
#     and prints the values each sent last, as JSON.
import asyncio, json, sys
from asyncua import ua
from asyncua.pubsub import *

FIELDS = [("Speed", ua.VariantType.Int16), ("Level", ua.VariantType.Double), ("Name", ua.VariantType.String), ("Running", ua.VariantType.Boolean)]


def meta(name):
    return DataSetMeta.Create(name, dataset_fields=[DataSetField.CreateScalar(n, t) for n, t in FIELDS])


async def start(ps, con):
    added = ps.add_connection(con)
    if asyncio.iscoroutine(added):
        await added


async def publish(port, encoding, seconds):
    plant = meta("Plant")
    source = PubSubDataSourceDict(plant)
    pds = PublishedDataSet.Create("Plant", plant, source)
    writer = DataSetWriter.new_uadp("W", "Plant", 7, datavalue=(encoding == "datavalue"), raw=(encoding == "raw"))
    group = WriterGroup.new_uadp("G", 3, publishing_interval=50, writer=[writer])
    con = PubSubConnection.udp_uadp("C", ua.UInt16(42), UdpSettings(Url=f"opc.udp://127.0.0.1:{port}"), writer_groups=[group])
    ps = PubSub.new(datasets=[pds])
    await start(ps, con)
    async with ps:
        for speed in range(int(seconds / 0.05)):
            source.datasources["Plant"] = {
                "Speed": ua.DataValue(ua.Variant(speed, ua.VariantType.Int16)),
                "Level": ua.DataValue(ua.Variant(2.5, ua.VariantType.Double)),
                "Name": ua.DataValue(ua.Variant("Pump 1", ua.VariantType.String)),
                "Running": ua.DataValue(ua.Variant(True, ua.VariantType.Boolean)),
            }
            await asyncio.sleep(0.05)


# asyncua calls these methods of whatever it's given as the subscribed dataset.
class Collect:
    def __init__(self, into, writer):
        self.into = into
        self.writer = writer

    def get_subscribed_dataset(self):
        return None

    async def on_state_change(self, meta, state):
        pass

    async def on_dataset_received(self, meta, fields):
        self.into[self.writer] = {f.Name: f.Value.Value.Value for f in fields}


async def subscribe(port, seconds):
    got = {}
    readers = [
        DataSetReader.new(ua.Variant(ua.UInt16(42), ua.VariantType.UInt16), 1, writer, meta(f"W{writer}"), subscribed=Collect(got, writer), enabled=True)
        for writer in [1, 2]
    ]
    con = PubSubConnection.udp_uadp("C", ua.UInt16(99), UdpSettings(Url=f"opc.udp://127.0.0.1:{port}"), reader_groups=[ReaderGroup.new("R", reader=readers, enable=True)])
    ps = PubSub.new()
    await start(ps, con)
    async with ps:
        print("ready", flush=True)
        await asyncio.sleep(seconds)
    print(json.dumps(got), flush=True)


if sys.argv[1] == "publish":
    asyncio.run(publish(int(sys.argv[2]), sys.argv[3], float(sys.argv[4])))
else:
    asyncio.run(subscribe(int(sys.argv[2]), float(sys.argv[3])))
