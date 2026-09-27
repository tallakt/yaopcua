# An asyncua OPC UA server for yaopcua's interop tests. The tests start it as a
# separate process with the port as argument; it prints "ready" once it listens
# and exits when its stdin closes.
import asyncio, sys
from asyncua import Server, ua, uamethod
from asyncua.server.user_managers import UserManager
from asyncua.crypto.permission_rules import User, UserRole


class Users(UserManager):
    def get_user(self, iserver, username=None, password=None, certificate=None):
        if username is None:
            return User(role=UserRole.User)
        if (username, password) == ("operator", "secret"):
            return User(role=UserRole.User, name=username)
        return None


@uamethod
def multiply(parent, a, b):
    return a * b


async def main(port):
    server = Server(user_manager=Users())
    await server.init()
    server.set_endpoint(f"opc.tcp://127.0.0.1:{port}/yaopcua/")
    server.set_server_name("yaopcua test server")
    server.set_security_policy([ua.SecurityPolicyType.NoSecurity])
    ns = await server.register_namespace("urn:yaopcua:test")

    plant = await server.nodes.objects.add_object(ua.NodeId("Plant", ns), ua.QualifiedName("Plant", ns))
    variables = [
        ("Pump1.Speed", 1500, ua.VariantType.Int16),
        ("Pump1.Running", True, ua.VariantType.Boolean),
        ("Pump1.Name", "Pump 1", ua.VariantType.String),
        ("Tank.Level", 2.5, ua.VariantType.Double),
        ("Tank.Setpoints", [1.0, 2.0, 3.0], ua.VariantType.Double),
        ("Counter", 7, ua.VariantType.UInt32),
        # for the tests that write
        ("Scratch.Int16", 0, ua.VariantType.Int16),
        ("Scratch.UInt32", 0, ua.VariantType.UInt32),
        ("Scratch.Double", 0.0, ua.VariantType.Double),
        ("Scratch.Boolean", True, ua.VariantType.Boolean),
        ("Scratch.String", "", ua.VariantType.String),
        ("Scratch.Array", [0.0], ua.VariantType.Double),
    ]
    for name, value, vtype in variables:
        node = await plant.add_variable(ua.NodeId(name, ns), ua.QualifiedName(name, ns), ua.Variant(value, vtype))
        await node.set_writable()

    readonly = await plant.add_variable(ua.NodeId("ReadOnly", ns), ua.QualifiedName("ReadOnly", ns), ua.Variant(1, ua.VariantType.Int32))

    # Enough children that browsing them takes more than one BrowseNext.
    many = await plant.add_folder(ua.NodeId("Many", ns), ua.QualifiedName("Many", ns))
    for i in range(250):
        await many.add_variable(ua.NodeId(f"Many.{i}", ns), ua.QualifiedName(f"Item{i}", ns), ua.Variant(i, ua.VariantType.Int32))

    await plant.add_method(ua.NodeId("Multiply", ns), ua.QualifiedName("Multiply", ns), multiply,
                           [ua.VariantType.Int32, ua.VariantType.Int32], [ua.VariantType.Int32])

    events = await server.get_event_generator()

    @uamethod
    async def fire(parent, message, severity):
        events.event.Message = ua.LocalizedText(message)
        events.event.Severity = severity
        await events.trigger()

    await plant.add_method(ua.NodeId("Fire", ns), ua.QualifiedName("Fire", ns), fire,
                           [ua.VariantType.String, ua.VariantType.UInt16], [])

    async with server:
        print("ready", flush=True)
        await asyncio.get_running_loop().run_in_executor(None, sys.stdin.read)


asyncio.run(main(int(sys.argv[1])))
