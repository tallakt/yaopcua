# Test vectors from asyncua (https://github.com/FreeOpcUa/opcua-asyncio), an
# OPC UA stack written independently of this one: random instances of every
# structure it knows, encoded by asyncua. types_test.exs checks that yaopcua
# decodes each one and encodes it back to the same bytes.
#
# asyncua runs only here, as a separate tool; nothing of it is in the library.
# To regenerate:
#
#     python3 -m venv /tmp/venv && /tmp/venv/bin/pip install asyncua==2.0.1
#     /tmp/venv/bin/python test/vectors/generate_asyncua.py 1 2 3 > test/vectors/asyncua.txt
#
# Each line is "<name> <1 if the encoding starts with its type id> <hex>".
import dataclasses, datetime, enum, random, struct, sys, typing, uuid
from asyncua import ua
from asyncua.ua import uaprotocol_auto as auto, uatypes as t
from asyncua.ua.ua_binary import struct_to_binary

R = random.Random()
NS = dict(vars(auto)); NS["ua"] = ua
INTS = {t.SByte: 8, t.Byte: 8, t.Int16: 16, t.UInt16: 16, t.Int32: 32, t.UInt32: 32, t.Int64: 64, t.UInt64: 64}
SIGNED = {t.SByte, t.Int16, t.Int32, t.Int64}

def integer(cls):
    bits = INTS[cls]
    n = R.choice([0, 1, R.getrandbits(bits), (1 << bits) - 1])
    return n - (1 << (bits - 1)) if cls in SIGNED else n

def f32():
    return struct.unpack("<f", struct.pack("<f", R.uniform(-1e6, 1e6)))[0]

def string():
    return R.choice([None, "", "Pump1.Speed", "æøå 水 é"])

def date():
    return (datetime.datetime(R.randrange(1990, 2040), R.randrange(1, 13), R.randrange(1, 28),
                     R.randrange(24), R.randrange(60), R.randrange(60), R.randrange(1000000), tzinfo=datetime.timezone.utc))

def nodeid(expanded=False):
    k = R.randrange(6)
    ns = R.choice([0, 1, 2, 300])
    cls = ua.ExpandedNodeId if expanded else ua.NodeId
    T = ua.NodeIdType
    if k == 0: return cls(R.randrange(256), 0, T.TwoByte)
    if k == 1: return cls(R.randrange(256, 65536), R.choice([1, 2]), T.FourByte)
    if k == 2: return cls(R.randrange(65536, 2**32), ns, T.Numeric)
    if k == 3: return cls("s" + str(R.randrange(1000)), ns, T.String)
    if k == 4: return cls(uuid.UUID(int=R.getrandbits(128)), ns, T.Guid)
    return cls(bytes(R.randrange(256) for _ in range(R.randrange(1, 5))), ns, T.ByteString)

SCALARS = [
    (ua.VariantType.Boolean, lambda: R.choice([True, False])),
    (ua.VariantType.Int16, lambda: integer(t.Int16)),
    (ua.VariantType.UInt32, lambda: integer(t.UInt32)),
    (ua.VariantType.Int64, lambda: integer(t.Int64)),
    (ua.VariantType.Double, lambda: R.uniform(-1e9, 1e9)),
    (ua.VariantType.Float, f32),
    (ua.VariantType.String, lambda: R.choice(["", "x", "Tank 3 level"])),
    (ua.VariantType.DateTime, lambda: date() or datetime.datetime(2026, 9, 27, tzinfo=datetime.timezone.utc)),
    (ua.VariantType.NodeId, nodeid),
    (ua.VariantType.LocalizedText, lambda: ua.LocalizedText("Speed", R.choice([None, "en-US"]))),
    (ua.VariantType.QualifiedName, lambda: ua.QualifiedName("Speed", R.randrange(3))),
    (ua.VariantType.ByteString, lambda: bytes(R.randrange(256) for _ in range(3))),
]

def variant():
    if R.random() < 0.15: return ua.Variant()
    vt, gen = R.choice(SCALARS)
    if R.random() < 0.3: return ua.Variant([gen() for _ in range(R.randrange(3))], vt)
    return ua.Variant(gen(), vt)

def value(tp, depth):
    origin = typing.get_origin(tp)
    if origin in (list, typing.List):
        (inner,) = typing.get_args(tp)
        return [value(inner, depth + 1) for _ in range(R.randrange(3) if depth < 4 else 0)]
    if origin is typing.Union:
        return value([a for a in typing.get_args(tp) if a is not type(None)][0], depth)
    if tp in INTS: return integer(tp)
    if tp is t.Boolean or tp is bool: return R.choice([True, False])
    if tp is t.Float: return f32()
    if tp is t.Double: return R.uniform(-1e9, 1e9)
    if tp is t.String: return string()
    if tp is t.DateTime: return date()
    if tp is t.Guid: return uuid.UUID(int=R.getrandbits(128))
    if tp is t.ByteString: return R.choice([None, b"", bytes(R.randrange(256) for _ in range(4))])
    if tp is t.NodeId: return nodeid()
    if tp is t.ExpandedNodeId: return nodeid(expanded=True)
    if tp is t.StatusCode: return ua.StatusCode(R.choice([0, 0x80340000, 0x40000000]))
    if tp is t.QualifiedName: return ua.QualifiedName(string(), R.randrange(3))
    if tp is t.LocalizedText: return ua.LocalizedText(string(), R.choice([None, "en-US"]))
    if tp is t.Variant: return variant()
    if tp is t.DataValue: return ua.DataValue(variant(), SourceTimestamp=date(), ServerTimestamp=date())
    if tp is t.DiagnosticInfo: return ua.DiagnosticInfo()
    if tp is t.ExtensionObject:
        return R.choice([None, ua.AnonymousIdentityToken(PolicyId=string()), ua.Range(Low=1.5, High=R.uniform(0, 100))])
    if isinstance(tp, type) and issubclass(tp, enum.Enum): return R.choice(list(tp))
    if dataclasses.is_dataclass(tp): return instance(tp, depth + 1)
    raise TypeError(f"no generator for {tp}")

def instance(cls, depth=0):
    hints = typing.get_type_hints(cls, globalns=NS)
    # Every field is set here: asyncua's own defaults include the current time and random GUIDs.
    kwargs = {f.name: value(hints[f.name], depth) for f in dataclasses.fields(cls) if f.init and f.name != "TypeId"}
    return cls(**kwargs)

# asyncua decodes the Encoding field of this one as a Byte; the spec says String.
BROKEN = {"SessionSecurityDiagnosticsDataType"}

for seed in sys.argv[1:]:
  R.seed(int(seed))
  for name in sorted(dir(auto)):
      cls = getattr(auto, name)
      if not (isinstance(cls, type) and dataclasses.is_dataclass(cls)) or name in BROKEN: continue
      try:
          obj = instance(cls)
          data = struct_to_binary(obj)
      except Exception as e:
          print(f"# {name}: {type(e).__name__} {e}", file=sys.stderr)
          continue
      prefixed = "TypeId" in {f.name for f in dataclasses.fields(cls)}
      print(name, int(prefixed), data.hex())
