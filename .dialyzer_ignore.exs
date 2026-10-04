# The OPC Foundation's schema files are read with xmerl while compiling, never at runtime, so xmerl
# isn't among the application's dependencies, and isn't in the PLT.
[
  {"lib/opcua/schema.ex", :unknown_function},
  {"lib/opcua/server/node_set.ex", :unknown_function}
]
