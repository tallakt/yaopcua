# The interop tests run against an asyncua server in a separate process, and
# need ASYNCUA_PYTHON to point to a Python with asyncua installed:
#
#     python3 -m venv ~/.venvs/asyncua && ~/.venvs/asyncua/bin/pip install asyncua
#     ASYNCUA_PYTHON=~/.venvs/asyncua/bin/python mix test
#
# The open62541 tests build a peer against open62541's library, and run where
# it is found (see test/support/open62541.ex): `brew install open62541`, or
# OPEN62541_PREFIX for one built elsewhere. The secure ones need it built with
# encryption (-DUA_ENABLE_ENCRYPTION=OPENSSL), which Homebrew's isn't. The
# secured PubSub ones need the PubSub AES-CTR policies, which open62541 1.5 has
# only with -DUA_ENABLE_ENCRYPTION=MBEDTLS (and -DUA_ENABLE_PUBSUB=ON); build it
# static (-DBUILD_SHARED_LIBS=OFF) if it needs to be found with OPEN62541_PREFIX.
#
# The Prosys tests run against a Prosys OPC UA Simulation Server, which
# someone starts by hand, so only when asked: `mix test --only prosys` (see
# test/opcua/prosys_test.exs).
exclude = [:prosys]
exclude = if System.get_env("ASYNCUA_PYTHON"), do: exclude, else: [:interop | exclude]
exclude = if OPCUA.Open62541.flags(), do: exclude, else: [:open62541 | exclude]
exclude = if OPCUA.Open62541.secure?(), do: exclude, else: [:open62541_secure | exclude]

exclude =
  if OPCUA.Open62541.pubsub_secure?(),
    do: exclude,
    else: [:open62541_pubsub_secure | exclude]

ExUnit.start(exclude: exclude)
