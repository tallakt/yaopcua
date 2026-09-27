# The interop tests run against an asyncua server in a separate process, and
# need ASYNCUA_PYTHON to point to a Python with asyncua installed:
#
#     python3 -m venv ~/.venvs/asyncua && ~/.venvs/asyncua/bin/pip install asyncua
#     ASYNCUA_PYTHON=~/.venvs/asyncua/bin/python mix test
exclude = if System.get_env("ASYNCUA_PYTHON"), do: [], else: [:interop]
ExUnit.start(exclude: exclude)
