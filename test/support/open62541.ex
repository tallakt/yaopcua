defmodule OPCUA.Open62541 do
  @moduledoc false
  # Finds open62541's library for the interop tests' peer, open62541_peer.c:
  # through OPEN62541_PREFIX, pkg-config, or the usual prefixes, Homebrew's
  # among them. `flags/0` gives the compiler's flags, or nil without it.

  @prefixes ["/opt/homebrew", "/usr/local", "/usr"]

  def flags do
    case System.get_env("OPEN62541_PREFIX") do
      nil -> pkg_config() || Enum.find_value(@prefixes, &prefix/1)
      dir -> prefix(dir)
    end
  end

  defp pkg_config do
    with path when path != nil <- System.find_executable("pkg-config"),
         {flags, 0} <-
           System.cmd(path, ["--cflags", "--libs", "open62541"], stderr_to_stdout: true) do
      String.split(flags)
    else
      _ -> nil
    end
  end

  defp prefix(dir) do
    if File.exists?(Path.join(dir, "include/open62541/server.h")) do
      lib = Path.join(dir, "lib")
      ["-I#{Path.join(dir, "include")}", "-L#{lib}", "-Wl,-rpath,#{lib}", "-lopen62541"]
    end
  end

  # Whether the library is built with encryption, for the secure tests.
  # Homebrew's isn't.
  def secure? do
    case flags() do
      nil ->
        false

      flags ->
        for("-I" <> dir <- flags, do: dir)
        |> Enum.concat(["/usr/include"])
        |> Enum.map(&Path.join(&1, "open62541/config.h"))
        |> Enum.find(&File.exists?/1)
        |> case do
          nil -> false
          config -> File.read!(config) =~ ~r/#define UA_ENABLE_ENCRYPTION_(OPENSSL|MBEDTLS)/
        end
    end
  end

  # Builds the peer into the build directory, returning its path.
  def build! do
    peer = Path.join(Mix.Project.build_path(), "open62541_peer")
    source = Path.expand("open62541_peer.c", __DIR__)
    {output, status} = System.cmd("cc", ["-o", peer, source | flags()], stderr_to_stdout: true)
    if status != 0, do: raise("can't build the open62541 peer: #{output}")
    peer
  end
end
