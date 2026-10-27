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
  def secure?, do: encryption() != nil

  # Whether the library has the PubSub AES-CTR policies, for the secured
  # PubSub tests: in open62541 1.5 only with PubSub and the mbedTLS plugin.
  def pubsub_secure?, do: encryption() == :mbedtls and config() =~ "#define UA_ENABLE_PUBSUB\n"

  # The encryption the library is built with, :openssl or :mbedtls, or nil.
  defp encryption do
    case Regex.run(~r/#define UA_ENABLE_ENCRYPTION_(OPENSSL|MBEDTLS)/, config()) do
      [_, "OPENSSL"] -> :openssl
      [_, "MBEDTLS"] -> :mbedtls
      nil -> nil
    end
  end

  # The library's config.h, or "" without it.
  defp config do
    with flags when flags != nil <- flags(),
         path when path != nil <-
           for("-I" <> dir <- flags, do: dir)
           |> Enum.concat(["/usr/include"])
           |> Enum.map(&Path.join(&1, "open62541/config.h"))
           |> Enum.find(&File.exists?/1) do
      File.read!(path)
    else
      _ -> ""
    end
  end

  # What a static library with mbedTLS needs to link, which a shared one has
  # already.
  defp link_flags, do: if(encryption() == :mbedtls, do: mbedtls_flags() ++ ["-lm"], else: [])

  # Builds the peer into the build directory, returning its path.
  def build! do
    peer = Path.join(Mix.Project.build_path(), "open62541_peer")
    source = Path.expand("open62541_peer.c", __DIR__)

    {output, status} =
      System.cmd("cc", ["-o", peer, source] ++ flags() ++ link_flags(), stderr_to_stdout: true)

    if status != 0, do: raise("can't build the open62541 peer: #{output}")
    peer
  end

  # Builds the secured PubSub peer, open62541_pubsub_peer.c, returning its
  # path, for a library that's `pubsub_secure?/0`. A static library needs
  # mbedTLS to link, found under MBEDTLS_PREFIX or the usual prefixes.
  def build_pubsub_peer! do
    peer = Path.join(Mix.Project.build_path(), "open62541_pubsub_peer")
    source = Path.expand("open62541_pubsub_peer.c", __DIR__)

    {output, status} =
      System.cmd("cc", ["-o", peer, source] ++ flags() ++ link_flags(), stderr_to_stdout: true)

    if status != 0, do: raise("can't build the open62541 PubSub peer: #{output}")
    peer
  end

  defp mbedtls_flags do
    prefix =
      System.get_env("MBEDTLS_PREFIX") ||
        Enum.find(
          ["/opt/homebrew/opt/mbedtls", "/usr/local/opt/mbedtls", "/usr"],
          &File.dir?(Path.join(&1, "include/mbedtls"))
        )

    libs = ["-lmbedtls", "-lmbedx509", "-lmbedcrypto"]

    if prefix,
      do: ["-I#{Path.join(prefix, "include")}", "-L#{Path.join(prefix, "lib")}" | libs],
      else: libs
  end
end
