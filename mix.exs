defmodule OPCUA.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/tallakt/yaopcua"

  def project do
    [
      app: :yaopcua,
      version: @version,
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      elixirc_paths: if(Mix.env() == :test, do: ["lib", "test/support"], else: ["lib"]),
      aliases: ["opcua.schema": &schema/1],
      description:
        "OPC UA in pure Elixir: client, server, events and alarms, security " <>
          "policies, and PubSub over UDP, for talking to PLCs, SCADA and HMIs " <>
          "without C in the BEAM.",
      package: package(),
      source_url: @source_url,
      docs: docs()
    ]
  end

  # schema/ ships too: the modules that need it read it while compiling.
  defp package do
    [
      licenses: ["Apache-2.0"],
      links: %{"GitHub" => @source_url},
      files: ~w(lib schema mix.exs .formatter.exs README.md LICENSE NOTICE)
    ]
  end

  defp docs do
    [
      main: "readme",
      extras: ["README.md", "LICENSE", "NOTICE"],
      source_ref: "v#{@version}",
      # Hundreds of generated structures and enumerations, kept apart.
      groups_for_modules: [
        Client: [OPCUA.Client],
        Server: [OPCUA.Server, OPCUA.Server.Node],
        PubSub: [OPCUA.PubSub, ~r/^OPCUA\.PubSub\./],
        Security: [OPCUA.Certificate, OPCUA.SecurityPolicy, OPCUA.SecureChannel],
        "Built-in types": [
          OPCUA.NodeId,
          OPCUA.ExpandedNodeId,
          OPCUA.QualifiedName,
          OPCUA.LocalizedText,
          OPCUA.Variant,
          OPCUA.DataValue,
          OPCUA.DiagnosticInfo,
          OPCUA.ExtensionObject,
          OPCUA.StatusCode
        ],
        "Generated types": [OPCUA.Types, ~r/^OPCUA\.Types\./]
      ],
      nest_modules_by_prefix: [OPCUA.Types, OPCUA.PubSub]
    ]
  end

  def application do
    [
      # OTP's own crypto, for the security policies
      extra_applications: [:logger, :crypto, :public_key]
    ]
  end

  defp deps do
    [
      # Only for the fuzz and property tests.
      {:stream_data, "~> 1.1", only: :test},
      {:ex_doc, "~> 0.40", only: :dev, runtime: false}
    ]
  end

  # mix opcua.schema UA-1.05.07-2026-07-30
  #
  # Replaces schema/ with unmodified copies of the OPC Foundation's definition
  # files from one release tag of https://github.com/OPCFoundation/UA-Nodeset,
  # and writes the tag to schema/VERSION. This is an alias rather than a task in
  # lib/ so it runs without compiling, and so it doesn't ship to projects that
  # depend on yaopcua.
  @schema ~w(Opc.Ua.Types.bsd Opc.Ua.NodeSet2.xml NodeIds.csv StatusCode.csv AttributeIds.csv)

  defp schema([tag]) do
    {:ok, _} = Application.ensure_all_started([:inets, :ssl])

    ssl = [
      verify: :verify_peer,
      cacerts: :public_key.cacerts_get(),
      customize_hostname_check: [match_fun: :public_key.pkix_verify_hostname_match_fun(:https)]
    ]

    files =
      for file <- @schema do
        url = ~c"https://raw.githubusercontent.com/OPCFoundation/UA-Nodeset/#{tag}/Schema/#{file}"

        case :httpc.request(:get, {url, []}, [ssl: ssl], body_format: :binary) do
          {:ok, {{_, 200, _}, _, body}} -> {file, body}
          {:ok, {{_, status, _}, _, _}} -> Mix.raise("#{file} of #{tag}: HTTP #{status}")
          {:error, reason} -> Mix.raise("#{file} of #{tag}: #{inspect(reason)}")
        end
      end

    File.mkdir_p!("schema")
    for {file, body} <- files, do: File.write!(Path.join("schema", file), body)
    File.write!("schema/VERSION", tag <> "\n")
    Mix.shell().info("schema/ now holds #{tag}")
  end

  defp schema(_), do: Mix.raise("usage: mix opcua.schema UA-1.05.07-2026-07-30")
end
