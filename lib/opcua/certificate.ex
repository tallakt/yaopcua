defmodule OPCUA.Certificate do
  @moduledoc """
  X.509 application instance certificates (Part 6, 6.2), as DER binaries.

  OPC UA identifies clients and servers by certificate. Each has one, whose
  subject alternative name carries the application URI, and each decides
  which certificates of the other side to trust.

      {cert, key} = OPCUA.Certificate.self_signed("urn:plant:server")
      :ok = OPCUA.Certificate.write("server.der", cert)
      :ok = OPCUA.Certificate.write_key("server.pem", key)

  Not supported: certificate chains (each side sends one certificate),
  revocation lists, and certificate signing requests. Trust is a list of
  certificates, or of the CAs that signed them.

  A self-signed certificate should be made once and kept: a new one on every
  start means every peer has to trust it again.
  """

  require Record

  @hrl "public_key/include/public_key.hrl"
  Record.defrecordp(
    :otp_certificate,
    :OTPCertificate,
    Record.extract(:OTPCertificate, from_lib: @hrl)
  )

  Record.defrecordp(
    :tbs_certificate,
    :OTPTBSCertificate,
    Record.extract(:OTPTBSCertificate, from_lib: @hrl)
  )

  Record.defrecordp(
    :key_info,
    :OTPSubjectPublicKeyInfo,
    Record.extract(:OTPSubjectPublicKeyInfo, from_lib: @hrl)
  )

  Record.defrecordp(:validity, :Validity, Record.extract(:Validity, from_lib: @hrl))
  Record.defrecordp(:extension, :Extension, Record.extract(:Extension, from_lib: @hrl))

  @sha256_rsa {1, 2, 840, 113_549, 1, 1, 11}
  @rsa {1, 2, 840, 113_549, 1, 1, 1}
  @common_name {2, 5, 4, 3}
  @organization {2, 5, 4, 10}
  @subject_alt_name {2, 5, 29, 17}
  @key_usage {2, 5, 29, 15}
  @ext_key_usage {2, 5, 29, 37}
  @basic_constraints {2, 5, 29, 19}
  @subject_key_id {2, 5, 29, 14}
  @authority_key_id {2, 5, 29, 35}
  @server_auth {1, 3, 6, 1, 5, 5, 7, 3, 1}
  @client_auth {1, 3, 6, 1, 5, 5, 7, 3, 2}

  @type t :: binary
  @type private_key :: tuple

  @doc """
  Makes a self-signed certificate for an application, and its private key.

  ## Options

    * `:name` - the common name (default `"yaopcua"`)
    * `:hostnames` - DNS names and IP addresses the application is reached
      at (default the host's name)
    * `:days` - how long it's valid (default 3650)
    * `:key_size` - RSA key bits (default 2048)
  """
  @spec self_signed(String.t(), keyword) :: {t, private_key}
  def self_signed(application_uri, opts \\ []) do
    key = :public_key.generate_key({:rsa, Keyword.get(opts, :key_size, 2048), 65_537})
    public = OPCUA.SecurityPolicy.public_key(key)
    {:ok, host} = :inet.gethostname()
    name = Keyword.get(opts, :name, "yaopcua")
    now = DateTime.utc_now()
    key_id = :crypto.hash(:sha, :public_key.der_encode(:RSAPublicKey, public))

    subject =
      {:rdnSequence,
       [
         [{:AttributeTypeAndValue, @common_name, {:utf8String, name}}],
         [{:AttributeTypeAndValue, @organization, {:utf8String, name}}]
       ]}

    alt_names =
      [{:uniformResourceIdentifier, String.to_charlist(application_uri)}] ++
        for host <- Keyword.get(opts, :hostnames, [List.to_string(host)]) do
          case :inet.parse_address(String.to_charlist(host)) do
            {:ok, ip} -> {:iPAddress, ip |> Tuple.to_list() |> :binary.list_to_bin()}
            {:error, _} -> {:dNSName, String.to_charlist(host)}
          end
        end

    tbs =
      tbs_certificate(
        version: :v3,
        serialNumber: :binary.decode_unsigned(:crypto.strong_rand_bytes(16)),
        signature: {:SignatureAlgorithm, @sha256_rsa, :NULL},
        issuer: subject,
        validity:
          validity(
            notBefore: time(DateTime.add(now, -1, :day)),
            notAfter: time(DateTime.add(now, Keyword.get(opts, :days, 3650), :day))
          ),
        subject: subject,
        subjectPublicKeyInfo:
          key_info(
            algorithm: {:PublicKeyAlgorithm, @rsa, :NULL},
            subjectPublicKey: public
          ),
        extensions: [
          extension(extnID: @subject_alt_name, critical: false, extnValue: alt_names),
          extension(
            extnID: @basic_constraints,
            critical: true,
            extnValue: {:BasicConstraints, false, :asn1_NOVALUE}
          ),
          extension(
            extnID: @key_usage,
            critical: true,
            extnValue: [
              :digitalSignature,
              :nonRepudiation,
              :keyEncipherment,
              :dataEncipherment,
              :keyCertSign
            ]
          ),
          extension(
            extnID: @ext_key_usage,
            critical: false,
            extnValue: [@server_auth, @client_auth]
          ),
          extension(extnID: @subject_key_id, critical: false, extnValue: key_id),
          extension(
            extnID: @authority_key_id,
            critical: false,
            extnValue: {:AuthorityKeyIdentifier, key_id, :asn1_NOVALUE, :asn1_NOVALUE}
          )
        ]
      )

    {:public_key.pkix_sign(tbs, key), key}
  end

  # UTCTime until 2049, GeneralizedTime after (RFC 5280, 4.1.2.5).
  defp time(%DateTime{year: year} = t) when year < 2050,
    do: {:utcTime, Calendar.strftime(t, "%y%m%d%H%M%SZ") |> String.to_charlist()}

  defp time(t), do: {:generalTime, Calendar.strftime(t, "%Y%m%d%H%M%SZ") |> String.to_charlist()}

  @doc "The certificate's RSA public key."
  @spec public_key(t) :: tuple
  def public_key(der) do
    tbs_certificate(subjectPublicKeyInfo: info) = tbs(der)
    key_info(info, :subjectPublicKey)
  end

  @doc "The size of the certificate's RSA key in bits, or nil for one that can't be read."
  @spec key_bits(t) :: pos_integer | nil
  def key_bits(der) do
    {:RSAPublicKey, n, _} = public_key(der)
    bit_size(:binary.encode_unsigned(n))
  rescue
    _ -> nil
  end

  @doc "The application URI in the certificate's subject alternative name, or nil."
  @spec application_uri(t) :: String.t() | nil
  def application_uri(der) do
    Enum.find_value(extensions(der), fn
      extension(extnID: @subject_alt_name, extnValue: names) ->
        Enum.find_value(names, fn
          {:uniformResourceIdentifier, uri} -> List.to_string(uri)
          _ -> nil
        end)

      _ ->
        nil
    end)
  end

  @doc "The SHA-1 of the certificate, by which OPC UA refers to it."
  @spec thumbprint(t) :: binary
  def thumbprint(der), do: :crypto.hash(:sha, der)

  @doc "Whether the certificate is valid now."
  @spec current?(t) :: boolean
  def current?(der) do
    tbs_certificate(validity: validity(notBefore: from, notAfter: to)) = tbs(der)
    now = DateTime.utc_now()

    DateTime.compare(parse_time(from), now) != :gt and
      DateTime.compare(parse_time(to), now) != :lt
  end

  defp parse_time({:utcTime, chars}) do
    <<yy::binary-2, rest::binary>> = List.to_string(chars)
    year = String.to_integer(yy)

    parse_time(
      {:generalTime,
       String.to_charlist("#{if year >= 50, do: 1900 + year, else: 2000 + year}" <> rest)}
    )
  end

  defp parse_time({:generalTime, chars}) do
    <<y::binary-4, mo::binary-2, d::binary-2, h::binary-2, mi::binary-2, s::binary-2, _::binary>> =
      List.to_string(chars)

    {:ok, time, 0} = DateTime.from_iso8601("#{y}-#{mo}-#{d}T#{h}:#{mi}:#{s}Z")
    time
  end

  @doc """
  Whether to trust a peer's certificate. `trust` is `:any`, or a list of
  certificates: the peer's own, or one of a CA that signed it. Either way it
  must be valid now.
  """
  @spec trusted?(t, :any | [t]) :: boolean
  def trusted?(der, trust) do
    current?(der) and
      case trust do
        :any -> true
        list when is_list(list) -> der in list or Enum.any?(list, &signed_by?(der, &1))
      end
  rescue
    # A peer's certificate is whatever it sent, and :public_key raises on
    # what it can't parse.
    _ -> false
  end

  defp signed_by?(der, ca) do
    match?({:ok, _}, :public_key.pkix_path_validation(ca, [der], []))
  end

  @doc "Reads a certificate from a DER or PEM file."
  @spec read(Path.t()) :: t
  def read(path) do
    data = File.read!(path)

    case :public_key.pem_decode(data) do
      [{:Certificate, der, _} | _] -> der
      _ -> data
    end
  end

  @doc "Reads an RSA private key from a PEM file."
  @spec read_key(Path.t()) :: private_key
  def read_key(path) do
    [entry | _] = path |> File.read!() |> :public_key.pem_decode()
    :public_key.pem_entry_decode(entry)
  end

  @doc "Writes a certificate as DER, or PEM if the path ends in `.pem`."
  @spec write(Path.t(), t) :: :ok | {:error, File.posix()}
  def write(path, der) do
    data =
      if Path.extname(path) == ".pem",
        do: :public_key.pem_encode([{:Certificate, der, :not_encrypted}]),
        else: der

    File.write(path, data)
  end

  @doc "Writes a private key as PEM."
  @spec write_key(Path.t(), private_key) :: :ok | {:error, File.posix()}
  def write_key(path, key),
    do:
      File.write(
        path,
        :public_key.pem_encode([:public_key.pem_entry_encode(:RSAPrivateKey, key)])
      )

  defp tbs(der) do
    otp_certificate(tbsCertificate: tbs) = :public_key.pkix_decode_cert(der, :otp)
    tbs
  end

  defp extensions(der) do
    case tbs_certificate(tbs(der), :extensions) do
      list when is_list(list) -> list
      _ -> []
    end
  end
end
