defmodule OPCUA.SecurityPolicy do
  @moduledoc """
  The security policies (Part 7): which algorithms sign and encrypt a secure
  channel, and the primitives that apply them, all from OTP's `:crypto` and
  `:public_key`.

  | Policy | Name here |
  |---|---|
  | None | `:none` |
  | Basic256Sha256 | `:basic256sha256` |
  | Aes128_Sha256_RsaOaep | `:aes128_sha256_rsa_oaep` |
  | Aes256_Sha256_RsaPss | `:aes256_sha256_rsa_pss` |

  All three secure ones sign with HMAC-SHA256 and derive their keys with
  P_SHA256. They differ in the AES key length and in how RSA signs and
  encrypts. The deprecated Basic128Rsa15 and Basic256 are left out.
  """

  @base "http://opcfoundation.org/UA/SecurityPolicy#"
  @rsa_sha256 "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
  @rsa_oaep "http://www.w3.org/2001/04/xmlenc#rsa-oaep"

  @policies %{
    none: %{uri: @base <> "None"},
    basic256sha256: %{
      uri: @base <> "Basic256Sha256",
      signature: :pkcs1,
      oaep: :sha,
      cipher: :aes_256_cbc,
      encryption_key: 32,
      signature_uri: @rsa_sha256,
      encryption_uri: @rsa_oaep
    },
    aes128_sha256_rsa_oaep: %{
      uri: @base <> "Aes128_Sha256_RsaOaep",
      signature: :pkcs1,
      oaep: :sha,
      cipher: :aes_128_cbc,
      encryption_key: 16,
      signature_uri: @rsa_sha256,
      encryption_uri: @rsa_oaep
    },
    aes256_sha256_rsa_pss: %{
      uri: @base <> "Aes256_Sha256_RsaPss",
      signature: :pss,
      oaep: :sha256,
      cipher: :aes_256_cbc,
      encryption_key: 32,
      signature_uri: "http://opcfoundation.org/UA/security/rsa-pss-sha2-256",
      encryption_uri: "http://opcfoundation.org/UA/security/rsa-oaep-sha2-256"
    }
  }

  # Every secure policy here: HMAC-SHA256 keys and signatures of 32 bytes,
  # AES blocks and IVs of 16, and nonces of 32.
  @signature_key 32
  @signature 32
  @block 16
  @nonce 32

  @type t :: :none | :basic256sha256 | :aes128_sha256_rsa_oaep | :aes256_sha256_rsa_pss
  @type mode :: :none | :sign | :sign_and_encrypt

  @doc "All the policies, from the weakest."
  def all, do: [:none, :aes128_sha256_rsa_oaep, :basic256sha256, :aes256_sha256_rsa_pss]

  @doc "The URI of a policy."
  @spec uri(t) :: String.t()
  def uri(policy), do: Map.fetch!(@policies, policy).uri

  @doc "The policy with this URI, or nil."
  @spec from_uri(String.t() | nil) :: t | nil
  def from_uri(uri),
    do:
      Enum.find_value(@policies, fn
        {name, %{uri: ^uri}} -> name
        _ -> nil
      end)

  @doc false
  def nonce_length(:none), do: 0
  def nonce_length(_), do: @nonce

  @doc false
  # How strong an endpoint is, for its SecurityLevel.
  def level(:none, _), do: 0

  def level(policy, mode),
    do:
      Enum.find_index(all(), &(&1 == policy)) * 10 + if(mode == :sign_and_encrypt, do: 5, else: 0)

  ## Asymmetric: RSA, for opening a channel and signing sessions

  @doc false
  def signature_uri(policy), do: Map.fetch!(@policies, policy).signature_uri

  @doc false
  def encryption_uri(policy), do: Map.fetch!(@policies, policy).encryption_uri

  @doc false
  def sign(policy, data, private_key) do
    :public_key.sign(data, :sha256, private_key, pss(policy))
  end

  @doc false
  def verify(policy, data, signature, public_key) do
    :public_key.verify(data, :sha256, signature, public_key, pss(policy))
  end

  defp pss(policy) do
    case Map.fetch!(@policies, policy).signature do
      :pss -> [rsa_padding: :rsa_pkcs1_pss_padding, rsa_pss_saltlen: 32]
      :pkcs1 -> []
    end
  end

  @doc false
  # The size of an RSA key in bytes: of a signature, and of an encrypted block.
  def key_size({:RSAPublicKey, n, _}), do: byte_size(:binary.encode_unsigned(n))

  def key_size(private_key) when elem(private_key, 0) == :RSAPrivateKey,
    do: key_size(public_key(private_key))

  @doc false
  def public_key({:RSAPrivateKey, _, n, e, _, _, _, _, _, _, _}), do: {:RSAPublicKey, n, e}

  @doc false
  # How much plain text fits in one encrypted block: OAEP takes 2 hashes and 2 bytes.
  def plain_block(policy, public_key) do
    hash = if Map.fetch!(@policies, policy).oaep == :sha256, do: 32, else: 20
    key_size(public_key) - 2 * hash - 2
  end

  @doc false
  # Encrypts block by block, for the receiver's public key. The last block
  # may be short.
  def encrypt(policy, data, public_key) do
    options = oaep(policy)

    data
    |> blocks(plain_block(policy, public_key))
    |> Enum.map(&rsa(:encrypt_public, [&1, public_key, options]))
    |> IO.iodata_to_binary()
  end

  defp blocks(<<>>, _), do: []
  defp blocks(data, size) when byte_size(data) <= size, do: [data]

  defp blocks(data, size),
    do: [
      binary_part(data, 0, size) | blocks(binary_part(data, size, byte_size(data) - size), size)
    ]

  @doc false
  def decrypt(policy, data, private_key) do
    block = key_size(private_key)
    options = oaep(policy)

    if rem(byte_size(data), block) == 0 do
      {:ok,
       for(<<chunk::binary-size(block) <- data>>,
         into: <<>>,
         do: rsa(:decrypt_private, [chunk, private_key, options])
       )}
    else
      {:error, :bad_security_checks_failed}
    end
  rescue
    _ -> {:error, :bad_security_checks_failed}
  end

  # OTP 27 deprecates RSA encryption in :public_key and :crypto, "do not
  # use", because of attacks on PKCS#1 v1.5 padding (Marvin). OPC UA only
  # uses OAEP here, which those attacks don't touch, and OpenSSL's OAEP is
  # sounder than one written by hand. The call is made dynamically so the
  # deprecation doesn't fail the build; if OTP removes these, OAEP goes on
  # top of :crypto.mod_pow.
  defp rsa(function, args), do: apply(:public_key, function, args)

  defp oaep(policy) do
    case Map.fetch!(@policies, policy).oaep do
      :sha256 -> [rsa_padding: :rsa_pkcs1_oaep_padding, rsa_oaep_md: :sha256]
      :sha -> [rsa_padding: :rsa_pkcs1_oaep_padding]
    end
  end

  @doc false
  # Encrypts a secret, such as a password, for the server: the length, the
  # secret and the server's nonce, as UserNameIdentityToken wants it.
  def encrypt_secret(policy, secret, nonce, public_key) do
    encrypt(
      policy,
      <<byte_size(secret) + byte_size(nonce)::little-32, secret::binary, nonce::binary>>,
      public_key
    )
  end

  @doc false
  def decrypt_secret(policy, data, nonce, private_key) do
    with {:ok, plain} <- decrypt(policy, data, private_key),
         <<length::little-32, rest::binary>> when length <= byte_size(rest) <- plain,
         secret_length = length - byte_size(nonce),
         true <- secret_length >= 0,
         <<secret::binary-size(secret_length), ^nonce::binary-size(byte_size(nonce)), _::binary>> <-
           rest do
      {:ok, secret}
    else
      _ -> {:error, :bad_identity_token_invalid}
    end
  end

  ## Symmetric: AES and HMAC with keys from the nonces, for every message

  @doc false
  # The keys for one direction of a channel (Part 6, 6.7.5): the client's
  # come from P_SHA256(server nonce, client nonce), the server's from
  # P_SHA256(client nonce, server nonce).
  def derive(policy, secret, seed) do
    %{encryption_key: key} = Map.fetch!(@policies, policy)

    <<signing::binary-size(@signature_key), encrypting::binary-size(key),
      iv::binary-size(@block)>> = p_sha256(secret, seed, @signature_key + key + @block)

    %{signing: signing, encrypting: encrypting, iv: iv}
  end

  @doc false
  # The TLS pseudo-random function P_SHA256 (RFC 5246, section 5).
  def p_sha256(secret, seed, length), do: p_sha256(secret, seed, seed, length, <<>>)

  defp p_sha256(_, _, _, length, acc) when byte_size(acc) >= length,
    do: binary_part(acc, 0, length)

  defp p_sha256(secret, seed, a, length, acc) do
    a = :crypto.mac(:hmac, :sha256, secret, a)
    p_sha256(secret, seed, a, length, acc <> :crypto.mac(:hmac, :sha256, secret, a <> seed))
  end

  @doc false
  def symmetric_signature_size, do: @signature

  @doc false
  def block_size, do: @block

  @doc false
  def mac(keys, data), do: :crypto.mac(:hmac, :sha256, keys.signing, data)

  @doc false
  def encrypt_symmetric(policy, keys, data),
    do: :crypto.crypto_one_time(cipher(policy), keys.encrypting, keys.iv, data, encrypt: true)

  @doc false
  def decrypt_symmetric(policy, keys, data) do
    if rem(byte_size(data), @block) == 0,
      do:
        {:ok,
         :crypto.crypto_one_time(cipher(policy), keys.encrypting, keys.iv, data, encrypt: false)},
      else: {:error, :bad_security_checks_failed}
  end

  defp cipher(policy), do: Map.fetch!(@policies, policy).cipher
end
