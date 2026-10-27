defmodule OPCUA.PubSub.Security do
  @moduledoc """
  Message security for PubSub (Part 14, 5.4 and 7.2.2.2.4): the security
  policies PubSub-Aes128-CTR and PubSub-Aes256-CTR, which sign a network
  message with HMAC-SHA256 and, in `:sign_and_encrypt` mode, encrypt its
  payload with AES in counter mode.

  | Policy | Name here | Key material |
  |---|---|---|
  | PubSub-Aes128-CTR | `:aes128_ctr` | 32 B signing key, 16 B encrypting key, 4 B nonce |
  | PubSub-Aes256-CTR | `:aes256_ctr` | 32 B signing key, 32 B encrypting key, 4 B nonce |

  The keys of one token are one byte string, the three parts in that order,
  as the Security Key Service hands them out. Publishers and subscribers of
  a security group share them; see `OPCUA.PubSub.SKS`.
  """

  alias OPCUA.PubSub.KeyStore

  @base "http://opcfoundation.org/UA/SecurityPolicy#"

  @policies %{
    aes128_ctr: %{uri: @base <> "PubSub-Aes128-CTR", cipher: :aes_128_ctr, encryption_key: 16},
    aes256_ctr: %{uri: @base <> "PubSub-Aes256-CTR", cipher: :aes_256_ctr, encryption_key: 32}
  }

  @signing_key 32
  @key_nonce 4
  @message_nonce 8
  @signature 32

  @type policy :: :aes128_ctr | :aes256_ctr
  @type mode :: :sign | :sign_and_encrypt
  @type keys :: %{policy: policy, signing: binary, encrypting: binary, nonce: binary}

  @doc """
  Checks the `security:` options of a publisher or subscriber and fills in
  the defaults (`:sign_and_encrypt`, `:aes128_ctr`). Raises ArgumentError
  for options that couldn't work, such as keys of the wrong length, or a
  Security Key Service reached over a session that isn't encrypted.
  """
  @spec check!(keyword) :: keyword
  def check!(security) when is_list(security), do: KeyStore.check!(security)

  def check!(other),
    do: raise(ArgumentError, "security: takes a keyword list, got #{inspect(other)}")

  @doc "The policies."
  def all, do: Map.keys(@policies)

  @doc "The URI of a policy."
  @spec uri(policy) :: String.t()
  def uri(policy), do: Map.fetch!(@policies, policy).uri

  @doc "The policy with this URI, or nil."
  @spec from_uri(String.t() | nil) :: policy | nil
  def from_uri(uri),
    do: Enum.find_value(@policies, fn {name, %{uri: u}} -> if u == uri, do: name end)

  @doc "Bytes of key material for one token."
  @spec key_length(policy) :: pos_integer
  def key_length(policy),
    do: @signing_key + Map.fetch!(@policies, policy).encryption_key + @key_nonce

  @doc "Bytes of the signature at the end of a signed message."
  def signature_size, do: @signature

  @doc "Bytes of a message nonce."
  def nonce_size, do: @message_nonce

  @doc "New random key material for a token."
  @spec generate(policy) :: binary
  def generate(policy), do: :crypto.strong_rand_bytes(key_length(policy))

  @doc "Splits the key material of a token into its three keys."
  @spec split(policy, binary) :: {:ok, keys} | :error
  def split(policy, bytes) when is_binary(bytes) do
    encrypting = Map.fetch!(@policies, policy).encryption_key

    if byte_size(bytes) == key_length(policy) do
      {:ok,
       %{
         policy: policy,
         signing: binary_part(bytes, 0, @signing_key),
         encrypting: binary_part(bytes, @signing_key, encrypting),
         nonce: binary_part(bytes, @signing_key + encrypting, @key_nonce)
       }}
    else
      :error
    end
  end

  def split(_, _), do: :error

  @doc """
  A message nonce: four random bytes (`prefix`, fixed for a while) and the
  sequence number of the message, so a nonce is never used twice with a key.
  """
  def message_nonce(prefix, sequence) when byte_size(prefix) == 4,
    do: <<prefix::binary, sequence::little-32>>

  @doc "Encrypts or decrypts (it's the same operation) a payload."
  @spec crypt(keys, binary, binary) :: binary
  def crypt(%{policy: policy} = keys, message_nonce, data) when byte_size(message_nonce) == 8 do
    # The counter block (Part 14, 7.2.2.2.4): the key nonce, the message
    # nonce and a 32 bit block counter that starts at 1.
    counter = <<keys.nonce::binary, message_nonce::binary, 1::32>>
    cipher = Map.fetch!(@policies, policy).cipher
    :crypto.crypto_one_time(cipher, keys.encrypting, counter, data, true)
  end

  @doc "The signature of a message, without its signature."
  @spec sign(keys, iodata) :: binary
  def sign(keys, data), do: :crypto.mac(:hmac, :sha256, keys.signing, data)

  @doc "Whether the signature is right, in constant time."
  @spec verify(keys, iodata, binary) :: boolean
  def verify(keys, data, signature),
    do: byte_size(signature) == @signature and :crypto.hash_equals(sign(keys, data), signature)
end
