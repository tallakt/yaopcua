defmodule OPCUA.SecurityPolicyTest do
  use ExUnit.Case, async: true

  alias OPCUA.SecurityPolicy

  @secure [:basic256sha256, :aes128_sha256_rsa_oaep, :aes256_sha256_rsa_pss]

  setup_all do
    key = :public_key.generate_key({:rsa, 2048, 65_537})
    %{key: key, public: SecurityPolicy.public_key(key)}
  end

  test "names and URIs" do
    assert SecurityPolicy.uri(:basic256sha256) ==
             "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"

    assert SecurityPolicy.from_uri(
             "http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss"
           ) == :aes256_sha256_rsa_pss

    assert SecurityPolicy.from_uri("http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15") ==
             nil
  end

  test "keys are derived with P_SHA256 as asyncua derives them" do
    # From asyncua's uacrypto.p_sha256(bytes(range(32)), bytes(range(100, 132)), [32, 32, 16])
    keys =
      SecurityPolicy.derive(
        :basic256sha256,
        :binary.list_to_bin(Enum.to_list(0..31)),
        :binary.list_to_bin(Enum.to_list(100..131))
      )

    assert Base.encode16(keys.signing, case: :lower) ==
             "5d667f3542df4c0d18c2edc05d8fecbf7beb6a0a0403e76e1e91719689d1ecd8"

    assert Base.encode16(keys.encrypting, case: :lower) ==
             "1cdf20ea137039545580dbadc02dc68572e6506f48406debe0a2f12bc59e7c01"

    assert Base.encode16(keys.iv, case: :lower) == "5e6332cea56dc081cef88b3e8fc6629c"

    # Aes128 takes a 16-byte key from the same stream.
    assert byte_size(SecurityPolicy.derive(:aes128_sha256_rsa_oaep, "a", "b").encrypting) == 16
  end

  test "signs and verifies", %{key: key, public: public} do
    for policy <- @secure do
      signature = SecurityPolicy.sign(policy, "data", key)
      assert byte_size(signature) == 256
      assert SecurityPolicy.verify(policy, "data", signature, public)
      refute SecurityPolicy.verify(policy, "other", signature, public)
    end
  end

  test "encrypts across several RSA blocks, the last one short", %{key: key, public: public} do
    data = :crypto.strong_rand_bytes(500)

    for policy <- @secure do
      encrypted = SecurityPolicy.encrypt(policy, data, public)
      assert byte_size(encrypted) == 3 * 256
      assert SecurityPolicy.decrypt(policy, encrypted, key) == {:ok, data}
    end

    assert SecurityPolicy.decrypt(:basic256sha256, "not a block", key) ==
             {:error, :bad_security_checks_failed}
  end

  test "a secret for the server carries its nonce, which must match", %{key: key, public: public} do
    nonce = :crypto.strong_rand_bytes(32)

    for policy <- @secure do
      encrypted = SecurityPolicy.encrypt_secret(policy, "secret", nonce, public)
      assert SecurityPolicy.decrypt_secret(policy, encrypted, nonce, key) == {:ok, "secret"}

      assert SecurityPolicy.decrypt_secret(policy, encrypted, :crypto.strong_rand_bytes(32), key) ==
               {:error, :bad_identity_token_invalid}
    end
  end

  test "symmetric encryption and signing" do
    keys =
      SecurityPolicy.derive(
        :aes256_sha256_rsa_pss,
        :crypto.strong_rand_bytes(32),
        :crypto.strong_rand_bytes(32)
      )

    data = :crypto.strong_rand_bytes(64)
    encrypted = SecurityPolicy.encrypt_symmetric(:aes256_sha256_rsa_pss, keys, data)
    assert encrypted != data

    assert SecurityPolicy.decrypt_symmetric(:aes256_sha256_rsa_pss, keys, encrypted) ==
             {:ok, data}

    assert byte_size(SecurityPolicy.mac(keys, data)) == 32
  end
end
