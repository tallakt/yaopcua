defmodule OPCUA.CertificateTest do
  use ExUnit.Case, async: true

  alias OPCUA.Certificate

  @moduletag :tmp_dir

  test "a self-signed certificate carries the application URI and host names" do
    {cert, key} = Certificate.self_signed("urn:plant:server", hostnames: ["plc1", "10.0.0.5"])
    assert Certificate.application_uri(cert) == "urn:plant:server"
    assert Certificate.current?(cert)
    assert Certificate.public_key(cert) == OPCUA.SecurityPolicy.public_key(key)
    assert byte_size(Certificate.thumbprint(cert)) == 20

    {:OTPCertificate, tbs, _, _} = :public_key.pkix_decode_cert(cert, :otp)
    extensions = elem(tbs, 10)
    {:Extension, _, _, names} = Enum.find(extensions, &(elem(&1, 1) == {2, 5, 29, 17}))
    assert {:dNSName, ~c"plc1"} in names
    assert {:iPAddress, <<10, 0, 0, 5>>} in names
  end

  test "trusts a certificate in the list, or signed by one in it" do
    {cert, _} = Certificate.self_signed("urn:a")
    {other, _} = Certificate.self_signed("urn:b")
    assert Certificate.trusted?(cert, [other, cert])
    refute Certificate.trusted?(cert, [other])
    refute Certificate.trusted?(cert, [])
    assert Certificate.trusted?(cert, :any)

    # A CA and a certificate it signed, made by :public_key so that the
    # chain is one every OTP release validates.
    rsa = [key: {:rsa, 2048, 65_537}, digest: :sha256]
    chain = :public_key.pkix_test_data(%{root: rsa, peer: rsa})
    [ca | _] = chain[:cacerts]
    assert Certificate.trusted?(chain[:cert], [ca])
    refute Certificate.trusted?(chain[:cert], [other])
  end

  test "an expired certificate isn't trusted" do
    {cert, _} = Certificate.self_signed("urn:old", days: -2)
    refute Certificate.current?(cert)
    refute Certificate.trusted?(cert, [cert])
    refute Certificate.trusted?(cert, :any)
  end

  test "reads and writes DER and PEM files", %{tmp_dir: dir} do
    {cert, key} = Certificate.self_signed("urn:files")

    for name <- ["cert.der", "cert.pem"] do
      path = Path.join(dir, name)
      :ok = Certificate.write(path, cert)
      assert Certificate.read(path) == cert
    end

    :ok = Certificate.write_key(Path.join(dir, "key.pem"), key)
    assert Certificate.read_key(Path.join(dir, "key.pem")) == key
  end
end
