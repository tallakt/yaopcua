# Runs asyncua's client against a secure yaopcua server, with each policy and
# mode and each kind of login, and prints what happened as JSON. Arguments:
# url, server certificate, client certificate and key, user certificate and
# key, and a client certificate and key the server doesn't trust.
import asyncio, json, sys
from asyncua import Client, ua
from asyncua.crypto import security_policies, uacrypto

POLICIES = {
    "basic256sha256": security_policies.SecurityPolicyBasic256Sha256,
    "aes128_sha256_rsa_oaep": security_policies.SecurityPolicyAes128Sha256RsaOaep,
    "aes256_sha256_rsa_pss": security_policies.SecurityPolicyAes256Sha256RsaPss,
}
MODES = {"sign": ua.MessageSecurityMode.Sign, "sign_and_encrypt": ua.MessageSecurityMode.SignAndEncrypt}


async def attempt(url, server_cert, cert, key, policy, mode, login, user_cert, user_key):
    client = Client(url)
    await client.set_security(POLICIES[policy], cert, key, server_certificate=server_cert, mode=MODES[mode])
    if login == "password":
        client.set_user("operator")
        client.set_password("secret")
    elif login == "certificate":
        client.user_certificate = await uacrypto.load_certificate(user_cert)
        client.user_private_key = await uacrypto.load_private_key(user_key)
    try:
        async with client:
            node = client.get_node("ns=1;s=Speed")
            await node.write_value(ua.DataValue(ua.Variant(1700, ua.VariantType.Int16)))
            return await node.read_value()
    except Exception as e:
        return type(e).__name__


async def main(url, server_cert, cert, key, user_cert, user_key, stranger_cert, stranger_key):
    out = {}
    for policy in POLICIES:
        for mode in MODES:
            for login in ["anonymous", "password", "certificate"]:
                out[f"{policy} {mode} {login}"] = await attempt(url, server_cert, cert, key, policy, mode, login, user_cert, user_key)

    out["untrusted"] = await attempt(url, server_cert, stranger_cert, stranger_key, "basic256sha256", "sign_and_encrypt", "anonymous", None, None)

    # A None channel, with the password encrypted for the server.
    plain = Client(url)
    plain.set_user("operator")
    plain.set_password("secret")
    async with plain:
        out["none password"] = await plain.get_node("ns=1;s=Speed").read_value()

    print(json.dumps(out))


asyncio.run(main(*sys.argv[1:9]))
