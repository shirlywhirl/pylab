import aiohttp
import asyncio
import fire
import json
import os

# YOINK: https://docs.github.com/en/rest/reference/actions#example-encrypting-a-secret-using-python
from base64 import b64encode
from nacl import encoding, public

def _encrypt(public_key: str, secret_value: str) -> str:
    """Encrypt a Unicode string using the public key."""
    public_key = public.PublicKey(public_key.encode("utf-8"), encoding.Base64Encoder())
    sealed_box = public.SealedBox(public_key)
    encrypted = sealed_box.encrypt(secret_value.encode("utf-8"))
    return b64encode(encrypted).decode("utf-8")

async def _get_insta_token(session, url, token):
    params = {"grant_type": "ig_refresh_token", "access_token": token}
    async with session.get(url, params=params) as resp:
        return await resp.text()

async def _get_github_pub_key(session, org):
    headers = {"accept": "application/vnd.github.v3+json"}
    url = "https://api.github.com/org/{org}/actions/secrets/public-key".format(org = org)
    async with session.get(url, params=params) as resp:
        # Likely has the key id needed in the next step
        return await resp.text()

async def _put_github_secret(session, org, secret_name, encrypted_secret):
    headers = {"accept": "application/vnd.github.v3+json"}
    url = "https://api.github.com/orgs/{org}/actions/secrets/{secret_name}".format(org = org, secret_name = secret_name)
    data = { "encrypted_value" : encrypted_secret,
             "key_id" : TODO,
             "visiblity" : "selected",
             "selected_repository_ids": "shirlywhirl/shirlywhirlmd" }
    async with session.put(url, params=params) as resp:
        # Should always return 201
        return await resp.text()


async def _refresh_token(old_token):

    async with aiohttp.ClientSession(raise_for_status=True) as session:
        resp = await _get_insta_token(
            session, "https://graph.instagram.com/refresh_access_token", old_token
        )
        new_token = json.loads(resp)["access_token"]

        # TODO: Upload pub key, ensure shirlywhirl is a an org
        pKey = await _get_github_pub_key(session, "shirlywhirl")
        encrypted_secret = _encrypt(pKey, new_token)


def refresh_token(token):
    # TODO: use an envVar for this
    loop = asyncio.get_event_loop()
    loop.run_until_complete(_refresh_token(token))


if __name__ == "__main__":
    fire.Fire()
