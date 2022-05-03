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
    headers = {"accept": "application/vnd.github.v3+json",
               "Authorization": "token " + os.environ["PAT_FOR_PUB"]}
    url = "https://api.github.com/orgs/{org}/actions/secrets/public-key".format(org = org)
    async with session.get(url, headers=headers) as resp:
        data = await resp.json()
        return (data["key"], data["key_id"])

async def _put_github_repo_secret(session, owner, repo, key_id, secret_name, encrypted_secret):
    headers = {"accept": "application/vnd.github.v3+json",
               "Authorization": "token " + os.environ["PAT_FOR_PUT"]}
    url = "https://api.github.com/repos/{owner}/{repo}/actions/secrets/{secret_name}".format(owner = owner, repo = repo, secret_name = secret_name)
    data = { "encrypted_value" : encrypted_secret,
             "key_id" : key_id }
    async with session.put(url, data=data, headers=headers) as resp:
        # Should always return 204
        return await resp.text()

async def _refresh_token(old_token):

    async with aiohttp.ClientSession(raise_for_status=True) as session:
        resp = await _get_insta_token(
            session, "https://graph.instagram.com/refresh_access_token", old_token
        )
        new_token = json.loads(resp)["access_token"]

        pKey, key_id  = await _get_github_pub_key(session, "shirlywhirl")
        encrypted_secret = _encrypt(pKey, new_token)
        status = await _put_github_repo_secret(session, "jbarno", "shirlywhirlmd", key_id, "INSTA_TOKEN", encrypted_secret)
        print(status)

def refresh_token():
    token = os.environ.get("SHIRLYWHIRLMD_INSTA_TOKEN")
    loop = asyncio.get_event_loop()
    loop.run_until_complete(_refresh_token(token))


if __name__ == "__main__":
    fire.Fire()
