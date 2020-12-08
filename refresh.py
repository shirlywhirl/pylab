import aiohttp
import asyncio
import fire
import json
import os


async def _get(session, url, token):
    params = {"grant_type": "ig_refresh_token", "access_token": token}
    async with session.get(url, params=params) as resp:
        return await resp.text()


async def _refresh_token(path):
    with open(path, "r") as f:
        data = f.read()
    assert data, "No data found at path"

    async with aiohttp.ClientSession(raise_for_status=True) as session:
        resp = await _get(
            session, "https://graph.instagram.com/refresh_access_token", data
        )
        token = json.loads(resp)["access_token"]

    with open(path, "w") as f:
        f.write(token)
        f.truncate()


def refresh_token(path):
    print("Attempting to refresh token at: {}".format(path))
    loop = asyncio.get_event_loop()
    loop.run_until_complete(_refresh_token(path))
    print("Token at: {} refreshed.".format(path))


if __name__ == "__main__":
    fire.Fire()
