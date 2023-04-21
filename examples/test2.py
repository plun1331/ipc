import asyncio
from ipc import Client
import logging

logging.basicConfig(level=logging.DEBUG)

async def run():
    client = Client(
        host='127.0.0.1',
        port=1234,
        secret="beans",
    )
    await client.connect()

asyncio.run(run())
