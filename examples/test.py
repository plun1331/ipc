import asyncio
from ipc import Server
import logging

logging.basicConfig(level=logging.DEBUG)

async def run():
    server = Server(
        host='0.0.0.0',
        port=1234,
        secret="beans",
    )
    await server.start()

asyncio.run(run())
