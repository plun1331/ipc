# BSD 3-Clause License

# Copyright (c) 2023, plun1331

# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:

# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.

# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.

# 3. Neither the name of the copyright holder nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.

# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# Packet Format:
# Length - int (5 bytes), length of only data
# Type - int (1 byte) (AUTH 0x00, KEEP_ALIVE 0x01, CLOSE 0x02, MESSAGE 0x03)
# Data - dict
import asyncio
import json
import logging
import time


log = logging.getLogger(__name__)

class Client:
    def __init__(self, *, host: str, port: int, secret: str) -> None:
        self.host: str = host
        self.port: int = port
        self.secret: str = secret

        self.reader: asyncio.StreamReader = None
        self.writer: asyncio.StreamWriter = None
        self.authenticated: bool = False
        self.last_keep_alive: float = None
        self.keep_alive_interval: float = 30
        self.packet_id: int = 0
        self.read_task: asyncio.Task = None
        self.keep_alive_task: asyncio.Task = None
        self._running = asyncio.Future()

    async def connect(self):
        self.reader, self.writer = await asyncio.open_connection(
            self.host, self.port
        )
        log.info("Connected to %s:%s", self.host, self.port)
        await self.authenticate()
        self.read_task = asyncio.create_task(self.read_handler())
        self.keep_alive_task = asyncio.create_task(self.keep_alive())
        await self._running

    async def read_handler(self):
        while True:
            try:
                request_type, data = await self.read()
            except asyncio.DisconnectedError:
                await self.close()
                return
            if request_type is None:
                await asyncio.sleep(0.01)
                continue
            if request_type == 0x00:
                self.authenticated = True
            elif request_type == 0x01:
                self.last_keep_alive = time.time()
            elif request_type == 0x02:
                await self.close()
            elif request_type == 0x03:
                await self.message(data)
            else:
                await self.close()
                raise Exception('Unknown request type')

    async def close(self):
        await self.write(0x02, {})
        self.writer.close()
        await self.writer.wait_closed()
        self.reader.feed_eof()
        if self.read_task:
            self.read_task.cancel()
        if self.keep_alive_task:
            self.keep_alive_task.cancel()
        log.info('Closed connection to %s:%s', self.host, self.port)
        self._running.set_result(None)

    async def authenticate(self):
        await self.write(0x00, {'secret': self.secret})

    async def keep_alive(self):
        while True:
            await self.write(0x01, {})
            self.last_keep_alive = time.time()
            await asyncio.sleep(self.keep_alive_interval)

    async def write(self, message_type: int, data: dict):
        data = json.dumps(data).encode('utf-8')
        log.debug('Sending %s: %s', message_type, data)
        data = len(data).to_bytes(5, 'big') + message_type.to_bytes(1, 'big') + data
        self.writer.write(data)
        await self.writer.drain()

    async def read(self):
        data = await self.reader.read(5)
        if len(data) == 0:
            return None, None
        length = int.from_bytes(data, 'big')
        data = await self.reader.readexactly(1)
        request_type = int.from_bytes(data, 'big')
        data = await self.reader.readexactly(length)
        data = json.loads(data.decode('utf-8'))
        log.debug('Recieved %s: %s', request_type, data)
        return request_type, data

    async def message(self, data: dict):
        pass

    async def request(self, route: str, payload: dict):
        self.packet_id += 1
        data = {
            'id': self.packet_id,
            'route': route,
            'data': payload
        }
        await self.write(0x03, data)
