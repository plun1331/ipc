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
from __future__ import annotations

import asyncio
import json
import logging
import time


log = logging.getLogger(__name__)


class Connection:
    def __init__(
        self, 
        server: Server,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter
    ):
        self.server: Server = server
        self.transport: asyncio.Transport = writer.transport
        self.reader: asyncio.StreamReader = reader
        self.writer: asyncio.StreamWriter = writer

        self.authenticated: bool = False
        self.last_keep_alive = time.time()
        self.handler_task = None
        
    @property
    def address(self):
        return self.transport.get_extra_info('peername')

    async def start(self):
        self.handler_task = asyncio.create_task(self.handler())
        log.info('Started handling for %s:%s', *self.address)

    async def handler(self):
        try:
            while True:
                try:
                    request_type, data = await self.read()
                except asyncio.DisconnectedError:
                    await self.close()
                    return
                if (
                    self.last_keep_alive + 
                    self.server.keep_alive_interval + 
                    self.server.keep_alive_wait_time
                ) < time.time():
                    await self.close()
                    return
                if request_type is None:
                    await asyncio.sleep(0.01)
                    continue
                if request_type == 0x00:
                    await self.auth(data)
                elif request_type == 0x01:
                    await self.keep_alive(data)
                elif request_type == 0x02:
                    await self.close()
                elif request_type == 0x03:
                    await self.message(data)
                else:
                    self.writer.close()
                    self.reader.feed_eof()
                    raise Exception('Invalid request type')
        except asyncio.CancelledError:
            log.error('Handler task cancelled')
        except Exception as e:
            log.exception('Error in handler')
            await self.close()

    async def read(self):
        data = await self.reader.read(5)
        if len(data) == 0:
            return None, None
        length = int.from_bytes(data, 'big')
        data = await self.reader.read(1)
        request_type = int.from_bytes(data, 'big')
        data = await self.reader.read(length)
        data = json.loads(data.decode('utf-8'))
        log.debug('Recieved %s: %s', request_type, data)
        return request_type, data

    async def write(self, message_type: int, data: dict):
        log.debug('Sending %s: %s', message_type, data)
        data = json.dumps(data).encode('utf-8')
        data = len(data).to_bytes(5, 'big') + message_type.to_bytes(1, 'big') + data
        self.writer.write(data)
        await self.writer.drain()
    
    async def close(self):
        if self.handler_task is not None:
            self.handler_task.cancel()
        self.writer.close()
        self.reader.feed_eof()
        self.server.connections.pop(self.address, None)
        log.info('Closed connection for %s:%s', *self.address)

    async def auth(self, data):
        if self.authenticated:
            await self.close()
            raise Exception('Already authenticated')
        if data['secret'] != self.server.secret:
            self.writer.close()
            self.reader.feed_eof()
            raise Exception('Invalid secret')
        self.authenticated = True
        self.server.connections[self.address] = self
        await self.write(0x00, {'success': True})

    async def keep_alive(self, data):
        self.last_keep_alive = time.time()
        await self.write(0x01, {'success': True})

    async def message(self, data):
        if not self.authenticated:
            await self.close()
            raise Exception('Not authenticated')
        message_id = data['id']
        route = data['route']
        data = data['data']
        response = await self.server.process(data)
        await self.write(0x03, {
            'id': message_id,
            'route': route,
            'data': response
        })



class Server:
    def __init__(
        self, 
        *, 
        host: str, 
        port: int,
        secret: str
    ) -> None:
        self.host: str = host
        self.port: int = port
        self.secret: str = secret

        self.connections = {}

        self.keep_alive_interval = 30
        self.keep_alive_wait_time = 5

    async def process_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        connection = Connection(self, reader, writer)
        log.info("New connection from %s:%s", *connection.address)
        self.connections[connection.address] = connection
        await connection.start()

    async def start(self):
        server = await asyncio.start_server(
            self.process_connection, 
            self.host, 
            self.port
        )
        async with server:
            await server.serve_forever()

    async def process(self, data):
        return {'success': True}
