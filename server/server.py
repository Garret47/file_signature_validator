import json
import sys
from abc import ABC, abstractmethod
import concurrent.futures
import asyncio
import aiofiles
import logging
import os
import argparse
import signal

logging.basicConfig(level=logging.DEBUG, datefmt='%d.%m.%Y %H:%M:%S',
                    format='[%(asctime)s] #%(levelname)- 5s - %(name)s - %(message)s'
                    )
logger = logging.getLogger(__name__)
HOST = 'localhost'
PORT = 8080
QUARANTINE_DIR = 'quarantine'


class Server(ABC):
    def __init__(self):
        self._server = None

    async def create_server(self):
        try:
            self._server = await asyncio.start_server(self.handler, HOST, PORT)
            logger.debug('Server Start')
            async with self._server:
                await self._server.serve_forever()
        except OSError:
            logger.critical('OsError, server already in use')
            sys.exit(1)

    @abstractmethod
    async def handler(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        raise NotImplemented('The handler must be overridden')


class CheckRequestMixin:
    @staticmethod
    def _check_bad_type(request: dict) -> bool:
        if type(request) != dict or not request.get('command') or type(request.get('params')) != dict:
            return True
        return False

    @staticmethod
    def _change_params(request: dict) -> dict | bool:
        params = request.get('params')
        if len(params.keys()) > 100:
            return False
        params = {key.lower(): values for key, values in params.items()}
        return params

    def _return_request(self, bad_request: dict, request: dict, params: dict) -> (str, dict):
        match request.get('command').lower():
            case 'checklocalfile':
                signature = self._check_bytes_signature(params.get('signature'))
                if type(signature) == bool:
                    bad_request.update({'Exception': 'signature not recognized'})
                    return '', bad_request
                params['signature'] = signature
                return 'checklocalfile', params
            case 'quarantinelocalfile': return 'quarantinelocalfile', params
        bad_request.update({'Exception': 'Command not recognized'})
        return '', bad_request

    def check_request(self, request: bytes) -> (str, dict):
        bad_request = {'status': 'failed'}
        try:
            request = json.loads(request.decode())
        except json.JSONDecodeError:
            bad_request.update({'Exception': 'json error'})
            return '', bad_request
        if self._check_bad_type(request):
            bad_request.update({'Exception': 'Please, Check the entered data'})
            return '', bad_request
        answer = self._change_params(request)
        if type(answer) == bool:
            bad_request.update({'Exception': 'params are too big'})
            return '', bad_request
        if not self._check_files_exist(answer.get('filepath')):
            bad_request.update({'Exception': 'File does not exist'})
            return '', bad_request
        return self._return_request(bad_request, request, answer)

    @staticmethod
    def _check_files_exist(file_path: str) -> bool:
        if file_path:
            return os.path.isfile(file_path)
        return False

    @staticmethod
    def _check_bytes_signature(signature: str) -> bytes | bool:
        try:
            tmp = bytes.fromhex(signature)
            return tmp
        except ValueError:
            logger.error(f'signature: {signature} not bytes')
            return False


class ServerCheckFiles(Server, CheckRequestMixin):
    QUARANTINE_DIR = QUARANTINE_DIR

    async def handler(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        logger.debug('client connect')
        try:
            data_bytes = await reader.readuntil(b'\n')
            command, params = self.check_request(data_bytes)
            if command == 'checklocalfile':
                logger.debug('client CheckLocalFile')
                response = {'FilePath': params['filepath'], 'signature': params['signature'].hex()}
                answer = await self.check_local_file(params['filepath'], params['signature'])
                if type(answer) == list:
                    response.update({'offsets': answer, 'status': 'success'})
                else:
                    response.update({'Exception': answer, 'status': 'failed'})
            elif command == 'quarantinelocalfile':
                logger.debug('client QuarantineLocalFile')
                if not os.path.isdir(self.QUARANTINE_DIR):
                    await self.quarantine_local_file({'filepath': ''}, f'mkdir {self.QUARANTINE_DIR}')
                response = await self.quarantine_local_file(params, f'mv {params["filepath"]} {self.QUARANTINE_DIR}/')
            else:
                response = params
            await self.write_answer_client(writer, response)
        except (asyncio.exceptions.IncompleteReadError, ConnectionError) as e:
            logger.error(f'Read failed, msg: {e}')

    @staticmethod
    async def write_answer_client(writer: asyncio.StreamWriter, response: dict):
        writer.write(json.dumps(response, ensure_ascii=False).encode())
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    @staticmethod
    def find_signature(data: bytes, signature: bytes, file_tell: int) -> list:
        offsets = []
        offset = 0
        while True:
            offset = data.find(signature, offset)
            if offset == -1:
                break
            offsets.append(file_tell - (len(data) - offset))
            offset += len(signature)
        return offsets

    @staticmethod
    async def read_bytes_in_file(f: aiofiles.threadpool.binary.AsyncBufferedReader, chunk: int):
        while True:
            data = await f.read(chunk)
            if data == b'':
                break
            yield data

    async def clear_queue(self, queue: asyncio.Queue, signature: bytes, tell: int, current_data: bytes = b'') -> list:
        data = b''
        while not queue.empty():
            data += await queue.get()
        data += current_data
        return self.find_signature(data, signature, tell)

    async def check_local_file(self, file_path: str, signature: bytes) -> list | str:
        queue_bytes = asyncio.Queue(maxsize=2)
        offsets = []
        try:
            async with aiofiles.open(file_path, mode='rb') as f:
                logger.debug(f'run read file {file_path}')
                async for data_bytes in self.read_bytes_in_file(f, 1024 * 1024):
                    if queue_bytes.qsize() == queue_bytes.maxsize:
                        offsets.extend(await self.clear_queue(queue_bytes, signature, await f.tell(), data_bytes))
                    await queue_bytes.put(data_bytes)
                offsets.extend(await self.clear_queue(queue_bytes, signature, await f.tell()))
        except (PermissionError, OSError) as e:
            logger.error(f'Read {file_path} failed')
            return str(e)
        return offsets

    @staticmethod
    async def quarantine_local_file(params: dict, cmd: str):
        proc = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE,
                                                     stderr=asyncio.subprocess.PIPE)
        _, stderr = await proc.communicate()
        logger.debug(f'[{cmd!r} exited with {proc.returncode}]')
        if proc.returncode == 0:
            return {'FilePath': params['filepath'], 'command': cmd, 'status': 'success'}
        else:
            return {'FilePath': params['filepath'], 'command': cmd, 'status': 'failed', 'stderr': stderr.decode()}


async def cleanup(loop_asyncio: asyncio.AbstractEventLoop):
    tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    await loop_asyncio.shutdown_asyncgens()
    loop_asyncio.stop()
    logger.info('Caught SIGINT')


def check_parse_argument(sys_args: list):
    parser = argparse.ArgumentParser(description='Arguments server')
    parser.add_argument('count_threads', help='Number of threads in the query processing pool', type=int)
    args = parser.parse_args(sys_args)
    if (args.count_threads > 0) and (args.count_threads < 20):
        return args
    else:
        logger.critical('Enter the correct number of threads')
        sys.exit(1)


def main(args: argparse.Namespace):
    loop = asyncio.get_event_loop()
    loop.set_default_executor(concurrent.futures.ThreadPoolExecutor(max_workers=args.count_threads))
    s = ServerCheckFiles()
    loop.create_task(s.create_server())

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: asyncio.ensure_future(cleanup(loop)))

    try:
        loop.run_forever()
    finally:
        loop.close()
        logger.info('Goodbye')


if __name__ == '__main__':
    name_spaces = check_parse_argument(sys.argv[1:])
    main(name_spaces)
