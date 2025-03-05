import signal
import socket
import json
import argparse
import os
import logging
import sys
from abc import ABC, abstractmethod

logging.basicConfig(level=logging.DEBUG, datefmt='%d.%m.%Y %H:%M:%S',
                    format='[%(asctime)s] #%(levelname)- 5s - %(name)s - %(message)s'
                    )
logger = logging.getLogger(__name__)
HOST = 'localhost'
PORT = 8080


class Client(ABC):
    def __init__(self):
        self.s = None

    @abstractmethod
    def open_connection(self, host: str, port: int):
        raise NotImplementedError('The function must be overridden')

    @abstractmethod
    def close_connection(self):
        raise NotImplementedError('The function must be overridden')


class ClientLocalFile(Client):
    def open_connection(self, host: str, port: int):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((host, port))

    def close_connection(self):
        if self.s:
            self.s.close()
            self.s = None


class ClientFactory:
    connections = {}

    @classmethod
    def new_connect(cls, host: str, port: int, id_client: str):
        logger.debug(cls.connections)
        if id_client not in cls.connections:
            client = ClientLocalFile()
            client.open_connection(host, port)
            cls.connections[id_client] = client

    @classmethod
    def close_all_connections(cls):
        for id_client in cls.connections:
            cls.connections[id_client].close_connection()
        cls.connections = {}

    @classmethod
    def read_response(cls, id_client: str) -> dict:
        response = b''
        while True:
            data = cls.connections[id_client].s.recv(1024 * 1024)
            if len(data) == 0:
                break
            response += data
        if not response:
            return {}
        try:
            return json.loads(response.decode())
        except json.JSONDecodeError as e:
            logger.critical('Unexpected behavior from the server')
            cls.connections[id_client].close_connection()
            raise json.JSONDecodeError

    @classmethod
    def write_request(cls, id_client: str, request: dict):
        try:
            request = json.dumps(request).encode()
            cls.connections[id_client].s.sendall(request + b'\n')
        except json.JSONDecodeError:
            cls.connections[id_client].s.sendall(b'\n')
            logger.error('Bad request')


def signal_handler(sig, frame):
    logger.info(f'Caught {sig}')
    ClientFactory.close_all_connections()
    sys.exit(0)


def check_parse_arguments(params: argparse.Namespace, epilog: str) -> dict:
    logger.debug(f'params: {params}')
    if params.json and (params.command or params.signature or params.file):
        logger.error(epilog)
        return {}
    if params.json and os.path.isfile(params.json):
        try:
            with open(file=params.json, mode='r') as f:
                return json.load(f)
        except (PermissionError, OSError, json.JSONDecodeError):
            return {}
    if not (params.command and params.file):
        return {}
    answer = {'command': params.command, 'params': {'FilePath': params.file}}
    if params.signature:
        answer['params']['signature'] = params.signature
    return answer


def parser_arguments(sys_args: list) -> dict:
    epilog = ('The program accepts either individual arguments (command, file_path, signature) '
              'or a single json argument.')
    parser = argparse.ArgumentParser(description="TCP Client", epilog=epilog)
    parser.add_argument('-c', '--command', help='Command to send', dest='command')
    parser.add_argument('-f', '--file_path', help='Path to file', dest='file')
    parser.add_argument('-s', '--signature', help='Signature for CheckLocalFile command', dest='signature')
    parser.add_argument('-j', '--json', help='Path to JSON file', dest='json')
    args = parser.parse_args(sys_args)
    return check_parse_arguments(args, epilog)


def main(args: dict):
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, signal_handler)
    client = 'client_1'
    ClientFactory.new_connect(HOST, PORT, client)
    ClientFactory.write_request(client, args)
    print('Response:', ClientFactory.read_response(client))
    ClientFactory.close_all_connections()


if __name__ == "__main__":
    client_request = parser_arguments(sys.argv[1:])
    # client_request = parser_arguments(['--command', 'CheckLocalFile', '--file_path', 'server/1.txt', '-s', '48 65 6c 6c 6f'])
    main(client_request)
