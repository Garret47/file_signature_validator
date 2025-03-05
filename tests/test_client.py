import json
import subprocess
import pytest
from server.server import check_parse_argument, main
from server.client import ClientFactory, parser_arguments
import os
from contextlib import nullcontext as not_raise
import multiprocessing
import time
import logging

logging.basicConfig(level=logging.DEBUG, datefmt='%d.%m.%Y %H:%M:%S',
                    format='[%(asctime)s] #%(levelname)- 5s - %(name)s - %(message)s'
                    )
logger = logging.getLogger(__name__)
HOST = 'localhost'
PORT = 8080
COUNT_THREADS = 5

stdout = subprocess.run('pwd', shell=True, capture_output=True)
stdout = stdout.stdout.decode().replace('\n', '')
absolute_path = os.path.join(stdout, 'tests')


@pytest.fixture(scope='module', autouse=True)
def start_server():
    args = check_parse_argument([str(COUNT_THREADS)])
    p1 = multiprocessing.Process(target=main, args=(args,))
    p1.start()
    time.sleep(1)
    if p1.is_alive:
        yield
        logger.debug('Server Stop')
        p1.terminate()
    else:
        logger.critical('Server not started')
        raise OSError('server')


@pytest.fixture(scope='function')
def move_quarantine():
    yield
    path_dir = os.path.join(absolute_path, '../quarantine')
    if os.path.isdir(path_dir):
        files = os.listdir(path_dir)
        for file in files:
            src_path_file = os.path.join(path_dir, file)
            dst_path_file = os.path.join(absolute_path, 'files')
            if os.path.isfile(src_path_file):
                subprocess.run(f'mv {src_path_file} {dst_path_file}', shell=True)
    else:
        logger.debug('not dir')


def read_all_response(flag):
    if flag:
        for i in ClientFactory.connections:
            response = ClientFactory.read_response(i)
            logger.debug(response)
            assert response['status'] == 'success'
        ClientFactory.close_all_connections()


def new_connections(request: dict):
    ClientFactory.new_connect(HOST, PORT, 'client_1')
    ClientFactory.write_request('client_1', request)
    response = ClientFactory.read_response('client_1')
    return response


class TestClient:
    test_check_args = (['-c', 'CheckLocalFile', '--file_path', f'{absolute_path}/files/1.txt', '--signature', '48'],
                       ['-c', 'QuarantineLocalFile', '-f', f'{absolute_path}/files/1.txt'],
                       ['--command', 'CheckLocalFile', '-f', f'{absolute_path}/files/1.txt', '--signature', '0A0A'],
                       ['-j', f'{absolute_path}/configs/1.json'],
                       ['--json', f'{absolute_path}/configs/2.json'])

    test_no_check_args = ([['-c', 'CheckLocalFile', '-j', f'{absolute_path}/configs/1.json'], not_raise()],
                          [['--command'], pytest.raises(SystemExit)],
                          [['-j', f'{absolute_path}/files/1.txt'], not_raise()],
                          [['f'], pytest.raises(SystemExit)])

    test_client_bad_send = (['--command', 'Check', '-f', f'{absolute_path}/files/1.txt'],
                            ['-c', 'CheckLocalFile', '-f', f'{absolute_path}/files/test/1.txt'],
                            ['-c', 'CheckLocalFile', '-f', f'{absolute_path}/files/1.txt', '-s', 'dadawdwa'],
                            ['-c', 'Quarantine', '-f', f'{absolute_path}/files/1.txt'],
                            ['--command', 'QuarantineLocalFile', '--file_path', f'{absolute_path}/files/1.1.txt'])

    test_client_many_send_check = (['-c', 'CheckLocalFile', '-f', f'{absolute_path}/files/1.txt', '-s', '0A0A'],
                                   ['-c', 'CheckLocalFile', '-f', f'{absolute_path}/files/2.txt',
                                    '-s', '4c6f72656d20697073756d20646f6c6f72'],
                                   ['-c', 'CheckLocalFile', '-f', f'{absolute_path}/files/3.txt', '-s', '0A0A'],
                                   ['--json', f'{absolute_path}/configs/3.json'])

    test_client_send_quarantine = (['-c', 'QuarantineLocalFile', '-f', f'{absolute_path}/files/1.txt'],
                                   ['-c', 'QuarantineLocalFile', '-f', f'{absolute_path}/files/2.txt'],
                                   ['-c', 'QuarantineLocalFile', '-f', f'{absolute_path}/files/3.txt'])

    # positive
    @pytest.mark.parametrize('args', test_check_args)
    def test_check_arguments(self, args):
        answer = parser_arguments(args)
        logger.debug(f'answer parse client: {answer}')
        assert answer != {} and type(answer) == dict

    # negative
    @pytest.mark.parametrize('args, expectation', test_no_check_args)
    def test_neg_check_arguments(self, args, expectation):
        with expectation:
            assert parser_arguments(args) == {}

    # positive client send
    @pytest.mark.parametrize('args', test_check_args)
    def test_check_send(self, args, move_quarantine):
        args = parser_arguments(args)
        if args:
            logger.info(f'args: {args}')
            response = new_connections(args)
            assert response['status'] == 'success'
            logger.debug(response)
            ClientFactory.close_all_connections()

    # negative client send
    @pytest.mark.parametrize('args', test_client_bad_send)
    def test_bad_check_send(self, args, move_quarantine):
        args = parser_arguments(args)
        if args:
            logger.info(f'args: {args}')
            response = new_connections(args)
            logger.debug(response)
            assert response['status'] == 'failed'
            ClientFactory.close_all_connections()

    @pytest.mark.parametrize('args', test_client_many_send_check)
    def test_many_send_request_client(self, args):
        ind = self.test_client_many_send_check.index(args)
        flag2 = ind == len(self.test_client_many_send_check) - 1
        args = parser_arguments(args)
        count_client_connections = 20
        if args:
            logger.info(f'args: {args}')
            for i in range(count_client_connections):
                ClientFactory.new_connect(HOST, PORT, f'{ind}_{i}')
                ClientFactory.write_request(f'{ind}_{i}', args)
            read_all_response(flag2)

    @pytest.mark.parametrize('args', test_client_send_quarantine)
    def test_check_quarantine(self, args, move_quarantine):
        args = parser_arguments(args)
        if args:
            logger.info(f'args: {args}')
            response = new_connections(args)
            logger.debug(response)
            assert response['status'] == 'success'
            ClientFactory.close_all_connections()