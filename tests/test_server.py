import asyncio
import subprocess
import time
import pytest
import logging
from server.server import check_parse_argument, main
import argparse
import multiprocessing

logging.basicConfig(level=logging.DEBUG, datefmt='%d.%m.%Y %H:%M:%S',
                    format='[%(asctime)s] #%(levelname)- 5s - %(name)s - %(message)s'
                    )
logger = logging.getLogger(__name__)


#positive test
@pytest.mark.parametrize('args', (['1'], ['2'], ['3'], ['15'], ['19']))
def test_check_parse_argument_pos(args: list):
    assert check_parse_argument(args) == argparse.Namespace(count_threads=int(args[0]))


#negative test
@pytest.mark.parametrize('args', (['20'], ['-7'], ['0'], ['da'], ['15', '33'], '321321'))
def test_check_parse_argument_neg(args: list):
    with pytest.raises(SystemExit):
        assert check_parse_argument(args)


#positive main test
@pytest.mark.parametrize('args', (['5'], ['2'], ['1']))
def test_check_main_function(args):
    args = check_parse_argument(args)
    p1 = multiprocessing.Process(target=main, args=(args, ))
    p1.start()
    time.sleep(1)
    if p1.is_alive():
        # print(subprocess.run('netstat -tuln | grep 127.0.0.1:8080', shell=True, capture_output=True).stdout.decode())
        p1.terminate()
    else:
        logger.critical('Server not started')
        raise OSError('server')