"""
This work is licensed under the terms of the MIT license.  
For a copy, see <https://opensource.org/licenses/MIT>.

Developed by NISLAB - Network and Information Security Laboratory
at George Emil Palade University of Medicine, Pharmacy, Science and
Technology of Târgu Mureş <https://nislab.umfst.ro/>

Contributors: Teri Lenard
"""
import time
import signal
from threading import Thread
from queue import Queue
from queue import Empty as EmptyException
from configparser import ConfigParser
from argparse import ArgumentParser

from log import logger
from log_requestor import LogRequestor
from tpm_core import TPMCore


class LogVerifier:

    def __init__(self, config):

        self._log_requestor = LogRequestor(
            config["bosch-iot"]["username"],
            config["bosch-iot"]["password"],
            config["bosch-iot"]["url"],
            config["bosch-iot"]["collection"],
            config["bosch-iot"]["token"]
        )

        # Time_n must store the start (past) timestamp value for queries
        self._time_n_file = config["processing"]["time_file"]
        self._time_n = None
        # Time_0 should store the current time
        self._time_0 = None

        self._should_run = False
        self._pooling_cycle = int(config["processing"]["pooling_cycle"])
        self._working_queue = Queue()
        self._worker = Thread(target=self._verify_task, daemon=True)

        self._tpm_core = TPMCore(config["tpm"])

    def start(self):
        self._should_run = True

        """
        On the first cycle get the time from file
        and current time. Extract the logs in the past
        period of time since last start.
        """

        ok = self._tpm_core.initialise()

        if not ok:
            logger.error("Could not initialise TPM")
            return

        logger.info("Loaded tpm public key")

        self._worker.start()
        logger.info("Starter working thread")

        self._time_n = self._read_time_file()
        self._time_0 = time.time()

        objects = self._log_requestor.request(self._time_n, self._time_0, limit=5)

        for obj in objects:
            self._working_queue.put(obj)

        self._time_n = self._time_0
        self._update_time_file()
        # self._time_0 = time.time()

        while self._should_run:
            time.sleep(self._pooling_cycle)
            self._time_0 = time.time()

            objects = self._log_requestor.request(self._time_n, self._time_0, limit=100)
            if len(objects) == 0:
                continue

            for obj in objects:
                self._working_queue.put(obj)

            self._time_n = self._time_0
            self._update_time_file()

    def _verify_task(self):

        while self._should_run:
            try:
                obj = self._working_queue.get(timeout=1)
            except EmptyException:
                continue

            ok = self._tpm_core.verify(obj)

            if not ok:
                logger.warning("Message with id {} not verified".format(obj.id))
            else:
                logger.info("Message with id{} verified".format(obj.id))

    def stop(self):
        self._should_run = False
        self._worker.join()

    def _read_time_file(self):
        """
        Reads time from file and converts it
        to a datetime object
        :return: datetime object
        """
        with open(self._time_n_file, "r") as f:
            str_time = f.readline()

            try:
                unix_time = float(str_time)
            except ValueError:
                print("Could not convert to unix time from file")
                return None

            return unix_time

    def _update_time_file(self):

        with open(self._time_n_file, "w") as f:
            f.write("{}".format(self._time_n))


def signal_handler(signum, frame):
    log_verifier.stop()


if __name__ == '__main__':

    signal.signal(signal.SIGQUIT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    parser = ArgumentParser(description="Log verifier.")
    parser.add_argument("-c", type=str, help="Path to config file.")
    args = parser.parse_args()

    config = ConfigParser()
    config.read(args.c)

    global log_verifier

    log_verifier = LogVerifier(config)
    log_verifier.start()
