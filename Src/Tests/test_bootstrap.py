import unittest
import os
import sys

sys.path.append("../")

from DiasLogging.bootstrap import bootstrap_openssl
from DiasLogging.bootstrap import PRIV_NAME, PUB_NAME


class TestBootstrap(unittest.TestCase):

    def __init__(self, methodName: str) -> None:
        super().__init__(methodName=methodName)

        self.good_type = "RSA"
        self.bad_type = "SRA"

        self.are_created = False

        self.bits = 1024
        self.path = "/tmp/"

    def tearDown(self) -> None:

        if self.are_created:
            os.remove(self.path + PUB_NAME)
            os.remove(self.path + PRIV_NAME)
        return super().tearDown()    

    def test_good_bootstrap_openssl(self):
        bootstrap_openssl(self.good_type, self.bits, self.path)
        self.assertTrue(os.path.isfile(self.path + PUB_NAME))
        self.assertTrue(os.path.isfile(self.path + PRIV_NAME))
        self.are_created = True

    def test_bad_bootstrap_openssl(self):
        pass


if __name__ == '__main__':
    unittest.main()
