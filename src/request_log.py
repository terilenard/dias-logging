import sys
import time

sys.path.append("/home/teri/Workspace/dias-hackathon-testbed1/modules/communication_protocol/python/")

from comm_core.communicator import Communicator
from comm_core.proto.logging_pb2 import LogMessage


def on_request(request):
    pass

def on_response(content):
    print("Received response: {}".format(str(content)))

requestor_address = "tcp://127.0.0.1:11004"
logger_address = "tcp://127.0.0.1:11002"
module_name = "DummyRequestor"
logger_name = "TPMLogger"
request_name = "LogMessage"

communicator = Communicator(
            requestor_address,
            on_request,
            None,
            [(logger_name, logger_address)],
            [])

log_request = LogMessage()
log_request.message = "Test"


communicator.request(logger_name, request_name,
                     log_request.SerializeToString(),
                     on_response)
time.sleep(0.1)
communicator.stop()
