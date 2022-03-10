
import logging
from time import sleep

import paho.mqtt.client as mqtt

# Dependencies
# pip3 install paho-mqtt

logger = logging.getLogger(__name__)


class MQTTClient(object):

    def __init__(self, user, password, host, port):
        self._inst = mqtt.Client()
        self._inst.username_pw_set(user, password)
        self._inst.on_connect = self._on_connect
        self._host = host
        self._port = port

    def is_connected(self):
        return self._inst.is_connected()

    def connect(self):
        self._inst.loop_start()
        self._inst.connect(self._host, self._port, 60)

    def stop(self):
        if self._inst.is_connected():
            self._inst.loop_stop()
            self._inst.disconnect()

    def _on_connect(self, client, userdata, flags, rc):

        if rc == 0:
            logger.info("Client connected successfully.")
            print("connected")
        else:
            logger.error("Client couldn't connect. Received code: {}.".format(rc))
            logger.info("Client tries reconnect...")
            self._inst.reconnect()

    def publish(self, data):

        if self._inst.is_connected():
            self._inst.publish("logging", data)
            logger.info("Published: {}".format(str(data)))
            return True
        else:
            logger.error("Client not connected.")
            return False
