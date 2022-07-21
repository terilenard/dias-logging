"""
This work is licensed under the terms of the MIT license.  
For a copy, see <https://opensource.org/licenses/MIT>.

Developed by NISLAB - Network and Information Security Laboratory
at George Emil Palade University of Medicine, Pharmacy, Science and
Technology of Târgu Mureş <https://nislab.umfst.ro/>

Contributors: Teri Lenard
"""
import paho.mqtt.client as mqtt


class MQTTClient(object):

    def __init__(self, user, password, host, port, service_name="",
                 on_message_callback=None):
        self._inst = mqtt.Client()
        self._inst.username_pw_set(user, password)
        self._inst.on_connect = self._on_connect
        self._inst.on_subscribe = self._on_subscribe

        if on_message_callback:
            self._inst.on_message = on_message_callback
        else:
            self._inst.on_message = self._on_new_message

        self._host = host
        self._port = port
        self._service_name = service_name

        self._log_topic = "logging/"
        self._event_topic = "log_events/"

    def is_connected(self):
        return self._inst.is_connected()

    def connect(self):
        self._inst.loop_start()
        self._inst.connect(self._host, self._port, 60)

    def stop(self):
        if self._inst.is_connected():
            self._inst.loop_stop(True)
            self._inst.disconnect()

    def _on_connect(self, client, userdata, flags, rc):

        if rc == 0:
            self._inst.subscribe(self._log_topic, 0)

        else:
            self._inst.reconnect()

    def _on_subscribe(self, mqttc, obj, mid, granted_qos):
        pass

    def publish_log(self, data):
        if self._inst.is_connected():
            self._inst.publish(self._event_topic, data)
            return True
        else:
            return False


if __name__ == "__main__":
    """
    mosquitto_pub  -h 127.0.0.1 -p 1883 -u mixcan -P mixcan -t logging/ -m "Roger Roger"
    """

    def on_new_log(mqttc, obj, msg):
        print(msg.payload.decode())

    try:
        client = MQTTClient("tpm_logger", "tpm_logger", "127.0.0.1", 1883, 
                            service_name="TPMLogger")
        client.connect()

        import time

        while True:
            time.sleep(0.1)
    except Exception:
        client.stop()
