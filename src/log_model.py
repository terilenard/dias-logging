"""
This work is licensed under the terms of the MIT license.  
For a copy, see <https://opensource.org/licenses/MIT>.

Developed by NISLAB - Network and Information Security Laboratory
at George Emil Palade University of Medicine, Pharmacy, Science and
Technology of Târgu Mureş <https://nislab.umfst.ro/>

Contributors: Teri Lenard
"""

class LogModel(object):

    def __init__(self, json_obj=None):

        if json_obj:
            self.from_json(json_obj)
        else:
            self.id = None
            self.payload = None
            self.message = None
            self.pcr = None
            self.signature = None
            self.can_id = None
            self.timestamp = None
            self.count = None
            self.is_new_chain = False

    def from_json(self, json_obj):
        try:
            self.id = json_obj["_id"]
            self.payload = json_obj["payload"]
            self.message = json_obj["payload"]["Message"]
            self.pcr = json_obj["payload"]["PCR"]
            self.signature = json_obj["payload"]["Signature"]
            self.can_id = json_obj["payload"]["CanId"]
            self.timestamp = json_obj["payload"]["Timestamp"]
            self.count = int(json_obj["payload"]["Count"])
            self.is_new_chain = bool(json_obj["payload"]["IsNewChain"])

            return self
        except ValueError as ex:
            print(ex.__str__())
            return None
