"""
This work is licensed under the terms of the MIT license.  
For a copy, see <https://opensource.org/licenses/MIT>.

Developed by NISLAB - Network and Information Security Laboratory
at George Emil Palade University of Medicine, Pharmacy, Science and
Technology of Târgu Mureş <https://nislab.umfst.ro/>

Contributors: Teri Lenard
"""

import requests
import json

from datetime import datetime
import time

from log_model import LogModel


class QueryBuilder:

    QUERY_TEMPLATE = {
        "collection": None,
        "sample": True,
        "query": [
            {
                "$limit": 1
            },
            {
                "$match": {
                    # "IsNewChain": False,
                    "payload.Timestamp": {
                        "$gte": {
                            "$numberDecimal": 0.00  # unix time
                        },
                        "$lte": {
                            "$numberDecimal": 0.00  # unix time
                        }
                    }
                }
            }

        ]

    }

    @staticmethod
    def build(collection, limit=None,
              is_new_chain=None,
              is_verified=None,
              start_date=None,
              end_date=None):

        query = QueryBuilder.QUERY_TEMPLATE
        query["collection"] = collection

        if limit:
            try:
                query["query"][0]["$limit"] = int(limit)
            except ValueError as ex:
                return None
        else:
            query["query"][0]["$limit"] = 1

        if start_date and end_date:
            query["query"][1]["$match"]["payload.Timestamp"]["$gte"]["$numberDecimal"] = start_date
            query["query"][1]["$match"]["payload.Timestamp"]["$lte"]["$numberDecimal"] = end_date
        else:
            query["query"][1]["$match"]["payload.Timestamp"] = {}

        return query


class LogRequestor:

    def __init__(self, username, password, url, collection, token):
        self._username = username
        self._password = password
        self._url = url
        self._collection = collection
        self._token = token

        self._headers = {
            'Content-type': 'application/json',
            'Accept': 'application/json',
            'X-XSRF-TOKEN': self._token
        }

    def request(self, start_date=None, end_date=None, limit=None):
        """
        Returns a list of LogModels
        :param start_date:
        :param end_date:
        :return:
        """
        data = QueryBuilder.build(self._collection, limit=limit,
                                  start_date=start_date, end_date=end_date)
        response = requests.post(self._url, data=json.dumps(data),
                                 headers=self._headers, auth=(self._username, self._password))

        content = response.content.decode()
        json_obj = json.loads(content)
        objects = [LogModel(item) for item in json_obj]

        return objects
