import os
import json
import logging
import datetime
import requests
import sys


class reporter_utils:
    def _set_logging(self):
        date = datetime.datetime.now().strftime("%m%d%Y_%H%M%S")

        if not os.path.exists("./logs"):
            os.makedirs("./logs")

        logging.basicConfig(
            filename=f"./logs/api_{date}.log",
            level=logging.INFO,
            format="%(asctime)s :: %(levelname)s :: %(message)s",
        )

    def _write_json(self, out_file, data, write="a"):
        """
        Write JSON

        :param self: Self
        :param id: file name
        :param id: python dictionary
        :param id: write type defaults to append
        """
        with open(f"{out_file}.json", write) as output:
            json.dump(data, output)

    def _read_json(self, input):
        """
        Read JSON

        :param self: Self
        :param id: file name
        :return: dictionary from json file
        """
        try:
            with open(f"{input}", "r") as data_file:
                data = json.load(data_file)
        except Exception as error:
            data = None

        return data

    def __init__(self, tenant_info, cve):
        self.name = tenant_info["name"]
        self.headers = {"accept": "application/json; charset=utf-8"}
        self.headers["Authorization"] = f"Api-Token {tenant_info['tenant_token']}"
        self.url = f"https://{tenant_info['env_id']}.live.dynatrace.com/"
        self.api_data = None
        self._set_logging()
        logging.info("Setting up environment")
        self.vState = "VULNERABLE"  # RESOLVED
        self.retry_max = 3
        self.cve = cve
        self.tenant = tenant_info["name"]
        self.products = self._read_json("apps.json")

    def _mkdir(self, path):
        if not os.path.exists(path):
            os.makedirs(path)

    def _rmfile(self, path):
        if os.path.exists(path):
            os.remove(path)

    def _get_api_data(self, url, debug=False):
        """
        Data Request

        :param self: Self
        :param url: url of api request
        :return: json of response
        """

        res = requests.get(url, headers=self.headers)
        api_data = None
        if res:
            api_data = res.json()
            if debug:
                self._write_json(f"{self.name}_API_results", api_data, "w")
        else:
            logging.error(f"Could not retrieve Data for {url} API call.")
            logging.error(f"API Returned: {res.json()}")

        return api_data

    def _post_api_data(self, url, data):
        """
        Data Push

        :param self: Self
        :param url: url of api call
        :param data: body of api call
        :return: json of response
        """

        res = requests.post(url, headers=self.headers, data=json.dumps(data))
        api_data = None
        if res:
            api_data = res.json()
        else:
            print(res.json())
            self._write_json(f"{self.name}_API_failed", data, "w")
            logging.error(f"Could not post Data for {url} API call.")
            logging.error(f"API Returned: {res.json()}")

        return api_data

    def _delete_api_data(self, url):
        """
        Data Delete

        :param self: Self
        :param url: url of api call
        :return: json of response
        """

        res = requests.delete(url, headers=self.headers)
        api_data = None
        if res:
            api_data = res.json()
        else:
            print(res.json())
            logging.error(f"Could not delete Data for {url} API call.")
            logging.error(f"API Returned: {res.json()}")
        return api_data

    def _get_entity_info(self, id):
        """
        Get Response Info

        :param self: Self
        :param id: id of entity to get info
        :return: json response from API.
        """
        url = self.url + f"api/v2/entities/{id}"
        info = self._get_api_data(url)
        return info

    def _get_metadata(self, data, query):
        """
        Get Metadata

        :param self: Self
        :param data: process group instance entity info
        :param query: data to find
        :return: string of queried data
        """
        metadata = (data.get("properties")).get("metadata")
        meta_val = "Unknown"
        for item in metadata:
            if item["key"] == query:
                meta_val = item["value"]
                break
        return meta_val

    def _get_tag(self, data, tag_key):
        tags = data.get("tags")
        tag_val = "Unknown"
        for item in tags:
            if item.get("key") == tag_key:
                tag_val = item.get("value")
        return tag_val

    def resolve_l3(self, mz_name):
        leader = "Unknown"
        if self.products != None:
            for product in self.products.keys():
                if mz_name in self.products[product]["mzs"]:
                    if self.products[product]["l3"]:
                        leader = "{}[{}]".format(
                            self.products[product]["l3"]["name"],
                            self.products[product]["l3"]["emailAddress"],
                        )
                    break
        return leader

    def get_mzs_l3s(self, data):
        mzs, l3s = [], []
        for mz in data.get("managementZones"):
            if "cve" not in mz["name"].lower():
                mzs.append(mz["name"])
                l3s.append(self.resolve_l3(mz["name"]))
        if len(mzs) == 0:
            logging.info(f"missed mz: {data}")
        return ", ".join(map(str, mzs)), ", ".join(map(str, l3s))

    def cve_lookup(self):
        """
        Export data to file


        :param self: Self
        :param cve_name: cve name to look up
        :return: Problem ID
        """
        url = (
            self.url
            + f"api/v2/securityProblems?securityProblemSelector=cveId%28{self.cve}%29"
        )
        problem_id = None

        try:
            logging.info(f"Looking up problem id for CVE {self.cve} in {self.name}")
            res = self._get_api_data(url)
            if res:
                for secProblem in res.get("securityProblems"):
                    if secProblem.get("status") == "OPEN":
                        if problem_id == None:
                            problem_id = secProblem.get("securityProblemId")
                        else:
                            self._write_json("./logs/secProblems", res, "w")
                            raise RuntimeError(
                                "Please contact development team, multiple open CVE id's for this CVE encountered during execution"
                            )
            else:
                print(res)
        except Exception as error:
            print("Could not resolve problem id")
            logging.error(f"Ran into problems resolving problem id: {error}")
            raise RuntimeError("Could not find related problem id")

        return problem_id

    def _validate_remediation(self, rem, valid=True):
        for pg in rem["remediationItems"]:
            if (
                pg["vulnerabilityState"] == "VULNERABLE"
                and len(pg["vulnerableComponents"]) == 0
            ):
                valid = False
        return valid

    def get_remediation(self, debug=False):
        """
        Pull remediation data:
        self.vState
        f"{self.url}api/v2/securityProblems/{cve}/remediationItems?remediationItemSelector=vulnerabilityState%28{vState}%29"
        f"{self.url}api/v2/securityProblems/{cve}/remediationItems?remediationItemSelector=vulnerabilityState(\"VULNERABLE\")"

        Logic:
        cve_id = cve_lookup(cve_num)
        output = remediation items for cve and look for only vulnerable components
        Write Output to file

        Args:
            cve ([string]): CVE number in question
        """
        try:
            cve_id = self.cve_lookup()
            url = f"{self.url}api/v2/securityProblems/{cve_id}/remediationItems?remediationItemSelector=vulnerabilityState%28{self.vState}%29"
            valid = False
            while not valid:
                rem = self._get_api_data(url)
                valid = self._validate_remediation(rem)
            if debug == True:
                self._write_json(f"{self.name}_rawrem", rem, "w")
            self.api_data = rem

        except Exception as err:
            logging.error(f"Error getting: {err} ")
            raise Exception

    def set_vState(self, vState):
        if vState in ["VULNERABLE", "RESOLVED"]:
            self.vState = vState

    def get_vState(self):
        return self.vState

    def set_cve(self, cve):
        self.cve = cve

    def get_cve(self):
        return self.cve


def read_json(input):
    """
    Read JSON
    :param self: Self
    :param id: file name
    :return: dictionary from json file
    """
    try:
        with open(f"{input}", "r") as data_file:
            data = json.load(data_file)
    except Exception as error:
        data = None

    return data
