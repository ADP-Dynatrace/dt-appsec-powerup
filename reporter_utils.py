from datetime import datetime
import os
import json
import logging
import requests
import sys
import urllib
import time
import copy
import shutil
class reporter_utils:
    def _set_logging(self):
        date = str(int(time.time()))

        if not os.path.exists(f"./logs"):
            os.makedirs(self.logs_dir)

        logging.basicConfig(
            filename=f"./logs/api_{date}.log",
            level=logging.INFO,
            format="%(asctime)s :: %(levelname)s :: %(message)s",
        )

    def _write_json(self, out_file, data, dir=None, write="a"):
        """
        Write JSON

        :param self: Self
        :param id: file name
        :param id: python dictionary
        :param id: write type defaults to append
        """
        if dir!=None:
            self._mkdir(f"./{dir}")
            out_file=f"./{dir}/{out_file}"
        
        with open(f"{out_file}.json", write) as output:
            json.dump(data, output, indent=4)
            
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

    def _mkdir(self, path):
        if not os.path.exists(path):
            os.makedirs(path)

    def _rmfile(self, path):
        if os.path.exists(path):
            os.remove(path)

    def _rmdir(self, path):
        if os.path.exists(path):
            shutil.rmtree(path)
    
    def __init__(self, tenant_info, cve):
        self._set_logging()
        logging.info("Setting up environment")
        self.logs_dir = "./logs"
        self.name = tenant_info["name"]
        self.headers = {"accept": "application/json; charset=utf-8"}
        self.headers["Authorization"] = f"Api-Token {tenant_info['tenant_token']}"
        self.url = f"https://{tenant_info['env_id']}.live.dynatrace.com/"
        self.api_data = None       
        self.vState = "VULNERABLE"  # RESOLVED
        self.retry_max = 3
        self.cve = cve
        self.tenant = tenant_info["name"]
        self.products = self._read_json("apps.json")
        self.vulnerable_technology = None
        self.entities = dict()

    def __del__(self):
        '''
        Clean up outstanding log files. 
        If timestamp is past a day, delete the log file.
        '''

        time_min=((int(time.time())) -  1 * (24 * 60 * 60) )
        
        logs = os.listdir("./logs")
        for log_file in logs:
            timestamp=int(log_file.split("_")[1].replace(".log", ""))
            if timestamp < time_min: 
                self._rmfile(f"./logs/{log_file}")
   
    def _export_entities(self):
        self._write_json(
            f"{self.name}_process_group", 
            {
                "timestamp": int(time.time()),
                **self.entities
            },
            dir=f"extracts/{self.get_vulnerable_technology()}/", 
            write="w"
        )
            
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
            logging.info(f"Call Successful for: {url}")
            api_data = res.json()
            if debug:
                curr_time =str(int(time.time()))
                logging.info("Debug enabled, writing output to file: " + f"{self.name}_{curr_time}_API_results")
                self._write_json(f"{self.name}_{curr_time}_API_results", api_data, dir="extracts", write="w")
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
            print(datetime.fromtimestamp(int(time.time())).strftime("[%m/%d/%Y %H:%M:%S]:")+res.json())
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
            print(datetime.fromtimestamp(int(time.time())).strftime("[%m/%d/%Y %H:%M:%S]:")+res.json())
            logging.error(f"Could not delete Data for {url} API call.")
            logging.error(f"API Returned: {res.json()}")
        return api_data
       
    def _validate_remediation(self, rem, valid=True):
        for pg in rem["remediationItems"]:
            if (
                pg["vulnerabilityState"] == "VULNERABLE"
                and len(pg["vulnerableComponents"]) == 0
            ):
                valid = False
        return valid
    
    def _entity_api(self, id):
        '''
        Get Entities 
        : param self: Self
        : param selector: Query Selector for Entities API
        : return: json response from API
        '''
        
        query={
            'pageSize': '4000',
            'fields': '+properties,+tags,+managementZones',
        }
        
        print(datetime.fromtimestamp(int(time.time())).strftime("[%m/%d/%Y %H:%M:%S]")+ f": Gathering Entities for {self.name}")
        entity = self._get_api_data(f"{self.url}api/v2/entities/{id}" + f"?{urllib.parse.urlencode(query)}")
        
        entity_copy = copy.deepcopy(entity)
        entity_copy.pop("entityId")
        self.entities[entity["entityId"]]=entity_copy
        self._export_entities()
        print(datetime.fromtimestamp(int(time.time())).strftime("[%m/%d/%Y %H:%M:%S]")+ f": {len(self.entities.keys())} collected")

    def _entities_api(self, selector, filter_time):
        '''
        Get Entities 
        : param self: Self
        : param selector: Query Selector for Entities API
        : return: json response from API
        '''
        
        url=f"{self.url}api/v2/entities" 
        
        query={
            'pageSize': '4000',
            'from': f'now-{filter_time}',
            'fields': '+properties,+tags,+managementZones',
            'entitySelector': selector, 

        }
        
        print(datetime.fromtimestamp(int(time.time())).strftime("[%m/%d/%Y %H:%M:%S]")+ f": Gathering Entities for {self.name}")
        
        output = self._get_api_data(
            url + f"?{urllib.parse.urlencode(query)}",
        )
                
        entities=output["entities"] 
        
        hasNextPage = "nextPageKey" in output.keys()         
        
        while hasNextPage:
            
            output = self._get_api_data(
                url+"?nextPageKey="+output["nextPageKey"],
            )
            
            entities += output["entities"]
            hasNextPage = "nextPageKey" in output.keys()
        
        for entity in entities:
            entity_copy = copy.deepcopy(entity)
            entity_copy.pop("entityId")
            self.entities[entity["entityId"]]=entity_copy
        
        
        print(datetime.fromtimestamp(int(time.time())).strftime("[%m/%d/%Y %H:%M:%S]")+ f": {len(self.entities.keys())} collected")

    def _get_pg_info(self, id):
        """
        Get Response Info

        :param self: Self
        :param id: id of pg to get info
        :return: json response from API.
        NOTE: Unix timestamp has greater values the more recent it was therefore: 
            time_min = int(time.time()) * (10 * 60)
            if timestamp > time_min -> time is less 10 minutes ago  
        """
        
        time_min=((int(time.time())) - 10*60)
        
        if len(self.entities.keys()) < 1: 
            entities = self._read_json(f"./extracts/{self.get_vulnerable_technology()}/{self.name}_process_group.json")
            if entities != None and entities["timestamp"] > time_min:
                self.entities = entities
            else:
                self.get_pgs(filter_time="72h")
            
        if id not in self.entities.keys():
            logging.info(f"PG not found: {id}")
            self._entity_api(id)
            
        return  self.entities.get(id)
        

    def _get_metadata(self, data, meta_query):
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
            if item["key"] == meta_query:
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

    def set_vState(self, vState):
        if vState in ["VULNERABLE", "RESOLVED"]:
            self.vState = vState

    def get_vState(self):
        return self.vState

    def set_cve(self, cve):
        self.cve = cve

    def get_cve(self):
        return self.cve

    def set_vulnerable_technology(self, vulnerable_technology):
        self.vulnerable_technology = vulnerable_technology

    def get_vulnerable_technology(self):
        return self.vulnerable_technology

    def set_entities(self, entities):
        self.entities = entities

    def get_entities(self):
        return self.entities

    def get_pgs(self, filter_time="72"):
        '''
            Entities API Wrapper
            :param selector: Optional Selector Query
            :param filter_time: Optional Filter Time
        '''
        self.set_entities(dict())
        
        if self.get_vulnerable_technology() == None:
            logging.error("No vulnerable technology specified")
            raise RuntimeError("No vulnerable technology specified")
            
        selector = f"type(Process_Group),softwareTechnologies({self.get_vulnerable_technology()})"
            
        self._entities_api(selector, filter_time)
            
        self._export_entities()
           
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
        Look up DT problem ID for CVE name.

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
            if res and res["totalCount"]> 0:                                
                    for secProblem in res.get("securityProblems"):
                        if secProblem.get("status") == "OPEN":
                            if problem_id == None:
                                problem_id = secProblem.get("securityProblemId")
                                self.vulnerable_technology = secProblem.get("technology")
                            else:
                                self._write_json("./logs/secProblems", res, "w")
                                raise RuntimeError(
                                    "Please contact development team, multiple open CVE id's for this CVE encountered during execution"
                                )
            else:
                logging.error(res)
       
        except Exception as error:
            print(datetime.fromtimestamp(int(time.time())).strftime("[%m/%d/%Y %H:%M:%S]:")+"Could not resolve problem id")
            logging.error(f"Ran into problems resolving problem id: {error}")
            raise RuntimeError("Could not find related problem id")

        return problem_id

    def get_remediation(self, debug=False):
        """
        Pull remediation data:
        Args:
            cve ([string]): CVE number in question
        """
        
        try:
            cve_id = self.cve_lookup()
            url = f"{self.url}api/v2/securityProblems/{cve_id}/remediationItems?remediationItemSelector=vulnerabilityState%28{self.vState}%29"
            valid = False
            while not valid:
                rem = self._get_api_data(url, debug=debug)
                valid = self._validate_remediation(rem)
                
            self.api_data=rem
             
        except Exception as err:
            logging.error(f"Error getting remediation: {err} ")
            raise RuntimeError(f"Error getting remediation: {err} ")

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
        logging.error(f"Error getting remediation: {error} ")
        data = None

    return data

if __name__ == "__main__":
    tenants = read_json("env.json")    
    env = "NonProd"
    tenant_info = {
        "name": env,
        "env_id": tenants[env]["id"],
        "tenant_token": tenants[env]["token"],
    }
    dt_reporter = reporter_utils(tenant_info, "CVE-2021-45105")
    problem_id = dt_reporter.cve_lookup()
    if problem_id != None:
        dt_reporter.get_pgs(filter_time="2h")