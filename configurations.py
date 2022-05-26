import os
import logging
from time import sleep
from reporter_utils import reporter_utils


class configurator(reporter_utils):
    def __init__(self, tenant_info, cve):
        super().__init__(tenant_info, cve)          
        self.config_template = None
        self.headers["Content-Type"] = "application/json"
        self.config = None
        self.cve_id = self.cve_lookup()
        self.configs={
            "at": "api/config/v1/autoTags",
            "mz": "api/config/v1/managementZones",
            "dashboard": "api/config/v1/dashboards"
        }

    def get_config(self):
        url = self.url + self.configs[self.config]
        if self.config == 'dashboard':
            config_list = self._get_api_data(url)["dashboards"]
        elif self.config in self.configs.keys():
            config_list = self._get_api_data(url)["values"]
        else:
            raise ValueError("Invalid config")

        output = False
        for config in config_list:
            if config["name"] == self.cve:
                output = True
        return output
        
    def _post_config(self, testing=False):
        if testing: 
            self._write_json(f"new_{self.config}", self.config_template, "w")
        else:            
            url = self.url + self.configs[self.config]
            print(f"Pushing configuration {self.config} to {self.name} ")
            self._post_api_data(url, self.config_template)

    def auto_config(self, testing=False):
        if not self.get_config():
            self.config_template = self._read_json(f"./configs/{self.config}.json")
            self.config_template["name"] = self.cve
            self.config_template["rules"][0]["conditions"][0]["comparisonInfo"]["value"]["key"]=self.cve
            self._post_config(testing)
            
        else:
            print("Skipping Configuration")

    def _set_dashboard(self, testing=False):
        self.config_template["dashboardMetadata"]["name"] = self.cve

        for tile in self.config_template["tiles"]:
            if tile["tileType"] == "HOSTS": 
                tile["filterConfig"]["filtersPerEntityType"]["HOST"]["AUTO_TAGS"]=[self.cve]
            
            elif tile["tileType"] == "MARKDOWN":
                if "##[Vulnerability Overview]" in tile["markdown"]:
                    tile["markdown"] = f"##[Vulnerability Overview]({self.url}ui/security/vulnerabilities/{self.cve_id}?gtf=-2h&gf=all)\n\n"
                elif "##[NVD Overview]" in tile["markdown"]:
                    tile["markdown"] = f"##[NVD Overview](https://nvd.nist.gov/vuln/detail/{self.cve})\n\n\n"
                elif "Remediation Tracker" in tile["markdown"]:
                    tile["markdown"] = f"###[Process Group Overview Remediation Tracker]({self.url}ui/security/vulnerabilities/{self.cve_id}/remediation-tracking?gtf=-2h&gf=all)\n"
                elif "Internet Exposure" in tile["markdown"]:
                    tile["markdown"] = f"###[Public Internet Exposure]({self.url}#newprocessessummary;gtf=-2h;gf=all;EXPOSING_SECURITY_PROBLEM={self.cve_id})"
                else:
                    print("skipping formating markdown")
            
            elif tile["tileType"] == "DATA_EXPLORER":
                for query in tile["queries"]:
                    for filter  in query["filterBy"]["nestedFilters"]:
                        for criteria in filter["criteria"]:
                            criteria["value"] = self.cve

            elif "managementZone" in tile["tileFilter"].keys():
                    tile["tileFilter"]["managementZone"]["id"] = self.mzID
                    tile["tileFilter"]["managementZone"]["name"] = self.mzName
            else:
                print(f"Unknown Tile: {tile}")
            
    def dashboard(self, testing=False):
        if not self.get_config():
            self.config_template = self._read_json("./configs/dashboard.json")
            url = self.url + self.configs["mz"]
            mz_list = self._get_api_data(url)
            self.mzID = None
            for mz in mz_list["values"]:
                if mz["name"] == self.cve:
                    self.mzName = mz["name"]
                    self.mzID = mz["id"]
            
            self._set_dashboard()
            self._post_config()
        else:
            print(f"Skipping Configuration: {self.config}")

    def run(self, config):
        
        if config in self.configs.keys() and config == "dashboard":
            print("Attempting to push dashboads")
            self.config=config
            self.dashboard()

        elif config in self.configs.keys():
            self.config = config
            self.auto_config()
        
        else:
            raise RuntimeError("Invalid config")
