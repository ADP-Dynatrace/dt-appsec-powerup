import json
from datetime import datetime
import logging
import time
from time import sleep
import os
from reporter_utils import reporter_utils


class remediation_reporter(reporter_utils):
    def __init__(self, tenant_info, cve):
        super().__init__(tenant_info, cve)
        self.filtered_data = None

    def _get_extra(self, entity_id, data):
        """
        Pull process group data

        Args:
            entity_id: id of process group
            data: filtered data to be added to
        """
        res = self._get_pg_info(entity_id)
        meta_values = ["COMMAND_LINE_ARGS", "JAVA_JAR_PATH"]
        tag_values = ["HostIP"]
        data["Management Zone(s)"] = "Unknown"
        data["L3(s)"] = "Unknown"
        if res != None:
            for meta_val in meta_values:
                data[meta_val] = self._get_metadata(res, meta_val)  # can be expanded
            for tag_val in tag_values:
                data[tag_val] = self._get_tag(res, tag_val)
            data["Management Zone(s)"], data["L3(s)"] = self.get_mzs_l3s(res)
        else:
            for meta_val in meta_values:
                data[meta_val] = "Nothing Found"  # can be expanded

            logging.info(f"No entity info found for {entity_id}")
        return data

    def _parser(self):
        """
        Parse the raw data and create a new dictionary for writting to json file
        vState
        Args:
            parser ([dict]): [:dict filtered dictionary]
        """
        filtered_data = {}
        
        for pg in self.api_data["remediationItems"]:
            name = pg["name"] 
            number_of_affected = len(pg["remediationProgress"]["affectedEntities"])
            
            total = (len(pg["remediationProgress"]["unaffectedEntities"]) + number_of_affected)
            
            vulnerable_components = ""
            num_of_vuln_comp = len(pg["vulnerableComponents"])
            
            for component in range(num_of_vuln_comp):
                component_name=pg['vulnerableComponents'][component]['displayName']
                if component != num_of_vuln_comp - 1:
                    vulnerable_components += (f"{component_name},")
                else:
                    vulnerable_components += (component_name)

            filtered_data[name] = {
                "URL": f"{self.url}#processgroupdetails;id={pg['id']}",
                "Processes Affected": f"{number_of_affected}/{total}",
                "Vulnerable Component": vulnerable_components,
            }

            filtered_data[name] = self._get_extra(
                pg["id"], filtered_data[name]
            )
                    
        print(datetime.fromtimestamp(int(time.time())).strftime("[%m/%d/%Y %H:%M:%S]: ") + 
              f"Total Process Groups for {self.tenant}: {len(filtered_data.keys())}")

        self.filtered_data = filtered_data

    def _export(self):
        """
        Write filtered data to file

        Args:
            filtered_data ([type]): [description]
        """
        self._mkdir(f"./remediation_reports/{self.cve}")
        print(datetime.fromtimestamp(int(time.time())).strftime("[%m/%d/%Y %H:%M:%S]:")+f"Writing {self.cve} Remediation Report for {self.name} ")
        logging.info(f"Writing {self.cve} Remediation Report for {self.name}")
        self._write_json(
            f"{self.name}_{self.vState}",
            self.filtered_data,
            dir=f"remediation_reports/{self.cve}/",
            write="w"
        )

    def generate_report(self):
        """
        Generate report for a given cve
        Logic:

        Args:
            cve ([string]): CVE for open problem
        """
        self.get_remediation()

        if len(self.api_data["remediationItems"]) > 0:
            self._parser()
            self._export()
        else:
            print(datetime.fromtimestamp(int(time.time())).strftime("[%m/%d/%Y %H:%M:%S]: ") + 
              f"No remediation items found, skipping report {self.cve} for {self.tenant}")