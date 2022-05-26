import json
import datetime
import logging
from time import sleep
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
        res = self._get_entity_info(entity_id)
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
        numOfPGs = len(self.api_data.get("remediationItems"))
        attempts = 0
        print(
            f"Running Reports for : {self.name} \nEstimated number of PGs: {numOfPGs}"
        )

        for pg in range(numOfPGs):
            try:
                if pg % 100 == 0:
                    print(f"Number of Process Groups parsed: {pg}")
                    sleep(10)

                item = self.api_data.get("remediationItems")[pg]
                name = item.get("name")

                numofAffected = len(item["remediationProgress"]["affectedEntities"])
                total = (
                    len(item["remediationProgress"]["unaffectedEntities"])
                    + numofAffected
                )
                vulnerableComponents = ""
                numOfVulComp = len(item["vulnerableComponents"])
                for itter in range(numOfVulComp):
                    if itter != numOfVulComp - 1:
                        vulnerableComponents += (
                            f"{item['vulnerableComponents'][itter]['displayName']},"
                        )
                    else:
                        vulnerableComponents += (
                            f"{item['vulnerableComponents'][itter]['displayName']}"
                        )

                filtered_data[name] = {
                    "URL": f"{self.url}#processgroupdetails;id={item.get('id')}",
                    "Processes Affected": f"{numofAffected}/{total}",
                    "Vulnerable Component": vulnerableComponents,
                }

                filtered_data[name] = self._get_extra(
                    item.get("id"), filtered_data[name]
                )

            except Exception as error:
                if attempts != self.retry_max:
                    error_msg = f"Failed to create report due to {error} \nNext attempt in 1 minute"
                    print(error_msg)
                    logging.error(error_msg)

                    sleep(61)
                    pg -= 1
                    attempts += 1
                else:
                    logging.error(f"Error {error}")
                    raise Exception

        print(f"Total Process Groups: {len(filtered_data)}")

        self.filtered_data = filtered_data

    def _export(self):
        """
        Write filtered data to file

        Args:
            filtered_data ([type]): [description]
        """
        if self.filtered_data != {}:
            date = datetime.datetime.now().strftime("%m%d%Y")
            self._mkdir(f"./remediation_reports/{self.cve}")
            print(f"Writing Remediation Report for {self.name} ")
            logging.info(f"Writing Remediation Report for {self.name}")
            self._write_json(
                f"./remediation_reports/{self.cve}/{self.name}_{self.vState}",
                self.filtered_data,
                "w",
            )
        else:
            self._rmfile(
                f"./remediation_reports/{self.cve}/{self.name}_{self.vState}.json"
            )

    def generate_report(self):
        """
        Generate report for a given cve
        Logic:

        Args:
            cve ([string]): CVE for open problem
        """
        self.get_remediation()
        self._parser()
        self._export()
