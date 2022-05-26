import sys, time, logging, os
import requests
from reporter_utils import reporter_utils


class metrics(reporter_utils):
    def __init__(self, tenant_info, cve):
        super().__init__(tenant_info, cve)
        self._set_logging()
        self.cve = cve
        self.vulnerableComponents = None
        self.metrics_api = "api/v2/metrics"
        self.metrics_key = "total_process_affected"
        self.metrics_selector = f"?metricSelector={self.metrics_key}%3Afilter%28eq%28%22cve%22%2C%22{self.cve}%22%29%29&from=now-7d"
        self.metrics_data = None
        self.dimension = "filename"

    def _set_testing_env(self, qtype):
        self.name = "Dev"
        url = f"https://{os.getenv('Dev')}/{self.metrics_api}/{qtype}"

        if qtype == "query":
            url += self.metrics_selector

        self.headers["Authorization"] = f"Api-Token {os.getenv('DevToken')}"
        return url

    def get_components(self):
        cve_id = self.cve_lookup()
        print(f"CVE ID: {cve_id}")
        url = (
            self.url
            + f"api/v2/securityProblems/{cve_id}?fields=%2BvulnerableComponents"
        )
        self.api_data = self._get_api_data(url, debug=True)
        vulnerableComponents = {}

        for component in self.api_data["vulnerableComponents"]:
            vulnerableComponents[component["fileName"]] = (
                vulnerableComponents.get(component["fileName"], 0)
                + component["numberOfAffectedEntities"]
            )

        self.vulnerableComponents = vulnerableComponents

    def metrics_query(self, testing=False):
        if testing:
            url = self._set_testing_env("query")
        else:
            url = self.url + f"{self.metrics_api}/query/{self.metrics_selector}"

        self.metrics_data = self._get_api_data(url)
        for metric in self.metrics_data["result"][0]["data"]:
            if (
                self.dimension in metric["dimensionMap"].keys()
                and metric["dimensionMap"][self.dimension]
                not in self.vulnerableComponents.keys()
            ):
                self.vulnerableComponents[metric["dimensionMap"][self.dimension]] = 0

        print(self.vulnerableComponents)

    def ingest(self, metricdata, testing=False):
        if testing:
            url = self._set_testing_env("ingest")

        else:
            url = self.url + f"{self.metrics_api}/ingest"

        res = requests.post(url, headers=self.headers, data=metricdata)

        if res:
            print(res.status_code)
            print(res.json())
        else:
            print(res.json())
            raise RuntimeError("Ran into error pushing metrics")

    def post_metrics(self):
        self.headers["Content-Type"] = "text/plain; charset=utf-8"
        if self.vulnerableComponents != None:
            print(f"Pushing {len(self.vulnerableComponents)} metrics")
            for component, val in self.vulnerableComponents.items():
                metricdata = (
                    f"{self.metrics_key},cve={self.cve},filename={component} {val}"
                )
                print(metricdata)
                self.ingest(metricdata)

    def run(self):
        print(f"Getting metrics for {self.name}")
        self.get_components()
        self.metrics_query()
        con = input("Pres Enter to Continue or N to skip...")
        if len(con) != 0 and con == "N":
            print("Skipping!")
        else:
            print("Posting Metrics...")
            self.post_metrics()