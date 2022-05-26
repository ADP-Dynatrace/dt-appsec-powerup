import os
import pandas as pd
from io import StringIO
import json


def read_json(input):
    """
    Read JSON

    :param self: Self
    :param id: file name
    :return: dictionary from json file
    """
    with open(f"{input}", "r") as data_file:
        data = json.load(data_file)
    return data


def excelerate(params):
    # Directory Setup
    reports_directory = os.getcwd() + "/deliverable_reports"

    if not os.path.exists(reports_directory):
        os.makedirs(reports_directory)
        print("created /deliverable_reports")

    JSONs = next(os.walk(os.getcwd() + "/remediation_reports"))[1]
    CVEs = next(os.walk(reports_directory))[1]
    for rcve in JSONs:
        if rcve not in CVEs:
            os.makedirs(f"{reports_directory}/{rcve}")
            print(f"created /deliverable_reports/{rcve}")

    reports = ["_res_remediation_reports.xlsx", "_vul_remediation_reports.xlsx"]

    # create xlsx(s)
    CVEs = next(os.walk(reports_directory))[1]
    for cve in CVEs:
        cve_directory = os.getcwd() + f"/deliverable_reports/{cve}"
        for report in reports:
            # if not os.path.exists(cve_directory + f"/{cve}{report}"):
            JSONs = next(os.walk(os.getcwd() + f"/remediation_reports/{cve}"))[2]
            JSONs = (
                (jsonfile for jsonfile in JSONs if "RESOLVED" in jsonfile)
                if report == reports[0]
                else (jsonfile for jsonfile in JSONs if "VULNERABLE" in jsonfile)
            )
            jsonlist = []
            for jsonfile in JSONs:
                jsonlist.append(jsonfile)
            if len(jsonlist) == 0:
                continue
            print(f"creating {cve_directory}/{cve}{report}")
            with pd.ExcelWriter(
                cve_directory + f"/{cve}{report}", engine="xlsxwriter"
            ) as writer:
                for jsonfile in jsonlist:
                    envjson = read_json(
                        os.getcwd() + f"/remediation_reports/{cve}/{jsonfile}"
                    )
                    dfjson = {
                        "PGI": [],
                        "URL": [],
                        "Affected Processes": [],
                        "Vulnerable Component(s)": [],
                        "Command Line Args": [],
                        "Java Jar Path": [],
                        "Host IP": [],
                        "Management Zone(s)": [],
                        "L3(s)": [],
                    }
                    for pgi, data in envjson.items():
                        if "UNKNOWN" in pgi:
                            continue
                        dfjson["PGI"].append(pgi)
                        dfjson["URL"].append(data["URL"])
                        dfjson["Affected Processes"].append(data["Processes Affected"])
                        dfjson["Vulnerable Component(s)"].append(
                            data["Vulnerable Component"]
                        )
                        dfjson["Command Line Args"].append(data["COMMAND_LINE_ARGS"])
                        dfjson["Java Jar Path"].append(data["JAVA_JAR_PATH"])
                        dfjson["Host IP"].append(data["HostIP"])
                        dfjson["Management Zone(s)"].append(data["Management Zone(s)"])
                        dfjson["L3(s)"].append(data["L3(s)"])
                    dfjson = json.dumps(dfjson)
                    df = pd.read_json(StringIO(dfjson))
                    df.to_excel(writer, sheet_name=f"{jsonfile}"[:-5])

    # create csv(s)
    for cve in CVEs:
        for report in reports:
            excel_file = reports_directory + "/" + cve + "/" + cve + report
            csv = "resolved" if report == reports[0] else "vulnerable"
            try:
                all_sheets = pd.read_excel(excel_file, sheet_name=None)
            except:
                continue
            sheets = all_sheets.keys()

            for sheet_name in sheets:
                sheet = pd.read_excel(excel_file, sheet_name=sheet_name)
                if not os.path.exists(f"{reports_directory}/{cve}/{csv}"):
                    os.makedirs(f"{reports_directory}/{cve}/{csv}")
                    print(f"created {reports_directory}/{cve}/{csv}")
                sheet.to_csv(
                    "%s/%s/%s/%s.csv" % (reports_directory, cve, csv, sheet_name),
                    index=False,
                )
