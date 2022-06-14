"""
NOTE: Dated for deprecation in V2
"""

import os
import pandas as pd
from io import StringIO
import json
import shutil


def rmdir(path):
    if os.path.exists(path):
        shutil.rmtree(path)


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


def make_reports_dir(path):
    if not os.path.exists(path):
        os.makedirs(path)
        print(f"created {path}")


def to_excel(params):
    # Directory Setup
    reports_directory = os.getcwd() + "/deliverable_reports"

    rmdir(reports_directory)
    try:
        json_dir = next(os.walk(os.getcwd() + "/remediation_reports"))[1]
    except Exception as err:
        raise RuntimeError("Remediation Reports Directory Does not exist")

    make_reports_dir(reports_directory)

    for rcve in json_dir:
        if rcve not in next(os.walk(reports_directory))[1]:
            os.makedirs(f"{reports_directory}/{rcve}")
            print(f"created /deliverable_reports/{rcve}")

    reports = ["_res_remediation_reports.xlsx", "_vul_remediation_reports.xlsx"]

    # create xlsx(s)
    CVEs = next(os.walk(reports_directory))[1]

    for cve in CVEs:
        cve_directory = os.getcwd() + f"/deliverable_reports/{cve}"
        for report in reports:
            # if not os.path.exists(cve_directory + f"/{cve}{report}"):
            json_dir = next(os.walk(os.getcwd() + f"/remediation_reports/{cve}"))[2]
            json_dir = (
                (jsonfile for jsonfile in json_dir if "RESOLVED" in jsonfile)
                if report == reports[0]
                else (jsonfile for jsonfile in json_dir if "VULNERABLE" in jsonfile)
            )
            jsonlist = []
            for jsonfile in json_dir:
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
                        "PG": [],
                        "URL": [],
                        "Affected Processes": [],
                        "Vulnerable Component(s)": [],
                        "Command Line Args": [],
                        "Java Jar Path": [],
                        "Host IP": [],
                        "Management Zone(s)": [],
                        "L3(s)": [],
                    }
                    for pg, data in envjson.items():
                        if "UNKNOWN" in pg:
                            continue
                        dfjson["PG"].append(pg)
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

            except Exception as err:
                if isinstance(err, FileNotFoundError):
                    continue
                else:
                    print(err)

            sheets = all_sheets.keys()
            for sheet_name in sheets:
                sheet = pd.read_excel(
                    excel_file, sheet_name=sheet_name, engine="openpyxl"
                )
                if not os.path.exists(f"{reports_directory}/{cve}/{csv}"):
                    os.makedirs(f"{reports_directory}/{cve}/{csv}")
                    print(f"created {reports_directory}/{cve}/{csv}")
                sheet.to_csv(
                    "%s/%s/%s/%s.csv" % (reports_directory, cve, csv, sheet_name),
                    index=False,
                )

    rmdir("./remediation_reports")
