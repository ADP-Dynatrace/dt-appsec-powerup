import os
import sys
from dotenv import load_dotenv
from tagger import tag_generator
from reporter_utils import read_json
from remediation_reporter import remediation_reporter
from configurations import configurator
from metrics import metrics
from excel_csv_reporter import to_excel

load_dotenv()
tenants = read_json("./configs/config.json")["tenants"]
cves = read_json("./configs/config.json")["cves"]
risk_levels = ["exposed", "affected"]

vstates = ["VULNERABLE", "RESOLVED"]

help_msg = f"""
python3 main.py <command> <args>

Description 
    Generate a report based off a risk level, environment and CVE

Commands [Mandatory]:
    rstatus: generate a report based on a risk level and an environment
    auto_tag: generates tags based on a run report of a risk level and environment  
    cve_lookup: Provides DT Problem id for a given CVE
    reset_tags: Removes tags for provided cve and environment
    push_configs: Creates Tags, Management Zones, & dashboards for given CVE
    metrics: Pushes Metrics based on vulnerable components

Args [Mandatory]:
    --env environment, possible values are: {*tenants,} or "all"
    --cve cve id ex: CVE-2021-45046

Args [Optional]:
    --rl risk level, possible values are: exposed, affected
    --v vulnerability state

Examples: 
    python3 main.py rstatus --cve CVE-2021-45046 --env NonProd --v resolved
    python3 main.py rstatus --cve CVE-2021-45046 --env NonProd
    python3 main.py rstatus --cve CVE-2021-45046 --v resolved
    python3 main.py rstatus --cve CVE-2021-45046
    python3 main.py rstatus
    python3 main.py cve_lookup --cve CVE-2021-45046
    python3 main.py auto_tag --cve CVE-2021-45046
    python3 main.py auto_tag
    python3 main.py reset_tags --cve CVE-2021-45046 --env NonProd
    python3 main.py push_configs --cve CVE-2021-4104
    python3 main.py metrics
    
"""


def args_parse(args):
    """
    Parses the arguments passed to the python script when it is run

            Parameters:
                array of arguments passed from the command line

            Returns:
                    args_dict (dict): Dictionary of command line arguments
    """
    args_dict = dict()

    if "--rl" in args:
        args_dict["rl"] = args[args.index("--rl") + 1]
    else:
        args_dict["rl"] = None

    if "--env" in args:
        args_dict["env"] = args[args.index("--env") + 1]
    else:
        args_dict["env"] = None

    if "--cve" in args:
        args_dict["cve"] = args[args.index("--cve") + 1]
    else:
        args_dict["cve"] = None

    if "--v" in args:
        args_dict["vstate"] = args[args.index("--v") + 1]
    else:
        args_dict["vstate"] = None
    return args_dict


def init_class(env, class_type, cve=None):
    """
    Initialize the desired class: tag_generator, configurator, metrics, remediation_reporter,

            Parameters:
                env: Dynatrace Environment
                class_type: Class type to be created
                cve: CVE that is to be used for execution

            Returns:
                    output (dict): Will either return the initialized class or the executable will terminate
    """
    output = None
    if env in tenants:
        tenant_info = {
            "name": env,
            "env_id": os.getenv(env),
            "tenant_token": os.getenv(f"{env}Token"),
        }
    class_types = {
        "tagger": tag_generator,
        "configure": configurator,
        "metrics": metrics,
        "rem": remediation_reporter,
    }
    if class_type in class_types.keys() and cve != None:
        dt_class = class_types[class_type](tenant_info, cve)
        output = dt_class
    else:
        print("No class available")
        sys.exit(1)
    return output


def resolve_cve(cve):
    """
    Resolve the CVE by obtaining the DT Problem ID that maps to the external CVE

            Parameters:
                cve: CVE that is to be used for execution

            Returns:
                    problem_id (string): Returns the DT Problem ID
    """
    dt_report = init_class(tenants[0], "rem", cve)
    problem_id = dt_report.cve_lookup(cve)
    return problem_id


def get_cves(params):
    """
    Gather all environments impacted by CVE

            Parameters:
               params: Command Line Parameters

            Returns:
                     cve_dict (dict): Dictionary of environments and the respective DT Problem ID
    """
    print(f"Getting all environments with valid CVE id: {params['cve']}")
    cve_dict = {}
    for env in tenants:
        dt_report = init_class(env, "rem", params["cve"])
        cve_id = dt_report.cve_lookup()
        cve_dict[env] = cve_id
    return cve_dict


def cve_lookup(params):
    """
    Lookup the DT ENV ID for a CVE

            Parameters:
               params: Command Line Parameters

            Returns:
                     None
    """
    cve_ids = get_cves(params)
    for env, cve_id in cve_ids.items():
        print(f"Environment: {env}, id: {cve_id}")


def gen_tag(env, cve):
    """
    Generate the tags for envrionment based on a provided CVE

            Parameters:
               env: Environment to create tags in
               cve: CVE to generate tags for

            Returns:
                     None
    """
    dt_tagger = init_class(env, "tagger", cve)
    dt_tagger.tag()


def remediation_report(env, cve, vstate=None):
    """
    Generate remediation report for envrionment based on a provided CVE

            Parameters:
               env: Environment to create tags in
               cve: CVE to generate tags for

            Returns:
                     None
    """
    rem_reporter = init_class(env, "rem", cve)
    if vstate is not None:
        rem_reporter.set_vState(vstate.upper())
        print(f"vState: {rem_reporter.get_vState()}")
    else:
        print(f"No vState selected using default")
    rem_reporter.generate_report()


def all_envs(params, fn):
    """
    Generate remediation reports or tags for all envrionments based on a provided CVE

            Parameters:
               params: Command line paramaters
               fn: Function to be used

            Returns:
                     None
    """
    cve_ids = get_cves(params)
    for env in cve_ids:
        if fn == "gt":
            gen_tag(env, params["cve"])
        elif fn == "rr":
            if params["vstate"] == None:
                for vstate in vstates:
                    remediation_report(env, params["cve"], vstate)
            else:
                remediation_report(env, params["cve"], params["vstate"])
        else:
            print("Unknown function")


def auto_tag(params):
    """
    Wrapper Function for genearting tags

            Parameters:
               params: Command line paramaters

            Returns:
                     None
    """
    if params["cve"] == None and params["env"] == None:
        for cve in cves:
            print(cve)
            params["cve"] = cve
            all_envs(params, "gt")

    if params["env"] == None:
        all_envs(params, "gt")

    else:
        gen_tag(params["env"], params["cve"])


def rstatus(params):
    """
    Wrapper Function for genearting remediation reports

            Parameters:
               params: Command line paramaters

            Returns:
                     None
    """
    if params["cve"] == None and params["env"] == None:
        for cve in cves:
            params["cve"] = cve
            all_envs(params, "rr")

    elif params["env"] == None:
        all_envs(params, "rr")

    else:
        remediation_report(params.get("env"), params.get("cve"), params.get("vstate"))


def push_configs(params):
    """
    Create configurations in Dynatrace, specifically Management Zone (mz) for CVE, Auto Tags (at) for CVE, Dashboard for CVE.
    If no CVE and ENV are provided, all cves and envs from the configuration file will be used,
    If no CVE but an ENV is provided, all cves from the configuration and the specified environment will be used, similar for no ENV but CVE

            Parameters:
               params: Command line paramaters

            Returns:
                     None
    """
    print(params)
    if params["cve"] == None and params["env"] == None:
        for cve in cves:
            params["cve"] = cve
            cve_ids = get_cves(params)

            for env in cve_ids:
                if cve_ids[env] != None:
                    dt_configurator = init_class(env, "configure", cve)
                    dt_configurator.run("mz")
                    dt_configurator.run("at")
                    dt_configurator.run("dashboard")

    elif params["env"] == None and params["cve"] != None:
        cve_ids = get_cves(params)

        for env in cve_ids:
            if cve_ids[env] != None:
                dt_configurator = init_class(env, "configure", params["cve"])
                dt_configurator.run("mz")
                dt_configurator.run("at")
                dt_configurator.run("dashboard")
    else:
        dt_configurator = init_class(params["env"], "configure", params["cve"])
        dt_configurator.run("mz")
        dt_configurator.run("at")
        dt_configurator.run("dashboard")


def push_metrics(params):
    """
    Push metrics to Dynatrace based on CVE.
    If no CVE and ENV are provided, all cves and envs from the configuration file will be used,
    If no CVE but an ENV is provided, all cves from the configuration and the specified environment will be used, similar for no ENV but CVE

            Parameters:
               params: Command line paramaters

            Returns:
                     None
    """
    if params["cve"] == None and params["env"] == None:
        for cve in cves:
            params["cve"] = cve
            cve_ids = get_cves(params)

            for env in cve_ids:
                if cve_ids[env] != None:
                    dt_metrics = init_class(env, "metrics", cve)
                    dt_metrics.run()

    elif params["env"] == None and params["cve"] != None:
        cve_ids = get_cves(params)
        for env in cve_ids:
            if cve_ids[env] != None:
                dt_metrics = init_class(env, "metrics", params["cve"])
                dt_metrics.run()

    elif params["env"] != None and params["cve"] == None:
        for cve in cves:
            params["cve"] = cve
            cve_ids = get_cves(params)

            if cve_ids[params["env"]] != None:
                dt_metrics = init_class(params["env"], "metrics", params["cve"])
                dt_metrics.run()

    else:
        dt_metrics = init_class(params["env"], "metrics", params["cve"])
        dt_metrics.run()


def help():
    """
    Prints help message to terminal
        Params:
            None
        Output:
            None
    """
    print(help_msg)


def run():
    """
    Takes in arguments and uses correct "commmand"
        Params:
            None
        Output:
            None
    """
    commands = {
        "rstatus": rstatus,
        "to_excel": to_excel,
        "auto_tag": auto_tag,
        "cve_lookup": cve_lookup,
        "push_configs": push_configs,
        "metrics": push_metrics,
        "help": help,
        "--h": help,
    }

    command = sys.argv[1]
    if command in commands:
        if command == "help" or command == "--h":
            commands[command]()
        else:
            params = args_parse(sys.argv)
            commands[command](params)
    else:
        print(f"Unknown Command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) >= 2:
        run()
    else:
        help()
