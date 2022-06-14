# Dynatrace AppSec Powerup V1.5
Automated Security Reporting Utility for for Dynatrace Security

## Features
Built with log4j in mind, the remediator provides the ability to:
1. Tag CVE's within a tenant
2. Manage CVE's in the form of Management Zones, Dashboards
3. Build Reports on CVE's across Environments

With the CVE tagger `auto_tag` and CVE configuratior `push_configs` users can automatically create tags for selected CVE's, allowing for dashboarding, charts, reporting, and many more insights from an AppSec perspective to be gained from a customer's deployment. Tags will be created for process groups in the target environment with the CVE id as the identifier, allowing for sorting by CVE in the various search filters and views (Process groups page, data explorer, dashboard dynamic filters, etc.). With the configurator, services and hosts of vulnerable process groups will be tagged as well, allowing for extended visibility into what is vulnerable. This comes with a management zone for each CVE as well, with vulnerablility overview dashboards.

The CVE Metrics Tool `metrics` adds to the dashboards functionality, where a custom metric for the # of vulnerable processes can be charted with each execution of the command.

The Remediation Reporter expands on the value to be gained from AppSec through generating JSON files per CVE, even for each tenant in a multi-tenant customer environment. As of the current version, the JSON contains:
1. process groups, a url leading to the process group in DT,
2. the number of vulernable processes with respective vulnerable components,
3. command line arguments run,
4. IP(s) of the host the vulnerable processe(s) were found,
5. managment zones,
6. and application owners

Running one more command, `to_excel` will create the `deliverable_reports` directory containing .xlsx and corresponding .csv reports respective to vulnerability status and environment. Going forward, reports will be automatically supported in only .csv for the end user.

## Usage
### **Setup**
#### **Python Requirements:**
**pip** - install via operating system specific method

Install all requirements -  `pip install -r requirements.txt`

*Note: in order to have L3 Leaders matched with management zones, a mapping needs to be provided in the root directory as `apps.json`. Please contact the consulants for a copy.*

By default, the available CVEs and tenants are listed in the `tenants` and `cves` lists in `./configs/config.json`. Adding to each list will include the tenant/CVE in no-parameter commands.

An .env file must be placed in the root directory containing the names of the tenant environments identical to what is listed in `./configs/config.json`. A template has been provided in the form of `.envtemplate`.

1. Open the `.envtemplate` file. The default tenants have already been inserted into the file, only needing the proper values for the tenant id and tenant token, i.e. **NonProd=** and **NonProdToken=**.

2. For each tenant, i.e. NonProd, and take the id from the Dynatrace tenant environment url ***xxxxxxxx***.live.dynatrace.com and place the value within the quotation marks for the tenant name(**NonProd=**).

3. Navigate back to the tenant, and under the left sidebar under *Manage* click *Access Token*. From here, enter a token name, and select the following scopes: 
    - `entities.read`
    - `entities.write`
    - `metrics.ingest`
    - `metrics.read`
    - `metrics.write`
    - `securityProblems.read`
    - `securityProblems.write`

4. Generate the token and store in a secure directory. Copy the token and place the value within the quotation marks for the tenant token(**ProdToken=**). Repeat steps 2-4 for any tenants added to `./configs/config.json`, keeping the same tenant name when editing the `.envtemplate` file.

5. Save and rename the file to `.env`.

6. Finally, with a mapping file `apps.json` in the directory all features will be set up for use.

From here, the remediation reporter will be able to interact with each tenant now that the proper permissions are obtained. Use cases for each function are detailed [below](#tasks).  
Additional help can be found with the `python3 main.py help` command. Depending on your python installation, `python3` can be replaced with `python`.

### **Running the Tagger**
The tagger can be run with the following command format:

    python3 main.py auto_tag --cve [CVE] --env [ENV]

where (no param will automatically select all available):

`[CVE]` refers to CVE ID (i.e. CVE-2021-45046)

`[ENV]` refers to specific Tenant (configured in .env file)

After the command is run, inside the environment there will be a manual tags created with the CVE as the key and vulnerable as the value. Subsequent runs will attempt to clear out older tags before retagging.

### **Running the Configuratior**

The configuratior can be run with the following command format:

    python3 main.py push_configs --cve [CVE] --env [ENV]

where:

`[CVE]` refers to CVE ID (i.e. CVE-2021-45046)

`[ENV]` refers to specific Tenant (configured in .env file, optional, none results in all)

The command creates 3 types of configurations per tenant/cve combination. Auto Tags are created and can be searched by the CVE name to link vulnerable services and hosts to vulnerable process groups. Management Zones are created to group the vulnerable entities and a dashboard is pushed to the tenant for information overview. These configurations only need to be created once, as they will automatically account for any newly tagged processes from the tagger.

### **Running the Metrics Tool**

The push metrics command can be run with:

    python3 main.py metrics --cve [CVE] --env [ENV]

where (no param will automatically select all available):

`[CVE]` refers to CVE ID (i.e. CVE-2021-45046)

`[ENV]` refers to specific Tenant (configured in .env file)

Running the command queries the vulnerablity status in custom metric form, and allows for the current vulnerable data to be pushed for use in a custom metric.
### **Running the Reporter**
The reporter can be run with the following command format:
     
     python3 main.py rstatus --cve [CVE] --env [ENV] --v [VSTATE]

where: (no param will automatically select all available)

`[CVE]` refers to CVE ID (i.e. CVE-2021-45046)

`[ENV]` refers to specific Tenant (configured in .env file)

`[VSTATE]` refers to specific vulnerability status (vulnerable or resolved) 


Each JSON file created by the reporter lays out the process group instances that are vulnerable to a CVE. If none are found in a tenant environment, then no JSON will be created.

To create a report files, run the `python main.py to_excel` command to create .xlsx files for each cve, one for resolved and one for vulnerable with each sheet of the respective .xlsx pertaining to a tenant. Then, .csv files are created for each sheet/tenant as well. Each execution of the script will create/overwrite with a new directory/files, but will otherwise not initially delete the previously created directory/files.

## Tasks

### **Remediation Report**

***As of V1.5, the single script `run.sh` will run the remedation report and create the csv excel files.***

The creation of a set of reports in .csv format can be done with two commands, `rstatus` and `to_excel`. The most common use case would be to create a report of all the vulnerable processes across all default tenants. For best results, clearing the `remediation_reports` and `deliverable_reports` directories periodically before running will avoid any possible data mismatches.

1. Running the following `python main.py --vstatus vulnerable` will begin iterating through the list of tenants for each CVE.

2. Once complete, the `remediation_reports` directory will contain a folder for each CVE, each CVE folder containing a JSON file for each tenant.

3. Running `python main.py to_excel` then initiates the report creation. If `deliverable_reports` is not present, it will be created, before generating .xlsx files for each cve, one for resolved and one for vulnerable (if either type of jsons are present) in each created CVE folder. Finally, .csv files for each of the sheets in each .xlsx are created, housed in either a `resolved` or `vulnerable` directory.

### **Tenant Vulnerablity Monitoring**
Tagging all the vulnerable processes in each tenant can be accomplished with `auto_tag` and `push_configs`, with the latter only needed to run once per CVE for each tenant.

1. Run `python main.py auto_tag` to tag all default CVEs in all default tenants. This can be run periodically to keep an updated list.

2. Independently from the tagger, `python main.py push_configs --cve [CVE OF YOUR CHOICE]` (i.e. `python main.py push_configs --cve CVE-2021-44832`) will create automatic tags, managment zones, and dashboards for each CVE. Running once will set up for the tenant, and subsequent runs will detect the already exisiting configurations and skip. All will be named after the CVE they were created for.

The `metrics` affords the additional metric **total_process_affected**, which, as the name suggests, measures the current total number of processes that are affected by a vulnerability. In the data explorer, this can be placed on a dashboard or even just trigged as an alert.

1. Run `python main.py metrics` to query the the list of CVE/tenant combo. Follow the prompts to either skip or push the collected metric to the respective tenant. Afterwards, the metric **total_process_affected** should show in the tenant.


## Limitations
- No GUI, coming in V2...
## Default Tracked CVE's:
+ CVE-2017-5645
+ CVE-2021-44228
+ CVE-2021-45046
+ CVE-2021-45105
+ CVE-2021-4104
+ CVE-2021-44832
+ CVE-2022-21724
+ CVE-2022-27772
+ CVE-2022-22965
+ CVE-2022-22963
+ CVE-2022-22947
