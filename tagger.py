import os
import logging
from time import sleep
from reporter_utils import reporter_utils


class tag_generator(reporter_utils):
    def __init__(self, tenant_info, cve):
        super().__init__(tenant_info, cve)
        self.headers["Content-Type"] = "application/json"
        self.impact_types = ["vulnerable"]
        self.entity_types = ["Host", "PROCESS_GROUP_INSTANCE", "PROCESS_GROUP"]
        self._set_logging()

    def _post_tag(self, entity_id):
        """
        API Calls for Posting Tags

        :param p1: Self
        :param p2: Entity ID
        :param p3: Data - Security Risk
        - Tag Example: 'CVE-2021-4104': 'vulnerable'
        Algo:
            - Verify if tag exists
            - If tag does not exist create one
        :return: bool or None depending on api output
        """
        url = self.url + f"api/v2/tags?entitySelector=entityId({entity_id})"
        data = {"tags": [{"key": self.cve, "value": "vulnerable"}]}
        verify = self._get_api_data(url + f",tag({self.cve})")
        output = False
        if verify.get("totalCount") == 0:
            output = self._post_api_data(url, data) != "None"
            logging.info(f"Successfully Posted Tag for {entity_id}")
        else:
            logging.info(f"Skipping Tag for {entity_id}")
        return output

    def _delete_tag(self, entity_id):
        url = (
            self.url
            + f"api/v2/tags?entitySelector=entityId({entity_id})&key={self.cve}&deleteAllWithKey=true"
        )

        return True if self._delete_api_data(url) != "None" else False

    def _get_entities(self, impact_type, entity_type):
        """
        Get all entities with a tag
        :param p1: Self
        :param impact_type: affected or exposed for directory
        :param entity_type: Host or PGI
        Algo:
            - Fetch entities with tag using API
                - If successfull:
                    - save to array
                - Else:
                    - log failure
        :return: array of entities with tag
        """
        entities = []
        if impact_type in self.impact_types and entity_type in self.entity_types:
            url = (
                self.url
                + f"api/v2/entities?pageSize=12000&entitySelector=tag%28%22{self.cve}:{impact_type}%22%29%2Ctype%28%22{entity_type}%22%29"
            )
            res = self._get_api_data(url)

            if res:
                entities = res["entities"]
            else:
                logging.error(
                    f"API Call for entities tagged with {self.cve}:{impact_type} unsuccessful"
                )

        return entities

    def _reset_tags(self, impact_type, entity_type):
        """
        Reset all tags for a given impact type and entity type

        :param p1: Self
        :param impact_type: affected or exposed
        :param input: Host, PGI
        Algo:
            - Get all entities that have a tag that matches desired value
            - For each entity:
                - Delete Tag
            - Update all entities that have a tag
            - If list is empty
                - pass
            - Else:
                - Something happened fail with runetime error

        """
        entities = self._get_entities(impact_type, entity_type)
        attempts = 0

        for entity_cnt in range(len(entities)):
            entity = entities[entity_cnt]
            self._delete_tag(entity["entityId"])
            logging.info(f"Removed tag for entity {entity['entityId']}")

        entities = self._get_entities(impact_type, entity_type)

        if len(entities) == 0:
            print(f"Successfully Removed All Tags for {self.cve}:{impact_type}")
            logging.info(f"Successfully Removed All Tags for {self.cve}:{impact_type}")
        else:
            print(
                "Skipped empty process groups instances, check logs for additional info"
            )
            logging.info("Skipped empty process groups instances:")
            logging.error(entities)

    def _reset_all_tags(self):
        for entity_type in self.entity_types:
            for risk_level in self.impact_types:
                self._reset_tags(risk_level, entity_type)

    def tag(self):
        """
        Tag all PGs that are vulnerable for a given CVE

        :param p1: Self
        :param cve: CVE Id that tags are required for
        Algo:
            - Get all entities that have a tag that matches desired value
            - For each entity:
                - Delete Tag
            - Update all entities that have a tag
            - If list is empty
                - pass
            - Else:
                - Something happened fail with runetime error

        """
        print(self.cve)
        self.get_remediation(self.cve)
        num_of_pgs = len(self.api_data.get("remediationItems"))
        pg_ids = []
        attempts = 0

        print(f"Reseting tags for {self.cve} in {self.name}")
        self._reset_all_tags()

        for pg_count in range(num_of_pgs):
            pg = self.api_data.get("remediationItems")[pg_count]
            if pg.get("id") not in pg_ids:
                pg_ids.append(pg.get("id"))

        print(f"Tagging {len(pg_ids)} PGs in {self.name}")

        for pg_id_count in range(len(pg_ids)):
            try:
                pg_id = pg_ids[pg_id_count]
                if pg_id_count > 1 and pg_id_count % 100 == 0:
                    sleep(10)
                    print(f"Tagged {pg_id_count + 1}/{len(pg_ids)} PGs")
                    logging.info(f"Tagged {pg_id_count + 1}/{len(pg_ids)} PGs")

                self._post_tag(pg_id)
            except Exception as error:
                if attempts != self.retry_max:
                    logging.error(f"Ran into Error {error}, trying again in 1 minute")
                    sleep(60)
                    pg_id_count -= 1
                    attempts += 1
                else:
                    raise RuntimeError("Could not proceed!")

        print("Completed")
        logging.info("Completed")
