import os
import sys
import time
from datetime import datetime, timedelta, timezone

import requests
import stix2
import yaml
from pycti import (
    Campaign,
    Identity,
    IntrusionSet,
    Location,
    MarkingDefinition,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    get_config_variable,
)


class CybelAngel:
    """Main class for the CybelAngel OpenCTI connector."""

    def __init__(self):
        """
        Initialize the CybelAngel connector by loading configuration and setting up the OpenCTI helper.

        """

        # Instantiate the connector helper from config
        try:
            config_file_path = (
                os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
            )
            config_file_path = config_file_path.replace("\\", "/")
            config = (
                yaml.load(open(config_file_path), Loader=yaml.FullLoader)
                if os.path.isfile(config_file_path)
                else {}
            )

            self.helper = OpenCTIConnectorHelper(config)

            # Extra config
            self.opencti_url = get_config_variable(
                "OPENCTI_URL", ["opencti", "url"], config, default="http://opencti:8080"
            )
            self.opencti_token = get_config_variable(
                "OPENCTI_TOKEN", ["opencti", "token"], config
            )
            self.connector_id = get_config_variable(
                "CONNECTOR_ID", ["connector", "id"], config
            )
            self.connector_type = get_config_variable(
                "CONNECTOR_TYPE",
                ["connector", "type"],
                config,
                default="EXTERNAL_IMPORT",
            )
            self.connector_name = get_config_variable(
                "CONNECTOR_NAME", ["connector", "name"], config, default="CybelAngel"
            )
            self.connector_scope = get_config_variable(
                "CONNECTOR_SCOPE", ["connector", "scope"], config, default="all"
            )
            self.connector_log_level = get_config_variable(
                "CONNECTOR_LOG_LEVEL",
                ["connector", "log_level"],
                config,
                default="error",
            )
            self.cybelangel_client_id = get_config_variable(
                "CYBELANGEL_CLIENT_ID", ["cybelangel", "client_id"], config
            )
            self.cybelangel_client_secret = get_config_variable(
                "CYBELANGEL_CLIENT_SECRET", ["cybelangel", "client_secret"], config
            )
            self.cybelangel_api_url = get_config_variable(
                "CYBELANGEL_API_URL",
                ["cybelangel", "api_url"],
                config,
                default="https://platform.cybelangel.com",
            )
            self.cybelangel_auth_url = get_config_variable(
                "CYBELANGEL_AUTH_URL",
                ["cybelangel", "auth_url"],
                config,
                default="https://auth.cybelangel.com/oauth/token",
            )
            self.cybelangel_marking = get_config_variable(
                "CYBELANGEL_MARKING",
                ["cybelangel", "marking"],
                config,
                default="TLP:AMBER+STRICT",
            )
            self.cybelangel_fetch_period = get_config_variable(
                "CYBELANGEL_FETCH_PERIOD",
                ["cybelangel", "fetch_period"],
                config,
                default="7",
            )

            # Scheduler / auto-backpressure (ISO 8601). Default = PT6H, i.e., 6 hours.
            self.duration_period = get_config_variable(
                "CONNECTOR_DURATION_PERIOD",
                ["connector", "duration_period"],
                config,
                default="PT6H",
            )

        except Exception as e:
            self.helper.connector_logger.error(
                f"Error loading configuration: {e}. Please check your config.yml file."
            )
            sys.exit(1)

    def load_marking_definition(self):
        """
        Load or create a STIX MarkingDefinition object based on the configured TLP level.

        Supports standard TLP levels: TLP:CLEAR, TLP:GREEN, TLP:AMBER, TLP:AMBER+STRICT and TLP:RED.
        TLP:CLEAR and TLP:AMBER+STRICT are handled as custom markings since they are not natively supported in STIX2.

        Returns:
            None
        """
        TLP_MAPPING = {
            "TLP:WHITE": stix2.TLP_WHITE,
            "TLP:CLEAR": stix2.TLP_WHITE,
            "TLP:GREEN": stix2.TLP_GREEN,
            "TLP:AMBER": stix2.TLP_AMBER,
            "TLP:AMBER+STRICT": stix2.MarkingDefinition(
                id=MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
                definition_type="statement",
                definition={"statement": "TLP:AMBER+STRICT"},
                allow_custom=True,
                x_opencti_definition_type="TLP",
                x_opencti_definition="TLP:AMBER+STRICT",
            ),
            "TLP:RED": stix2.TLP_RED,
        }

        tlp_value = self.cybelangel_marking.strip().upper()
        if tlp_value in TLP_MAPPING:
            self.cybelangel_marking = TLP_MAPPING[tlp_value]
        else:
            self.helper.connector_logger.warning(
                f"Unsupported TLP marking '{tlp_value}', defaulting to TLP:AMBER+STRICT"
            )
            self.cybelangel_marking = TLP_MAPPING["TLP:AMBER+STRICT"]

    def authenticate(self, max_retries=3, delay=5):
        """
        Authenticate with the CybelAngel API using client credentials and retrieve an access token.
        Retries on failure up to `max_retries` times with `delay` seconds between attempts.

        Args:
            None

        Returns:
            str: A valid OAuth2 bearer token if authentication is successful, otherwise None.

        Raises:
            Exception: If the authentication request fails or the response is invalid.
            :param delay: Delay in seconds between retry attempts.
            :param max_retries: Maximum number of retry attempts.
        """

        auth_data = {
            "client_id": self.cybelangel_client_id,
            "client_secret": self.cybelangel_client_secret,
            "audience": "https://platform.cybelangel.com/",
            "grant_type": "client_credentials",
        }

        headers = {
            "Content-Type": "application/json",
            "User-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/138.0.0.0 Safari/537.36 ",
        }
        for attempt in range(1, max_retries + 1):
            self.helper.connector_logger.info(
                f"Attempt {attempt} to authenticate with CybelAngel API"
            )
            try:
                response = requests.post(
                    self.cybelangel_auth_url, json=auth_data, headers=headers
                )
                response.raise_for_status()
                token_data = response.json()
                if "access_token" in token_data:
                    self.helper.connector_logger.info("Authentication successful")
                    return token_data["access_token"]
                else:
                    self.helper.connector_logger.error(
                        f"Authentication failed: {token_data}"
                    )
                    return None
            except requests.exceptions.RequestException as e:
                self.helper.connector_logger.error(
                    f"Error during authentication attempt {attempt}: {e}"
                )
                self.helper.connector_logger.info(
                    f"Retrying in {delay} seconds... (Attempt {attempt}/{max_retries})"
                )
                if attempt < max_retries:
                    time.sleep(delay)

    def create_cybelangel_org(self):
        """
        Creates an identity object for the CybelAngel organization.

        This function generates a STIX 2.1 Identity object representing the CybelAngel organization. The identity includes details such as the name, description, confidence level, identity class, type, and object marking references.

        """
        try:
            identity = stix2.Identity(
                id=Identity.generate_id("CybelAngel", "Organization"),
                spec_version="2.1",
                name="CybelAngel",
                description="Cybelangel is a cybersecurity company that specializes in detecting and mitigating cyber "
                "threats.",
                confidence=50,
                identity_class="organization",
                type="identity",
                object_marking_refs=(
                    [self.cybelangel_marking.id] if self.cybelangel_marking else None
                ),
            )
            self.helper.connector_logger.debug(
                "CybelAngel identity object created successfully."
            )

            return identity
        except Exception as e:
            self.helper.connector_logger.error(
                f"Error creating CybelAngel organization identity: {e}"
            )
            return None

    # ----------------------
    # STIX Builder
    # ----------------------
    def _create_identity(
        self, name, identity_class, marking=None, created_by=None, contact_info=None
    ):
        if not name:
            return None
        if len(name) < 2:
            self.helper.connector_logger.warning(
                f"Identity name '{name}' is too short, adding whitespace."
            )
            name += " "
        return stix2.Identity(
            id=Identity.generate_id(name, identity_class),
            name=name,
            identity_class=identity_class,
            contact_information=contact_info,
            object_marking_refs=marking,
            created_by_ref=created_by,
        )

    def _create_relationship(
        self,
        rel_type,
        source_id,
        target_id,
        claimed_at,
        marking=None,
        created_by=None,
    ):
        return stix2.Relationship(
            id=StixCoreRelationship.generate_id(rel_type, source_id, target_id),
            source_ref=source_id,
            target_ref=target_id,
            created=claimed_at,
            relationship_type=rel_type,
            object_marking_refs=marking,
            created_by_ref=created_by,
        )

    # ----------------------
    # Fetch Data
    # ----------------------
    def opencti_bundle(self, work_id, last_run=None):
        token = self.authenticate()
        self.helper.connector_logger.debug(
            "Token received, proceeding with data fetching."
        )
        cybelangel_org_identity = self.create_cybelangel_org()

        if not token or not cybelangel_org_identity:
            self.helper.connector_logger.error("Missing token or CybelAngel identity.")
            return

        since_date, end_date, parameters = self._build_fetch_parameters(last_run)
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        self._fetch_and_process_pages(
            headers, parameters, cybelangel_org_identity, work_id, since_date
        )

    def _build_fetch_parameters(self, last_run):
        """
        Compute since_date/end_date and build the CybelAngel API parameters.
        Returns (since_date, end_date, parameters) or (None, None, "sort_by=-claimed_at") if full history.
        """

        base_sort = "sort_by=claimed_at&sort_order=desc"

        if last_run:
            try:
                since_date = datetime.fromisoformat(last_run).astimezone(timezone.utc)
            except ValueError:
                fetch_period = getattr(self, "cybelangel_fetch_period", "7")
                since_date = datetime.now(timezone.utc) - timedelta(
                    days=int(fetch_period)
                )
                since_date = since_date.replace(
                    hour=0, minute=0, second=0, microsecond=0
                )
                self.helper.connector_logger.warning(
                    f"Invalid last_run format. Using last {fetch_period} days."
                )
            end_date = datetime.now(timezone.utc)
            parameters = (
                f"{base_sort}"
                f"&start_date={since_date.strftime('%Y-%m-%dT%H:%M:%SZ')}"
                f"&end_date={end_date.strftime('%Y-%m-%dT%H:%M:%SZ')}"
            )
            return since_date, end_date, parameters

        # No last_run -> we use CYBELANGEL_FETCH_PERIOD
        fetch_period = getattr(self, "cybelangel_fetch_period", "all")
        if fetch_period == "all":
            # No date filter
            return None, None, base_sort

        days = int(fetch_period)
        since_date = datetime.now(timezone.utc) - timedelta(days=days)
        since_date = since_date.replace(hour=0, minute=0, second=0, microsecond=0)
        end_date = datetime.now(timezone.utc)
        parameters = (
            f"{base_sort}"
            f"&start_date={since_date.strftime('%Y-%m-%dT%H:%M:%SZ')}"
            f"&end_date={end_date.strftime('%Y-%m-%dT%H:%M:%SZ')}"
        )
        return since_date, end_date, parameters

    def _fetch_and_process_pages(
        self, headers, parameters, author_org, work_id, since_date
    ):
        skip = 0
        limit = 50
        has_more = True
        attempt = 0

        while has_more:
            url = f"{self.cybelangel_api_url}/api/v1/threat-intelligence/claimed-attacks?limit={limit}&skip={skip}&{parameters}"
            self.helper.connector_logger.debug(
                f"Fetching data from CybelAngel API: {url}"
            )
            response = requests.get(url, headers=headers)

            # The CybelAngel token expires after 1 hour. This block reauthenticates in case the token is no longer valid
            if response.status_code == 401 and attempt < 3:
                attempt += 1
                self.helper.connector_logger.info(
                    f"Token expired, re-authenticating. Attempt {attempt}..."
                )
                token = self.authenticate()
                if not token:
                    self.helper.connector_logger.error(
                        "Re-authentication failed, exiting."
                    )
                    return
                headers["Authorization"] = f"Bearer {token}"
                self.helper.connector_logger.info(
                    "Re-authentication successful, retrying data fetch."
                )
                attempt = 0  # Reset attempt counter on successful response
                continue
            elif response.status_code != 200:
                self.helper.connector_logger.error(
                    f"Failed to fetch data from CybelAngel: {response.status_code}. Response: {response.text}. "
                    f"Retrying..."
                )
                time.sleep(5)
                attempt += 1
                if attempt >= 3:
                    self.helper.connector_logger.error(
                        "Failed to fetch data after 3 attempts, exiting."
                    )
                    return
                continue

            attacks = response.json().get("claimed_attacks", [])
            if not attacks:
                has_more = False
                self.helper.connector_logger.info(
                    "No more attacks found, stopping processing."
                )
                break

            self.helper.connector_logger.info(
                f"Processing {len(attacks)} attacks - skip {skip} with limit {limit}"
            )

            for attack in attacks:
                self._process_attack(attack, since_date, author_org, work_id)

            skip += limit

    # ----------------------
    # Parse & Ingest Data
    # ----------------------
    def _process_attack(self, attack, since_date, author_org, work_id):
        claimed_at = attack.get("claimed_at")
        if claimed_at:
            try:
                claimed_at = datetime.strptime(
                    claimed_at, "%Y-%m-%dT%H:%M:%S.%fZ"
                ).replace(tzinfo=timezone.utc)
            except ValueError:
                claimed_at = datetime.strptime(
                    claimed_at, "%Y-%m-%dT%H:%M:%SZ"
                ).replace(tzinfo=timezone.utc)

        # Stop early if attack is before last_run
        if since_date and claimed_at and claimed_at < since_date:
            self.helper.connector_logger.info(
                f"Stopping processing as claimed_at {claimed_at.strftime('%Y-%m-%dT%H:%M:%SZ')} is before "
                f"last_run value {since_date.strftime('%Y-%m-%dT%H:%M:%SZ')}"
            )
            return

        stix_objects = [author_org, self.cybelangel_marking]
        author_org_id = author_org["id"] if author_org else None
        marking_id = [self.cybelangel_marking.id] if self.cybelangel_marking else None

        # Attack fields
        campaign_objective = attack.get("category", "Unknown")
        threat_actors = attack.get("threat_actors", []) or []
        countries = attack.get("countries", []) or []
        industries_list = attack.get("industries", []) or []
        victims = attack.get("victims", []) or []
        domains = attack.get("domains", []) or []

        # Resource level heuristic
        resource_level = (
            "Contest" if "ddos" in campaign_objective.lower() else "Organization"
        )

        # Actor label used in campaign naming
        final_actor = (
            threat_actors[0]
            if (threat_actors and threat_actors[0])
            else "Unknown actor"
        )
        campaign_date = ""
        if claimed_at:
            claimed_date = datetime.strptime(
                claimed_at.strftime("%Y-%m-%d"), "%Y-%m-%d"
            ).date()
            campaign_date = f" ({claimed_date})"

        # --- Locations (countries) shared across campaigns for this attack
        locations = []
        for country in countries:
            if not country:
                continue
            location = stix2.Location(
                id=Location.generate_id(country, "Country"),
                name=country,
                type="location",
                country=country,
                object_marking_refs=marking_id,
                created_by_ref=author_org_id,
            )
            locations.append(location)
            stix_objects.append(location)

        # --- Sectors (industries) shared across campaigns for this attack
        sector_objs = []
        for ind in industries_list:
            if not ind:
                continue
            sector = self._create_identity(ind, "class", marking_id, author_org_id)
            if sector:
                sector_objs.append(sector)
                stix_objects.append(sector)

        # --- Intrusion Sets shared across campaigns for this attack
        intrusion_sets = []
        for actor in threat_actors:
            if not actor:
                continue
            if len(actor) < 2:
                self.helper.connector_logger.info(
                    f"Intrusion set name {actor} is too short, adding whitespace."
                )
                actor = actor + " "
            intrusion_set = stix2.IntrusionSet(
                id=IntrusionSet.generate_id(actor),
                name=actor,
                description=f"Threat actor {actor} from CybelAngel",
                resource_level=resource_level,
                last_seen=claimed_at,
                object_marking_refs=marking_id,
                created_by_ref=author_org_id,
            )
            intrusion_sets.append(intrusion_set)
            stix_objects.append(intrusion_set)

        # --- Build victim-domain pairing
        victim_domain_pairs = []
        if victims and domains and len(domains) == len(victims):
            victim_domain_pairs = list(zip(victims, domains))
        elif victims:
            victim_domain_pairs = [(v, None) for v in victims]

        # --- If no victims at all: keep a generic campaign (backward compatible)
        if not victim_domain_pairs and not victims:
            campaign_name = f"{campaign_objective.capitalize()} campaign by {final_actor} - {campaign_date}".rstrip(
                " - "
            )
            campaign_description = f"{campaign_objective.capitalize()} campaign by {final_actor} with no specific target"
            campaign = stix2.Campaign(
                id=Campaign.generate_id(campaign_name),
                name=campaign_name,
                description=campaign_description,
                created=claimed_at,
                first_seen=claimed_at,
                last_seen=claimed_at,
                objective=campaign_objective,
                object_marking_refs=marking_id,
                created_by_ref=author_org_id,
            )
            stix_objects.append(campaign)

            # campaign -> locations
            for location in locations:
                stix_objects.append(
                    self._create_relationship(
                        "targets",
                        campaign.id,
                        location.id,
                        claimed_at,
                        marking_id,
                        author_org_id,
                    )
                )
            # campaign -> sectors
            for sector in sector_objs:
                stix_objects.append(
                    self._create_relationship(
                        "targets",
                        campaign.id,
                        sector.id,
                        claimed_at,
                        marking_id,
                        author_org_id,
                    )
                )
            # campaign -> intrusion sets
            for iset in intrusion_sets:
                stix_objects.append(
                    self._create_relationship(
                        "attributed-to",
                        campaign.id,
                        iset.id,
                        claimed_at,
                        marking_id,
                        author_org_id,
                    )
                )
            # intrusion sets -> locations / sectors
            for iset in intrusion_sets:
                for location in locations:
                    stix_objects.append(
                        self._create_relationship(
                            "targets",
                            iset.id,
                            location.id,
                            claimed_at,
                            marking_id,
                            author_org_id,
                        )
                    )
                for sector in sector_objs:
                    stix_objects.append(
                        self._create_relationship(
                            "targets",
                            iset.id,
                            sector.id,
                            claimed_at,
                            marking_id,
                            author_org_id,
                        )
                    )

        # --- One campaign per victim
        for victim_name, victim_domain in victim_domain_pairs:
            if not victim_name:
                continue
            v = victim_name if len(victim_name) >= 2 else (victim_name + " ")

            # Create victim identity
            identity = self._create_identity(
                v, "Organization", marking_id, author_org_id, victim_domain
            )
            if identity:
                stix_objects.append(identity)

            # Create a dedicated campaign for this victim
            campaign_name = f"{final_actor} targets {v}"
            campaign_description = f"{campaign_objective.capitalize()} campaign by {final_actor} targeting {v}"
            campaign = stix2.Campaign(
                id=Campaign.generate_id(campaign_name),
                name=campaign_name,
                description=campaign_description,
                created=claimed_at,
                first_seen=claimed_at,
                last_seen=claimed_at,
                objective=campaign_objective,
                object_marking_refs=marking_id,
                created_by_ref=author_org_id,
            )
            stix_objects.append(campaign)

            # campaign -> victim
            if identity:
                stix_objects.append(
                    self._create_relationship(
                        "targets",
                        campaign.id,
                        identity.id,
                        claimed_at,
                        marking_id,
                        author_org_id,
                    )
                )
            # campaign -> locations
            for location in locations:
                stix_objects.append(
                    self._create_relationship(
                        "targets",
                        campaign.id,
                        location.id,
                        claimed_at,
                        marking_id,
                        author_org_id,
                    )
                )
            # campaign -> sectors
            for sector in sector_objs:
                stix_objects.append(
                    self._create_relationship(
                        "targets",
                        campaign.id,
                        sector.id,
                        claimed_at,
                        marking_id,
                        author_org_id,
                    )
                )
            # campaign -> intrusion sets
            for iset in intrusion_sets:
                stix_objects.append(
                    self._create_relationship(
                        "attributed-to",
                        campaign.id,
                        iset.id,
                        claimed_at,
                        marking_id,
                        author_org_id,
                    )
                )

            # intrusion sets -> victim / locations / sectors
            for iset in intrusion_sets:
                if identity:
                    stix_objects.append(
                        self._create_relationship(
                            "targets",
                            iset.id,
                            identity.id,
                            claimed_at,
                            marking_id,
                            author_org_id,
                        )
                    )
                for location in locations:
                    stix_objects.append(
                        self._create_relationship(
                            "targets",
                            iset.id,
                            location.id,
                            claimed_at,
                            marking_id,
                            author_org_id,
                        )
                    )
                for sector in sector_objs:
                    stix_objects.append(
                        self._create_relationship(
                            "targets",
                            iset.id,
                            sector.id,
                            claimed_at,
                            marking_id,
                            author_org_id,
                        )
                    )

        # Send bundle to OpenCTI
        if stix_objects:
            try:
                bundle = stix2.Bundle(
                    objects=stix_objects, allow_custom=True
                ).serialize()
                self.helper.send_stix2_bundle(bundle, update=True, work_id=work_id)
                self.helper.connector_logger.info(
                    f"Successfully processed {len(stix_objects)} STIX objects from CybelAngel."
                )
            except Exception as e:
                self.helper.connector_logger.error(f"Error creating STIX bundle: {e}")

    def process_data(self):
        """
        Main data processing method that manages synchronization with CybelAngel APIs.
        It initiates a work session, retrieves the last run state, processes new data,
        and updates the state in OpenCTI.

        """

        try:
            self.helper.connector_logger.info("Synchronizing with CybelAngel APIs...")
            timestamp = int(time.time())
            now = datetime.fromtimestamp(timestamp, timezone.utc)
            friendly_name = "CybelAngel run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )
            current_state = self.helper.get_state()
            last_run = current_state.get("last_run") if current_state else None
            self.helper.connector_logger.info(
                "Get Elements since " + last_run
                if last_run
                else "No previous run found"
            )

            self.opencti_bundle(work_id, last_run)
            self.helper.set_state({"last_run": now.astimezone().isoformat()})
            message = "End of synchronization"
            self.helper.api.work.to_processed(work_id, message)
            self.helper.connector_logger.info(message)
        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info("Connector stop")
            sys.exit(0)
        except Exception as e:
            error_message = f"Unexpected error during synchronization: {str(e)}"
            self.helper.api.work.report_expectation(
                work_id=work_id,
                error={"error": error_message, "source": "CybelAngel Connector"},
            )

            self.helper.connector_logger.error(str(e))

    def run(self):
        """
        Run using OpenCTI Scheduler (ISO 8601 duration + auto-backpressure).

        """
        try:
            self.helper.connector_logger.info("Fetching CybelAngel data ...")
            self.load_marking_definition()

            self.helper.schedule_iso(
                message_callback=self.process_data,
                duration_period=self.duration_period,
            )

        except Exception as e:
            self.helper.connector_logger.error(f"Error in CybelAngel connector: {e}")
            raise


if __name__ == "__main__":
    try:
        cybelAngelConnector = CybelAngel()
        cybelAngelConnector.run()
    except Exception as e:
        print(f"Error running CybelAngel connector: {e}")
        time.sleep(10)
        sys.exit(0)
