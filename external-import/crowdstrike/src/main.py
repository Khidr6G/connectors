"""OpenCTI CrowdStrike connector main module."""

import traceback

from pycti import OpenCTIConnectorHelper

from crowdstrike_feeds_connector import ConnectorSettings, CrowdStrike

if __name__ == "__main__":
    """
    Entry point of the script
    """
    try:
        settings = ConnectorSettings()
        helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

        connector = CrowdStrike(config=settings, helper=helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
