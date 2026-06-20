from .neo4j_client import neo4j_client

class RelationshipBuilder:
    @staticmethod
    def link_asset_and_user(asset_id: str, username: str):
        neo4j_client.add_relationship(f"User:{username}", f"Asset:{asset_id}", "USES")

    @staticmethod
    def link_incident_and_asset(incident_id: str, asset_id: str):
        neo4j_client.add_relationship(f"Incident:{incident_id}", f"Asset:{asset_id}", "TARGETS")

    @staticmethod
    def link_cve_and_asset(cve_id: str, asset_id: str, severity: float = 7.0):
        neo4j_client.add_relationship(f"CVE:{cve_id}", f"Asset:{asset_id}", "EXPLOITS", {"cvss": severity})

    @staticmethod
    def link_ioc_and_incident(ioc_val: str, incident_id: str):
        neo4j_client.add_relationship(f"IOC:{ioc_val}", f"Incident:{incident_id}", "INDICATES")
