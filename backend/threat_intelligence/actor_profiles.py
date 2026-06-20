from typing import Dict, Any

class ActorProfiles:
    PROFILE_DATA = {
        "APT29": {
            "aliases": ["Cozy Bear", "Nobelium"],
            "origin": "State-sponsored",
            "target_sectors": ["Government", "Diplomatic", "Think Tanks"],
            "signature_techniques": ["T1566", "T1059.001", "T1003.001"]
        },
        "APT41": {
            "aliases": ["Double Dragon", "Barium"],
            "origin": "State-sponsored / Financial",
            "target_sectors": ["Healthcare", "Telecom", "High Tech"],
            "signature_techniques": ["T1190", "T1574.002", "T1071"]
        }
    }

    @classmethod
    def get_actor_profile(cls, name: str) -> Dict[str, Any]:
        return cls.PROFILE_DATA.get(name, {"aliases": [], "origin": "unknown", "target_sectors": [], "signature_techniques": []})
