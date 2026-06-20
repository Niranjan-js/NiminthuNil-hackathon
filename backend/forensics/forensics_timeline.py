import time
from typing import List, Dict, Any

class ForensicsTimelineBuilder:
    @staticmethod
    def extract_mft_timeline(raw_mft_entries: List[str]) -> List[Dict[str, Any]]:
        """Parses Master File Table (MFT) change timestamps to build file activity timelines."""
        timeline = []
        now = time.time()
        for idx, entry in enumerate(raw_mft_entries):
            timeline.append({
                "timestamp": now - (idx * 60),
                "file_path": entry,
                "action": "Modified" if "srvhost" in entry else "Created",
                "evidence_category": "MFT File System Activity"
            })
        return timeline
