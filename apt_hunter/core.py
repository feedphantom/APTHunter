from attackcti import attack_client
from pathlib import Path
import json
import re
import requests

DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "enterprise-attack.json"
MITRE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"


def _string_values(value):
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, (list, tuple, set)):
        return [item for item in value if isinstance(item, str) and item]
    return []


def _is_active(obj):
    return not obj.get("revoked", False) and not obj.get("x_mitre_deprecated", False)


def _mitre_url(obj):
    for ref in obj.get("external_references", []):
        url = ref.get("url", "")
        if url.startswith("https://attack.mitre.org/"):
            return url
    return ""


def find_group_by_alias(alias):
    client = attack_client()
    group = client.get_group_by_alias(alias)
    if not group:
        return []
    return [{
        "id": group.get("id"),
        "name": group.get("name"),
        "aliases": _string_values(group.get("aliases")),
        "description": group.get("description", ""),
        "url": _mitre_url(group),
    }]


def _download_attack_data():
    response = requests.get(MITRE_URL, timeout=20)
    response.raise_for_status()
    data = response.json()
    if not isinstance(data, dict) or not isinstance(data.get("objects"), list):
        raise ValueError("MITRE returned an invalid ATT&CK data bundle")
    return data


def load_apt_groups():
    try:
        if DATA_FILE.exists():
            with DATA_FILE.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
        else:
            data = _download_attack_data()
            DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
            temporary_file = DATA_FILE.with_suffix(".json.tmp")
            temporary_file.write_text(
                json.dumps(data, ensure_ascii=False), encoding="utf-8"
            )
            temporary_file.replace(DATA_FILE)
    except (OSError, ValueError, requests.RequestException) as error:
        print(f"❌ No se pudieron cargar los datos de MITRE ATT&CK: {error}")
        return []

    objects = data.get("objects", []) if isinstance(data, dict) else []
    active_objects = [
        obj for obj in objects if isinstance(obj, dict) and _is_active(obj)
    ]
    objects_by_id = {
        obj["id"]: obj for obj in active_objects if isinstance(obj.get("id"), str)
    }
    attack_patterns = {
        object_id: obj
        for object_id, obj in objects_by_id.items()
        if obj.get("type") == "attack-pattern"
    }

    techniques_by_group = {}
    malware_by_group = {}
    tools_by_group = {}
    campaigns_by_group = {}

    for relation in active_objects:
        if relation.get("type") != "relationship":
            continue

        relation_type = relation.get("relationship_type")
        source_id = relation.get("source_ref")
        target_id = relation.get("target_ref")
        if not source_id or not target_id:
            continue

        if relation_type == "uses" and source_id in objects_by_id:
            source = objects_by_id[source_id]
            target = objects_by_id.get(target_id)
            if not target:
                continue
            source_type = source.get("type")
            target_type = target.get("type")
            if source_type == "intrusion-set":
                if target_type == "attack-pattern":
                    techniques_by_group.setdefault(source_id, set()).add(target_id)
                elif target_type == "malware":
                    malware_by_group.setdefault(source_id, set()).add(target_id)
                elif target_type == "tool":
                    tools_by_group.setdefault(source_id, set()).add(target_id)

        elif relation_type == "attributed-to":
            campaign = objects_by_id.get(source_id)
            group = objects_by_id.get(target_id)
            if campaign and campaign.get("type") == "campaign" and group and group.get("type") == "intrusion-set":
                campaigns_by_group.setdefault(target_id, set()).add(source_id)

    groups = []
    for group in active_objects:
        if group.get("type") != "intrusion-set":
            continue

        group_id = group.get("id")
        technique_ids = techniques_by_group.get(group_id, set())
        techniques = [
            attack_patterns[tech_id]
            for tech_id in technique_ids
            if tech_id in attack_patterns
        ]
        tactic_names = {
            phase.get("phase_name")
            for technique in techniques
            for phase in technique.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
            and phase.get("phase_name")
        }

        sectors = _string_values(group.get("x_mitre_targeted_sector"))
        countries = _string_values(group.get("country")) or _string_values(
            group.get("x_mitre_countries")
        )
        description = group.get("description", "")
        description = re.sub(r"\[(.*?)\]\((.*?)\)", r"\1", description)
        description = re.sub(r"\*\*([^*]+)\*\*", r"\1", description)
        description = re.sub(r"\*([^*]+)\*", r"\1", description)
        description = re.sub(r"__([^_]+)__", r"\1", description)
        description = re.sub(r"_([^_]+)_", r"\1", description)
        description = re.sub(r"\s+", " ", description).strip()

        malware_ids = malware_by_group.get(group_id, set())
        tool_ids = tools_by_group.get(group_id, set())
        campaign_ids = campaigns_by_group.get(group_id, set())

        groups.append({
            "id": group_id,
            "name": group.get("name", "N/A"),
            "aliases": _string_values(group.get("aliases")),
            "description": description,
            "url": _mitre_url(group),
            "tactics": sorted(tactic_names),
            "techniques": sorted({
                technique.get("name", "")
                for technique in techniques
                if technique.get("name")
            }),
            "sectors": sectors,
            "countries": countries,
            "malware": sorted({
                objects_by_id[item_id].get("name", "")
                for item_id in malware_ids
                if item_id in objects_by_id and objects_by_id[item_id].get("name")
            }),
            "tools": sorted({
                objects_by_id[item_id].get("name", "")
                for item_id in tool_ids
                if item_id in objects_by_id and objects_by_id[item_id].get("name")
            }),
            "campaigns": sorted({
                objects_by_id[item_id].get("name", "")
                for item_id in campaign_ids
                if item_id in objects_by_id and objects_by_id[item_id].get("name")
            }),
        })

    return groups
