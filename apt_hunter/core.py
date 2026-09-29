from attackcti import attack_client
from pathlib import Path
import json
import requests

DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "enterprise-attack.json"
MITRE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"


def find_group_by_alias(alias):
    lift = attack_client()
    group = lift.get_group_by_alias(alias)
    if group:
        return [
            {
                "id": group.get("id"),
                "name": group.get("name"),
                "aliases": group.get("aliases", []),
                "description": group.get("description", ""),
                "url": group.get("external_references", [{}])[0].get("url", ""),
            }
        ]
    return []


def load_apt_groups():
    data = None

    # Leer archivo local (si existe, NO descargar de nuevo)
    if DATA_FILE.exists():
        try:
            with DATA_FILE.open("r", encoding="utf-8") as f:
                data = json.load(f)
                print("✅ Datos cargados desde archivo local.")
        except Exception as e:
            print(f"⚠️ Error leyendo archivo local: {e}")
            data = None
    else:
        # Solo descargar si no existe el archivo local
        print("🌐 Descargando datos desde MITRE...")
        try:
            response = requests.get(MITRE_URL, timeout=10)
            response.raise_for_status()
            data = response.json()
            with DATA_FILE.open("w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            print("✅ Archivo descargado y guardado localmente.")
        except Exception as e:
            print(f"❌ Error al descargar: {e}")
            return []

    if not isinstance(data, dict):
        return []

    objects = data.get("objects", [])
    intrusion_sets = [obj for obj in objects if obj.get("type") == "intrusion-set"]
    relationships = [
        obj
        for obj in objects
        if obj.get("type") == "relationship" and obj.get("relationship_type") == "uses"
    ]
    attack_patterns = {
        obj["id"]: obj for obj in objects if obj.get("type") == "attack-pattern" and obj.get("id")
    }

    groups = []
    import re

    def clean_description(text):
        if not text:
            return ""
        text = re.sub(r"\[(.*?)\]\((.*?)\)", r"\1", text)
        text = re.sub(r"\*\*([^*]+)\*\*", r"\1", text)
        text = re.sub(r"\*([^*]+)\*", r"\1", text)
        text = re.sub(r"__([^_]+)__", r"\1", text)
        text = re.sub(r"_([^_]+)_", r"\1", text)
        return re.sub(r"\s+", " ", text).strip()

    for group in intrusion_sets:
        group_id = group.get("id")
        technique_ids = [
            rel["target_ref"]
            for rel in relationships
            if rel.get("source_ref") == group_id
            and rel.get("target_ref", "").startswith("attack-pattern--")
        ]
        techniques = [
            attack_patterns[tid]["name"]
            for tid in technique_ids
            if tid in attack_patterns and attack_patterns[tid].get("name")
        ]
        tactics = set()
        for tid in technique_ids:
            ap = attack_patterns.get(tid)
            if ap and "kill_chain_phases" in ap:
                for phase in ap["kill_chain_phases"]:
                    if phase.get("kill_chain_name") == "mitre-attack":
                        tactics.add(phase.get("phase_name"))

        aliases = group.get("aliases", [])
        if isinstance(aliases, str):
            aliases = [aliases]
        sectors = group.get("x_mitre_targeted_sector", [])
        if isinstance(sectors, str):
            sectors = [sectors]
        countries = group.get("country", []) or group.get("x_mitre_countries", [])
        if isinstance(countries, str):
            countries = [countries]

        description = clean_description(group.get("description", ""))
        groups.append(
            {
                "id": group_id,
                "name": group.get("name", "N/A"),
                "aliases": aliases,
                "description": description,
                "url": group.get("external_references", [{}])[0].get("url", ""),
                "tactics": sorted(tactics),
                "techniques": sorted(set(techniques)),
                "sectors": sectors,
                "countries": countries,
            }
        )

    return groups
