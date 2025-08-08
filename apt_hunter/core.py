from attackcti import attack_client
import os
import json
import requests

DATA_FILE = "data/enterprise-attack.json"
MITRE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"


def find_group_by_alias(alias):
    lift = attack_client()
    group = lift.get_group_by_alias(alias)
    if group:
        return [
            {
                "name": group.get("name"),
                "aliases": group.get("aliases", []),
                "description": group.get("description", ""),
                "url": group.get("external_references", [{}])[0].get("url", ""),
            }
        ]
    else:
        return []


def load_apt_groups():
    data = None
    local_data = None

    # Leer archivo local (si existe, NO descargar de nuevo)
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, "r", encoding="utf-8") as f:
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
            with open(DATA_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            print("✅ Archivo descargado y guardado localmente.")
        except Exception as e:
            print(f"❌ Error al descargar: {e}")
            return []

    # Filtrar intrusion-set
    objects = data.get("objects", [])
    intrusion_sets = [obj for obj in objects if obj.get("type") == "intrusion-set"]
    relationships = [
        obj
        for obj in objects
        if obj.get("type") == "relationship" and obj.get("relationship_type") == "uses"
    ]
    attack_patterns = {
        obj["id"]: obj for obj in objects if obj.get("type") == "attack-pattern"
    }

    groups = []
    import re

    def clean_description(text):
        if not text:
            return ""
        # Quitar enlaces markdown: [texto](url)
        text = re.sub(r"\[(.*?)\]\((.*?)\)", r"\1", text)
        # Quitar negritas y cursivas markdown
        text = re.sub(r"\*\*([^*]+)\*\*", r"\1", text)
        text = re.sub(r"\*([^*]+)\*", r"\1", text)
        text = re.sub(r"__([^_]+)__", r"\1", text)
        text = re.sub(r"_([^_]+)_", r"\1", text)
        # Quitar saltos de línea extra y espacios
        text = re.sub(r"\s+", " ", text).strip()
        return text

    for group in intrusion_sets:
        group_id = group.get("id")
        # Técnicas usadas por el grupo
        technique_ids = [
            rel["target_ref"]
            for rel in relationships
            if rel.get("source_ref") == group_id
            and rel["target_ref"].startswith("attack-pattern--")
        ]
        # Nombres de técnicas
        techniques = [
            attack_patterns[tid]["name"]
            for tid in technique_ids
            if tid in attack_patterns
        ]
        # Tácticas asociadas a las técnicas
        tactics = set()
        for tid in technique_ids:
            ap = attack_patterns.get(tid)
            if ap and "kill_chain_phases" in ap:
                for phase in ap["kill_chain_phases"]:
                    if phase.get("kill_chain_name") == "mitre-attack":
                        tactics.add(phase.get("phase_name"))
        # Normalizar campos
        aliases = group.get("aliases", [])
        if isinstance(aliases, str):
            aliases = [aliases]
        sectors = group.get("x_mitre_targeted_sector", [])
        if isinstance(sectors, str):
            sectors = [sectors]
        # Países objetivo
        countries = group.get("country", [])
        if not countries:
            countries = group.get("x_mitre_countries", [])
        if isinstance(countries, str):
            countries = [countries]
        norm_tactics = sorted(list(tactics)) if tactics else []
        norm_techniques = sorted(list(set(techniques))) if techniques else []
        description = clean_description(group.get("description", ""))
        groups.append(
            {
                "name": group.get("name", "N/A"),
                "aliases": aliases,
                "description": description,
                "url": group.get("external_references", [{}])[0].get("url", ""),
                "tactics": norm_tactics,
                "techniques": norm_techniques,
                "sectors": sectors,
                "countries": countries,
            }
        )

    return groups
