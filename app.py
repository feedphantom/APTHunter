import requests
from io import BytesIO

MITRE_JSON_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"


def get_latest_attack_spec_version():
    try:
        resp = requests.get(MITRE_JSON_URL, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            for obj in data.get("objects", []):
                if obj.get("type") == "x-mitre-matrix" and obj.get(
                    "x_mitre_attack_spec_version"
                ):
                    return obj.get("x_mitre_attack_spec_version"), data
        return None, None
    except Exception:
        return None, None


import sys
import os
import pandas as pd
import json
import streamlit as st
import json
from apt_hunter.core import load_apt_groups
from apt_hunter.filters import filter_by_country, filter_by_sector, find_group_by_alias

# --- Panel lateral de guía ATT&CK ---
DATA_FILE = os.path.join(os.path.dirname(__file__), "data/enterprise-attack.json")


@st.cache_data(show_spinner=False)
def load_attack_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return None


def get_tactics_and_techniques(attack_data):
    tactics = []
    techniques = []
    mitigations = {}
    if not attack_data:
        return tactics, techniques, mitigations
    objects = attack_data.get("objects", [])
    for obj in objects:
        if obj.get("type") == "x-mitre-tactic":
            tactics.append(
                {
                    "id": obj["id"],
                    "name": obj.get("name", ""),
                    "description": obj.get("description", ""),
                }
            )
        elif obj.get("type") == "attack-pattern":
            techniques.append(
                {
                    "id": obj["id"],
                    "name": obj.get("name", ""),
                    "description": obj.get("description", ""),
                    "mitigations": [],
                }
            )
        elif obj.get("type") == "course-of-action":
            mitigations[obj["id"]] = {
                "name": obj.get("name", ""),
                "description": obj.get("description", ""),
            }
    # Relacionar técnicas con mitigaciones
    for obj in attack_data.get("objects", []):
        if (
            obj.get("type") == "relationship"
            and obj.get("relationship_type") == "mitigates"
        ):
            source = obj.get("source_ref")
            target = obj.get("target_ref")
            for tech in techniques:
                if tech["id"] == target:
                    if source in mitigations:
                        tech["mitigations"].append(mitigations[source])

    return tactics, techniques, mitigations


attack_data = load_attack_data()
if attack_data is None:
    st.error("No se pudo cargar el archivo enterprise-attack.json")
    st.stop()
tactics, techniques, _ = get_tactics_and_techniques(attack_data)


# Leer países y sectores desde JSON
with open(
    os.path.join(os.path.dirname(__file__), "data/choices.json"), encoding="utf-8"
) as f:
    choices = json.load(f)
COUNTRIES = sorted(choices["countries"])
SECTORS = sorted(choices["sectors"])


st.set_page_config(page_title="APTHunter", layout="wide")
st.title("🕵️ APTHunter Web")
# Mostrar versión o fecha del enterprise-attack.json si está disponible
attack_version = None
attack_date = None
attack_spec_version = None
if attack_data:
    # Buscar campos típicos de versión o fecha
    attack_version = attack_data.get("version")
    attack_date = attack_data.get("modified") or attack_data.get("date")
    # Buscar x_mitre_attack_spec_version en los objetos
    for obj in attack_data.get("objects", []):
        if obj.get("type") == "x-mitre-matrix":
            if not attack_version:
                attack_version = obj.get("x_mitre_version")
            if not attack_date:
                attack_date = obj.get("modified")
            if obj.get("x_mitre_attack_spec_version"):
                attack_spec_version = obj.get("x_mitre_attack_spec_version")
            break
if attack_version or attack_date or attack_spec_version:
    st.caption(
        f"Base MITRE ATT&CK local: "
        f"{'versión ' + str(attack_version) if attack_version else ''}"
        f"{' | ' if attack_version and attack_date else ''}"
        f"{'fecha ' + str(attack_date) if attack_date else ''}"
        f"{' | ' if (attack_version or attack_date) and attack_spec_version else ''}"
        f"{'spec ' + str(attack_spec_version) if attack_spec_version else ''}"
    )

    # Comprobar si hay una versión más nueva (comparación robusta)
    def parse_version(v):
        return tuple(int(x) for x in str(v).split(".")) if v else (0,)

    latest_spec_version, _ = get_latest_attack_spec_version()
    if latest_spec_version and attack_spec_version:
        local_v = parse_version(attack_spec_version)
        remote_v = parse_version(latest_spec_version)
        st.caption(
            f"Spec local: {attack_spec_version} | Spec remoto: {latest_spec_version}"
        )
        if remote_v > local_v:
            st.warning(f"¡Nueva versión disponible! Spec {latest_spec_version}")
            if st.button("Descargar y actualizar enterprise-attack.json"):
                try:
                    content = requests.get(MITRE_JSON_URL, timeout=15).content
                    with open(DATA_FILE, "wb") as f:
                        f.write(content)
                    st.success(
                        "¡Archivo actualizado correctamente! Recarga la página para usar la nueva versión."
                    )
                except Exception as e:
                    st.error(f"Error al descargar el archivo: {e}")
        else:
            st.info(
                f"Ya tienes la versión más reciente del spec ({attack_spec_version})"
            )
    elif latest_spec_version:
        st.caption(f"Spec remoto disponible: {latest_spec_version}")


# Cargar datos solo una vez usando cache
@st.cache_data(show_spinner=False)
def get_groups():
    return load_apt_groups()


groups = get_groups()
filtered_groups = groups  # Copia base


tabs = st.tabs(
    [
        "🔍 Buscador APTs",
        "🛡️ Tácticas y Técnicas",
        "🦠 Malware",
        "🛠️ Herramientas",
        "🎯 Campañas",
        "📊 Estadísticas",
    ]
)
tab1, tab2, tab3, tab4, tab5, tab6 = tabs

# TAB 1: Buscador APTs
with tab1:
    st.header("🔍 Buscador APTs")
    # Opciones de búsqueda
    option = st.radio(
        "¿Cómo quieres buscar?", ["Todos", "Por país", "Por alias", "Por sector"]
    )
    # Lógica de filtrado
    filtered_groups = groups
    if option == "Por país":
        country = st.selectbox("Selecciona un país", COUNTRIES)
        filtered_groups = filter_by_country(groups, country)
    elif option == "Por alias":
        alias = st.text_input("Introduce el alias (ej: APT29)")
        if alias:
            filtered_groups = find_group_by_alias(groups, alias)
        else:
            filtered_groups = []
    elif option == "Por sector":
        sector = st.selectbox("Selecciona un sector", SECTORS)
        filtered_groups = filter_by_sector(groups, sector)

    st.success(f"Grupos encontrados: {len(filtered_groups)}")

    if filtered_groups:
        for g in filtered_groups:
            # Normalización defensiva
            name = g.get("name", "N/A")
            aliases = g.get("aliases", [])
            if isinstance(aliases, str):
                aliases = [aliases]
            group_tactics = g.get("tactics", [])
            if isinstance(group_tactics, str):
                group_tactics = [group_tactics]
            group_techniques = g.get("techniques", [])
            if isinstance(group_techniques, str):
                group_techniques = [group_techniques]
            sectors = g.get("sectors", [])
            if isinstance(sectors, str):
                sectors = [sectors]
            url = g.get("url", "")
            description = g.get("description", "")
            # Buscar malware utilizado por el grupo y campañas atribuidas
            group_id = g.get("id")
            malware_used = set()
            campaigns = set()
            if group_id and attack_data:
                for rel in attack_data.get("objects", []):
                    if rel.get("type") == "relationship":
                        # Malware usado por el grupo
                        if (
                            rel.get("relationship_type") == "uses"
                            and rel.get("source_ref") == group_id
                            and rel.get("target_ref", "").startswith("malware--")
                        ):
                            malware_id = rel.get("target_ref")
                            malware_obj = next(
                                (
                                    m
                                    for m in attack_data["objects"]
                                    if m.get("id") == malware_id
                                    and m.get("type") == "malware"
                                ),
                                None,
                            )
                            if malware_obj:
                                malware_used.add(malware_obj.get("name", ""))
                        # Campañas en las que participa el grupo
                        if (
                            rel.get("relationship_type") == "attributed-to"
                            and rel.get("target_ref") == group_id
                            and rel.get("source_ref", "").startswith("campaign--")
                        ):
                            camp_id = rel.get("source_ref")
                            camp_obj = next(
                                (
                                    c
                                    for c in attack_data["objects"]
                                    if c.get("id") == camp_id
                                    and c.get("type") == "campaign"
                                ),
                                None,
                            )
                            if camp_obj:
                                campaigns.add(camp_obj.get("name", ""))
            # Construir líneas para malware y campañas
            malware_line = (
                f"🦠 **Malware:** {', '.join(sorted(malware_used))}"
                if malware_used
                else ""
            )
            campaigns_line = (
                f"🎯 **Campañas:** {', '.join(sorted(campaigns))}" if campaigns else ""
            )
            st.markdown(
                f"""
                ### 🎯 {name}
                🏷️ **Alias:** {', '.join(aliases) or 'N/A'}  
                🧩 **Tácticas:** {', '.join(group_tactics) or 'N/A'}  
                🛠️ **Técnicas:** {', '.join(group_techniques) or 'N/A'}  
                🏢 **Sectores:** {', '.join(sectors) or 'N/A'}  
                {malware_line}  
                {campaigns_line}  
                🔗 [MITRE ATT&CK Link]({url})  
                """
            )
            if malware_used:
                with st.expander("🦠 Malware utilizado por el grupo"):
                    st.markdown(", ".join(sorted(malware_used)))
            if campaigns:
                with st.expander("🎯 Campañas atribuidas al grupo"):
                    st.markdown(", ".join(sorted(campaigns)))
            with st.expander("📝 Descripción"):
                st.write(description)
    else:
        st.warning("❗ No se encontraron resultados.")


# TAB 2: Tácticas y Técnicas
with tab2:

    # Usar variables locales para evitar shadowing
    tactics_data = tactics
    techniques_data = techniques

    st.header("🛡️ Tácticas y Técnicas")
    modo = st.radio(
        "¿Qué quieres explorar?",
        ["Táctica", "Técnica"],
        horizontal=True,
        key="modo_tab2",
    )
    st.success(
        f"Tácticas cargadas: {len([t for t in tactics_data if isinstance(t, dict) and 'name' in t])}  | Técnicas cargadas: {len([t for t in techniques_data if isinstance(t, dict) and 'name' in t])}"
    )
    if modo == "Táctica":
        tactic_names = sorted(
            [t["name"] for t in tactics_data if isinstance(t, dict) and "name" in t]
        )
        selected_tactic = st.selectbox(
            "Selecciona una táctica ATT&CK:", tactic_names, key="tactic_select_tab2"
        )
        tactic = next(
            (
                t
                for t in tactics_data
                if isinstance(t, dict) and t.get("name") == selected_tactic
            ),
            None,
        )
        if tactic:
            st.markdown(f"### 🛡️ {tactic['name']}")
            st.write(tactic["description"])
            # Técnicas asociadas
            related_techniques = []
            for obj in attack_data.get("objects", []):
                if obj.get("type") == "attack-pattern":
                    for kcp in obj.get("kill_chain_phases", []):
                        if kcp.get("phase_name", "").lower() == tactic["name"].lower():
                            related_techniques.append(obj["name"])
            if related_techniques:
                st.markdown(
                    "**Técnicas asociadas:** "
                    + ", ".join(sorted(set(related_techniques)))
                )
            else:
                st.info("No hay técnicas asociadas a esta táctica.")
    else:
        # Validación defensiva: solo usar técnicas que sean dict y tengan 'name'
        technique_names = sorted(
            [t["name"] for t in techniques_data if isinstance(t, dict) and "name" in t]
        )
        selected_technique = st.selectbox(
            "Selecciona una técnica ATT&CK:",
            technique_names,
            key="technique_select_tab2",
        )
        tech = next(
            (
                t
                for t in techniques_data
                if isinstance(t, dict) and t.get("name") == selected_technique
            ),
            None,
        )
        if tech:
            st.markdown(f"### 🛠️ {tech['name']}")
            st.write(tech["description"])
            if tech.get("mitigations"):
                with st.expander("Mitigaciones recomendadas"):
                    for mit in tech["mitigations"]:
                        st.markdown(f"- **{mit['name']}**: {mit['description']}")

# TAB 3: Malware
with tab3:
    st.header("🦠 Malware")
    malware_objs = [o for o in attack_data["objects"] if o.get("type") == "malware"]
    st.success(f"Malware cargado: {len(malware_objs)}")
    if not malware_objs:
        st.info("No hay malware documentado en la base de datos.")
    else:
        opciones = sorted(
            [m.get("name", "Sin nombre") for m in malware_objs], key=lambda x: x.lower()
        )
        seleccion = st.selectbox(
            "Selecciona un malware:", opciones, key="malware_select_tab3"
        )
        malware = next((m for m in malware_objs if m.get("name") == seleccion), None)
        if malware:
            url = ""
            for ext in malware.get("external_references", []):
                if ext.get("url", "").startswith("https://attack.mitre.org/software/"):
                    url = ext["url"]
            col1, col2 = st.columns([1, 2])
            with col1:
                st.markdown(f"### 🦠 {malware.get('name','')}")
                if url:
                    st.markdown(f"[Ver en MITRE ATT&CK]({url})")
                platforms = malware.get("x_mitre_platforms", [])
                if platforms:
                    st.markdown(f"**Plataformas:** {', '.join(platforms)}")
            with col2:
                st.markdown("**Descripción:**")
                st.write(malware.get("description", "Sin descripción."))
            # Técnicas asociadas
            related_techniques = set()
            for obj in attack_data.get("objects", []):
                if (
                    obj.get("type") == "relationship"
                    and obj.get("relationship_type") == "uses"
                ):
                    if obj.get("source_ref", "").startswith("malware--") and obj.get(
                        "target_ref", ""
                    ).startswith("attack-pattern--"):
                        if obj.get("source_ref") == malware.get("id"):
                            # Buscar nombre de la técnica
                            tech_id = obj.get("target_ref")
                            tech = next(
                                (
                                    t
                                    for t in attack_data["objects"]
                                    if t.get("id") == tech_id
                                    and t.get("type") == "attack-pattern"
                                ),
                                None,
                            )
                            if tech:
                                related_techniques.add(tech.get("name", ""))
            if related_techniques:
                with st.expander("Técnicas asociadas a este malware"):
                    st.markdown(", ".join(sorted(related_techniques)))

# TAB 4: Herramientas
with tab4:
    st.header("🛠️ Herramientas")
    tool_objs = [o for o in attack_data["objects"] if o.get("type") == "tool"]
    st.success(f"Herramientas cargadas: {len(tool_objs)}")
    if not tool_objs:
        st.info("No hay herramientas documentadas en la base de datos.")
    else:
        opciones = sorted(
            [t.get("name", "Sin nombre") for t in tool_objs], key=lambda x: x.lower()
        )
        seleccion = st.selectbox(
            "Selecciona una herramienta:", opciones, key="tool_select_tab4"
        )
        tool = next((t for t in tool_objs if t.get("name") == seleccion), None)
        if tool:
            url = ""
            for ext in tool.get("external_references", []):
                if ext.get("url", "").startswith("https://attack.mitre.org/software/"):
                    url = ext["url"]
            col1, col2 = st.columns([1, 2])
            with col1:
                st.markdown(f"### 🛠️ {tool.get('name','')}")
                if url:
                    st.markdown(f"[Ver en MITRE ATT&CK]({url})")
                platforms = tool.get("x_mitre_platforms", [])
                if platforms:
                    st.markdown(f"**Plataformas:** {', '.join(platforms)}")
            with col2:
                st.markdown("**Descripción:**")
                st.write(tool.get("description", "Sin descripción."))
            # Técnicas asociadas
            related_techniques = set()
            for obj in attack_data.get("objects", []):
                if (
                    obj.get("type") == "relationship"
                    and obj.get("relationship_type") == "uses"
                ):
                    if obj.get("source_ref", "").startswith("tool--") and obj.get(
                        "target_ref", ""
                    ).startswith("attack-pattern--"):
                        if obj.get("source_ref") == tool.get("id"):
                            # Buscar nombre de la técnica
                            tech_id = obj.get("target_ref")
                            tech = next(
                                (
                                    t
                                    for t in attack_data["objects"]
                                    if t.get("id") == tech_id
                                    and t.get("type") == "attack-pattern"
                                ),
                                None,
                            )
                            if tech:
                                related_techniques.add(tech.get("name", ""))
            if related_techniques:
                with st.expander("Técnicas asociadas a esta herramienta"):
                    st.markdown(", ".join(sorted(related_techniques)))

# TAB 5: Campañas
with tab5:
    st.header("🎯 Campañas")
    camp_objs = [o for o in attack_data["objects"] if o.get("type") == "campaign"]
    st.success(f"Campañas cargadas: {len(camp_objs)}")
    if not camp_objs:
        st.info("No hay campañas documentadas en la base de datos.")
    else:
        opciones = sorted(
            [c.get("name", "Sin nombre") for c in camp_objs], key=lambda x: x.lower()
        )
        seleccion = st.selectbox(
            "Selecciona una campaña:", opciones, key="camp_select_tab5"
        )
        camp = next((c for c in camp_objs if c.get("name") == seleccion), None)
        if camp:
            url = ""
            for ext in camp.get("external_references", []):
                if ext.get("url", "").startswith("https://attack.mitre.org/campaigns/"):
                    url = ext["url"]
            col1, col2 = st.columns([1, 2])
            with col1:
                st.markdown(f"### 🎯 {camp.get('name','')}")
                if url:
                    st.markdown(f"[Ver en MITRE ATT&CK]({url})")
                # Periodo
                first_seen = camp.get("first_seen")
                last_seen = camp.get("last_seen")
                if first_seen or last_seen:
                    periodo = f"{first_seen or '?'} - {last_seen or '?'}"
                    st.markdown(f"**Periodo:** {periodo}")
            with col2:
                st.markdown("**Descripción:**")
                st.write(camp.get("description", "Sin descripción."))
            # Objetivos
            targets = camp.get("targets", [])
            if targets:
                with st.expander("Objetivos de la campaña"):
                    st.markdown(", ".join(targets))

# TAB 6: Estadísticas
with tab6:
    st.header("📊 Estadísticas de APT-Hunter")

    # Grupos por país
    country_counts = {}
    for g in groups:
        for c in g.get("countries", []):
            country_counts[c] = country_counts.get(c, 0) + 1
    if country_counts:
        st.subheader("Grupos APT por país")
        df_countries = pd.DataFrame(
            list(country_counts.items()), columns=["País", "Cantidad"]
        )
        st.bar_chart(df_countries.set_index("País"))

    # Técnicas más usadas
    technique_counts = {}
    for g in groups:
        for t in g.get("techniques", []):
            technique_counts[t] = technique_counts.get(t, 0) + 1
    # Grupos por país
    country_counts = {}
    for g in groups:
        for c in g.get("countries", []):
            country_counts[c] = country_counts.get(c, 0) + 1
    st.subheader("Grupos APT por país")
    if country_counts:
        df_countries = pd.DataFrame(
            list(country_counts.items()), columns=["País", "Cantidad"]
        )
        st.dataframe(
            df_countries.sort_values("Cantidad", ascending=False),
            use_container_width=True,
        )
        st.bar_chart(df_countries.set_index("País"))
    else:
        st.info("No hay datos de países en los grupos.")

    # Técnicas más usadas
    technique_counts = {}
    for g in groups:
        for t in g.get("techniques", []):
            technique_counts[t] = technique_counts.get(t, 0) + 1
    st.subheader("Técnicas más usadas por grupos (Top 10)")
    if technique_counts:
        df_tech = pd.DataFrame(
            sorted(technique_counts.items(), key=lambda x: x[1], reverse=True)[:10],
            columns=["Técnica", "Veces"],
        )
        df_tech.index = range(1, len(df_tech) + 1)
        df_tech.index.name = "Ranking"
        st.dataframe(df_tech, use_container_width=True)
        st.bar_chart(df_tech.set_index("Técnica"))
    else:
        st.info("No hay datos de técnicas en los grupos.")

    # Malware más frecuente
    malware_counts = {}
    for g in groups:
        for m in g.get("malware", []):
            malware_counts[m] = malware_counts.get(m, 0) + 1
    st.subheader("Malware más utilizado por grupos (Top 10)")
    if malware_counts:
        df_malware = pd.DataFrame(
            sorted(malware_counts.items(), key=lambda x: x[1], reverse=True)[:10],
            columns=["Malware", "Veces"],
        )
        st.dataframe(df_malware, use_container_width=True)
        st.bar_chart(df_malware.set_index("Malware"))
    else:
        st.info("No hay datos de malware en los grupos.")

    # Sectores más atacados
    sector_counts = {}
    for g in groups:
        for s in g.get("sectors", []):
            sector_counts[s] = sector_counts.get(s, 0) + 1
    st.subheader("Sectores más atacados")
    if sector_counts:
        df_sectors = pd.DataFrame(
            list(sector_counts.items()), columns=["Sector", "Cantidad"]
        )
        st.dataframe(
            df_sectors.sort_values("Cantidad", ascending=False),
            use_container_width=True,
        )
        st.bar_chart(df_sectors.set_index("Sector"))
    else:
        st.info("No hay datos de sectores en los grupos.")
