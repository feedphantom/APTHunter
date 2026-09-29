from __future__ import annotations

import json
import os
import tempfile
from collections import Counter
from pathlib import Path

import pandas as pd
import requests
import streamlit as st

from apt_hunter.core import MITRE_URL, load_apt_groups
from apt_hunter.filters import filter_by_country, filter_by_sector, find_group_by_alias


ROOT = Path(__file__).resolve().parent
DATA_FILE = ROOT / "data" / "enterprise-attack.json"
CHOICES_FILE = ROOT / "data" / "choices.json"
ATTACK_BASE_URL = "https://attack.mitre.org"


st.set_page_config(
    page_title="APTHunter · MITRE ATT&CK Explorer",
    page_icon="🕵️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
      .block-container {max-width: 1500px; padding-top: 2rem; padding-bottom: 3rem;}
      [data-testid="stMetric"] {background: #f5f7fb; border: 1px solid #e6eaf2;
        padding: 1rem 1.1rem; border-radius: 0.8rem;}
      [data-testid="stMetricLabel"] {font-size: .9rem;}
      h1 {letter-spacing: -0.035em;}
      .stTabs [data-baseweb="tab-list"] {gap: .45rem;}
      .stTabs [data-baseweb="tab"] {border-radius: .55rem .55rem 0 0;}
    </style>
    """,
    unsafe_allow_html=True,
)


def _active(obj: dict) -> bool:
    return not obj.get("revoked", False) and not obj.get("x_mitre_deprecated", False)


def _values(value) -> list[str]:
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, (list, tuple, set)):
        return [item for item in value if isinstance(item, str) and item]
    return []


@st.cache_data(show_spinner=False)
def load_attack_data(path: str, modified_ns: int, size: int) -> dict:
    del modified_ns, size
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict) or not isinstance(data.get("objects"), list):
        raise ValueError("El archivo local no contiene un bundle STIX ATT&CK válido.")
    return data


@st.cache_data(show_spinner=False)
def load_choices(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


@st.cache_data(ttl=3600, show_spinner=False)
def fetch_remote_attack_data() -> dict:
    response = requests.get(MITRE_URL, timeout=30)
    response.raise_for_status()
    data = response.json()
    if (
        not isinstance(data, dict)
        or not isinstance(data.get("objects"), list)
        or len(data["objects"]) < 100
        or not any(obj.get("type") == "x-mitre-matrix" for obj in data["objects"])
    ):
        raise ValueError("La respuesta no parece un bundle ATT&CK Enterprise completo.")
    return data


@st.cache_data(show_spinner=False)
def build_indexes(data: dict, fingerprint: tuple[int, int]) -> dict:
    del fingerprint
    objects = [obj for obj in data.get("objects", []) if isinstance(obj, dict) and _active(obj)]
    by_id = {obj["id"]: obj for obj in objects if isinstance(obj.get("id"), str)}
    by_type: dict[str, list[dict]] = {}
    for obj in objects:
        by_type.setdefault(obj.get("type", ""), []).append(obj)

    relationships = [
        obj for obj in by_type.get("relationship", [])
        if obj.get("source_ref") in by_id and obj.get("target_ref") in by_id
    ]
    techniques_by_group: dict[str, set[str]] = {}
    malware_by_group: dict[str, set[str]] = {}
    tools_by_group: dict[str, set[str]] = {}
    campaigns_by_group: dict[str, set[str]] = {}
    techniques_by_software: dict[str, set[str]] = {}
    mitigations_by_technique: dict[str, set[str]] = {}

    for rel in relationships:
        relation_type = rel.get("relationship_type")
        source_id = rel["source_ref"]
        target_id = rel["target_ref"]
        source = by_id[source_id]
        target = by_id[target_id]
        source_type = source.get("type")
        target_type = target.get("type")

        if relation_type == "uses":
            if source_type == "intrusion-set":
                if target_type == "attack-pattern":
                    techniques_by_group.setdefault(source_id, set()).add(target_id)
                elif target_type == "malware":
                    malware_by_group.setdefault(source_id, set()).add(target_id)
                elif target_type == "tool":
                    tools_by_group.setdefault(source_id, set()).add(target_id)
            elif source_type in {"malware", "tool"} and target_type == "attack-pattern":
                techniques_by_software.setdefault(source_id, set()).add(target_id)

        elif relation_type == "mitigates" and source_type == "course-of-action" and target_type == "attack-pattern":
            mitigations_by_technique.setdefault(target_id, set()).add(source_id)

        elif relation_type == "attributed-to" and source_type == "campaign" and target_type == "intrusion-set":
            campaigns_by_group.setdefault(target_id, set()).add(source_id)

    return {
        "objects": objects,
        "by_id": by_id,
        "by_type": by_type,
        "relationships": relationships,
        "techniques_by_group": techniques_by_group,
        "malware_by_group": malware_by_group,
        "tools_by_group": tools_by_group,
        "campaigns_by_group": campaigns_by_group,
        "techniques_by_software": techniques_by_software,
        "mitigations_by_technique": mitigations_by_technique,
    }


@st.cache_data(show_spinner=False)
def get_groups(fingerprint: tuple[int, int]) -> list[dict]:
    del fingerprint
    return load_apt_groups()


def _mitre_link(obj: dict) -> str:
    for ref in obj.get("external_references", []):
        url = ref.get("url", "")
        if isinstance(url, str) and url.startswith(ATTACK_BASE_URL + "/"):
            return url
    return ""


def _spec_version(data: dict) -> str | None:
    for obj in data.get("objects", []):
        if obj.get("type") == "x-mitre-matrix":
            version = obj.get("x_mitre_attack_spec_version")
            if version:
                return str(version)
    return None


def _version_tuple(value: str | None) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in (value or "").split("."))
    except ValueError:
        return ()


def _save_bundle(data: dict) -> None:
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=DATA_FILE.parent, delete=False
    ) as handle:
        temporary_path = Path(handle.name)
        json.dump(data, handle, ensure_ascii=False)
        handle.flush()
        os.fsync(handle.fileno())
    temporary_path.replace(DATA_FILE)


def _count_values(groups: list[dict], field: str) -> Counter:
    counts = Counter()
    for group in groups:
        counts.update(set(_values(group.get(field))))
    return counts


def _entity_options(objects: list[dict]) -> list[str]:
    return sorted(
        [obj["id"] for obj in objects if obj.get("id") and obj.get("name")],
        key=lambda object_id: (
            objects_by_id.get(object_id, {}).get("name", "").casefold(),
            object_id,
        ),
    )


try:
    stat = DATA_FILE.stat()
    fingerprint = (stat.st_mtime_ns, stat.st_size)
    attack_data = load_attack_data(str(DATA_FILE), *fingerprint)
except FileNotFoundError:
    fingerprint = (0, 0)
    attack_data = None
except (OSError, ValueError, json.JSONDecodeError) as error:
    fingerprint = (0, 0)
    attack_data = None
    local_data_error = str(error)
else:
    local_data_error = ""

if attack_data is None:
    st.title("🕵️ APTHunter")
    st.error(
        local_data_error
        or "No se encontró data/enterprise-attack.json o el archivo no se pudo leer."
    )
    st.write("Descarga una copia válida de ATT&CK Enterprise para iniciar la aplicación.")
    if st.button("Descargar datos oficiales de MITRE"):
        try:
            with st.spinner("Descargando y validando ATT&CK Enterprise…"):
                remote_data = fetch_remote_attack_data()
                _save_bundle(remote_data)
            st.cache_data.clear()
            st.rerun()
        except (requests.RequestException, ValueError, OSError) as error:
            st.error(f"No se pudo descargar una copia válida: {error}")
    st.stop()

indexes = build_indexes(attack_data, fingerprint)
groups = get_groups(fingerprint)
choices = load_choices(str(CHOICES_FILE))
attack_version = attack_data.get("version")
attack_spec = _spec_version(attack_data)

with st.sidebar:
    st.title("🕵️ APTHunter")
    st.caption("Explorador de inteligencia de amenazas · MITRE ATT&CK")
    st.divider()
    st.subheader("Datos")
    if attack_spec:
        st.caption(f"ATT&CK spec local: **{attack_spec}**")
    elif attack_version:
        st.caption(f"Dataset local: **{attack_version}**")
    st.caption(f"{len(groups):,} grupos · {len(indexes['objects']):,} objetos activos")
    if st.button("Comprobar actualizaciones", use_container_width=True):
        with st.spinner("Consultando MITRE…"):
            try:
                remote_data = fetch_remote_attack_data()
                st.session_state["remote_attack_data"] = remote_data
                st.session_state["remote_check_error"] = ""
            except (requests.RequestException, ValueError) as error:
                st.session_state["remote_check_error"] = str(error)

    remote_error = st.session_state.get("remote_check_error")
    remote_data = st.session_state.get("remote_attack_data")
    if remote_error:
        st.warning(f"No se pudo consultar MITRE: {remote_error}")
    elif remote_data:
        remote_spec = _spec_version(remote_data)
        if remote_spec and attack_spec and _version_tuple(remote_spec) > _version_tuple(attack_spec):
            st.info(f"Hay una versión más nueva: **{remote_spec}**.")
            if st.button("Actualizar base local", type="primary", use_container_width=True):
                try:
                    _save_bundle(remote_data)
                    st.session_state.pop("remote_attack_data", None)
                    st.session_state.pop("remote_check_error", None)
                    st.cache_data.clear()
                    st.rerun()
                except OSError as error:
                    st.error(f"No se pudo guardar la actualización: {error}")
        elif remote_spec and attack_spec:
            st.success("La base local está actualizada.")
        else:
            st.info("MITRE respondió, pero no se encontró la versión spec en una de las bases.")

    st.divider()
    st.caption("Fuente: MITRE ATT&CK Enterprise. Revisa las referencias antes de tomar decisiones.")

st.title("APTHunter")
st.markdown(
    "Explora grupos, técnicas y herramientas documentadas en ATT&CK. "
    "Los filtros usan los campos publicados por MITRE."
)

countries = sorted(
    set(_values(choices.get("countries", [])))
    | {value for group in groups for value in _values(group.get("countries"))},
    key=str.casefold,
)
sectors = sorted(
    set(_values(choices.get("sectors", [])))
    | {value for group in groups for value in _values(group.get("sectors"))},
    key=str.casefold,
)

metric_cols = st.columns(4)
metric_cols[0].metric("Grupos", f"{len(groups):,}")
metric_cols[1].metric("Técnicas", f"{len(indexes['by_type'].get('attack-pattern', [])):,}")
metric_cols[2].metric("Malware", f"{len(indexes['by_type'].get('malware', [])):,}")
metric_cols[3].metric("Campañas", f"{len(indexes['by_type'].get('campaign', [])):,}")

tab_search, tab_techniques, tab_malware, tab_tools, tab_campaigns, tab_stats = st.tabs(
    ["🔎 Grupos", "🛡️ ATT&CK", "🦠 Malware", "🧰 Herramientas", "🎯 Campañas", "📊 Estadísticas"]
)


with tab_search:
    st.subheader("Buscar grupos")
    first, second, third = st.columns([2, 1, 1])
    query = first.text_input("Nombre o alias", placeholder="Ej.: APT29, Cozy Bear…")
    country_filter = second.selectbox("País", ["Todos"] + countries)
    sector_filter = third.selectbox("Sector", ["Todos"] + sectors)

    results = groups
    if query.strip():
        query_lower = query.strip().casefold()
        alias_matches = {group["id"] for group in find_group_by_alias(groups, query)}
        results = [
            group for group in results
            if group.get("id") in alias_matches
            or query_lower in group.get("name", "").casefold()
        ]
    if country_filter != "Todos":
        results = filter_by_country(results, country_filter)
    if sector_filter != "Todos":
        results = filter_by_sector(results, sector_filter)

    st.caption(f"{len(results):,} resultado(s)")
    if results:
        export_frame = pd.DataFrame([
            {
                "Nombre": group.get("name", ""),
                "ID ATT&CK": group.get("id", ""),
                "Alias": ", ".join(_values(group.get("aliases"))),
                "Países": ", ".join(_values(group.get("countries"))),
                "Sectores": ", ".join(_values(group.get("sectors"))),
                "Tácticas": ", ".join(_values(group.get("tactics"))),
                "Técnicas": ", ".join(_values(group.get("techniques"))),
                "Malware": ", ".join(_values(group.get("malware"))),
                "Herramientas": ", ".join(_values(group.get("tools"))),
                "Campañas": ", ".join(_values(group.get("campaigns"))),
                "MITRE": group.get("url", ""),
                "Descripción": group.get("description", ""),
            }
            for group in results
        ])
        st.download_button(
            "Descargar resultados CSV",
            data=export_frame.to_csv(index=False).encode("utf-8-sig"),
            file_name="apthunter-grupos.csv",
            mime="text/csv",
        )

        for group in results:
            with st.container(border=True):
                title_col, link_col = st.columns([5, 1])
                title_col.subheader(group.get("name", "Grupo sin nombre"))
                if group.get("url"):
                    link_col.link_button("MITRE ↗", group["url"], use_container_width=True)
                aliases = _values(group.get("aliases"))
                if aliases:
                    st.caption("Alias: " + " · ".join(aliases))
                summary_cols = st.columns(4)
                summary_cols[0].caption("Países")
                summary_cols[0].write(", ".join(_values(group.get("countries"))) or "Sin datos")
                summary_cols[1].caption("Sectores")
                summary_cols[1].write(", ".join(_values(group.get("sectors"))) or "Sin datos")
                summary_cols[2].caption("Tácticas")
                summary_cols[2].write(", ".join(_values(group.get("tactics"))) or "Sin datos")
                summary_cols[3].caption("Técnicas")
                summary_cols[3].write(str(len(_values(group.get("techniques")))))
                related = []
                for label, field in (("Malware", "malware"), ("Herramientas", "tools"), ("Campañas", "campaigns")):
                    names = _values(group.get(field))
                    if names:
                        related.append(f"**{label}:** {', '.join(names)}")
                if related:
                    st.markdown("  ·  ".join(related))
                with st.expander("Descripción"):
                    st.text(group.get("description") or "Sin descripción disponible.")
    else:
        st.info("No hay grupos que coincidan con esos filtros.")


with tab_techniques:
    st.subheader("Tácticas y técnicas")
    view = st.radio("Explorar por", ["Técnica", "Táctica"], horizontal=True, key="attack_view")
    if view == "Técnica":
        search = st.text_input("Buscar técnica", placeholder="Ej.: PowerShell, T1059…")
        technique_objects = indexes["by_type"].get("attack-pattern", [])
        if search.strip():
            term = search.strip().casefold()
            technique_objects = [
                obj for obj in technique_objects
                if term in obj.get("name", "").casefold()
                or any(term in ref.get("external_id", "").casefold() for ref in obj.get("external_references", []))
            ]
        technique_objects.sort(key=lambda obj: obj.get("name", "").casefold())
        if technique_objects:
            selected_id = st.selectbox(
                "Selecciona una técnica",
                [obj["id"] for obj in technique_objects],
                format_func=lambda object_id: (
                    f"{indexes['by_id'][object_id].get('name', 'Sin nombre')} · "
                    f"{next((ref.get('external_id') for ref in indexes['by_id'][object_id].get('external_references', []) if ref.get('source_name') == 'mitre-attack'), 'ATT&CK')}"
                ),
                key="technique_choice",
            )
            technique = indexes["by_id"][selected_id]
            st.markdown(f"### {technique.get('name', 'Técnica')}")
            st.text(technique.get("description", "Sin descripción disponible."))
            link = _mitre_link(technique)
            if link:
                st.link_button("Abrir en MITRE ATT&CK ↗", link)
            phases = sorted({
                phase.get("phase_name", "").replace("-", " ").title()
                for phase in technique.get("kill_chain_phases", [])
                if phase.get("phase_name")
            })
            if phases:
                st.markdown("**Tácticas:** " + " · ".join(phases))
            mitigation_ids = indexes["mitigations_by_technique"].get(selected_id, set())
            mitigations = [indexes["by_id"][item] for item in sorted(mitigation_ids) if item in indexes["by_id"]]
            if mitigations:
                st.markdown("**Mitigaciones**")
                for mitigation in mitigations:
                    with st.container(border=True):
                        st.markdown(f"**{mitigation.get('name', 'Mitigación')}**")
                        st.text(mitigation.get("description", ""))
        else:
            st.info("No se encontraron técnicas con ese texto.")
    else:
        tactics = indexes["by_type"].get("x-mitre-tactic", [])
        tactics.sort(key=lambda obj: obj.get("name", "").casefold())
        if tactics:
            selected_tactic_id = st.selectbox(
                "Selecciona una táctica",
                [obj["id"] for obj in tactics],
                format_func=lambda object_id: indexes["by_id"][object_id].get("name", "Táctica"),
                key="tactic_choice",
            )
            tactic = indexes["by_id"][selected_tactic_id]
            st.markdown(f"### {tactic.get('name', 'Táctica')}")
            st.text(tactic.get("description", ""))
            short_name = tactic.get("x_mitre_shortname", "")
            related = [
                obj.get("name", "")
                for obj in indexes["by_type"].get("attack-pattern", [])
                if any(
                    phase.get("phase_name") == short_name
                    and phase.get("kill_chain_name") == "mitre-attack"
                    for phase in obj.get("kill_chain_phases", [])
                )
            ]
            st.caption(f"{len(related)} técnicas asociadas")
            if related:
                st.write(", ".join(sorted(related, key=str.casefold))


def _show_software_tab(tab, object_type: str, title: str) -> None:
    with tab:
        st.subheader(title)
        objects = indexes["by_type"].get(object_type, [])
        objects = sorted(
            [obj for obj in objects if obj.get("name")],
            key=lambda obj: obj.get("name", "").casefold(),
        )
        if not objects:
            st.info(f"No hay registros activos de {title.lower()} en esta base.")
            return
        selected_id = st.selectbox(
            f"Selecciona {title.lower()}",
            [obj["id"] for obj in objects],
            format_func=lambda object_id: (
                f"{indexes['by_id'][object_id].get('name', 'Sin nombre')} · {object_id.rsplit('--', 1)[-1][:8]}"
            ),
            key=f"select_{object_type}",
        )
        selected = indexes["by_id"][selected_id]
        left, right = st.columns([2, 1])
        with left:
            st.markdown(f"### {selected.get('name', title)}")
            st.text(selected.get("description", "Sin descripción disponible."))
        with right:
            link = _mitre_link(selected)
            if link:
                st.link_button("Abrir en MITRE ATT&CK ↗", link)
            platforms = _values(selected.get("x_mitre_platforms"))
            if platforms:
                st.caption("Plataformas: " + ", ".join(platforms))

        technique_ids = indexes["techniques_by_software"].get(selected_id, set())
        technique_names = sorted({
            indexes["by_id"][tech_id].get("name", "")
            for tech_id in technique_ids
            if tech_id in indexes["by_id"] and indexes["by_id"][tech_id].get("name")
        }, key=str.casefold)
        if technique_names:
            with st.expander(f"Técnicas relacionadas ({len(technique_names)})"):
                st.write(", ".join(technique_names))


_show_software_tab(tab_malware, "malware", "Malware")
_show_software_tab(tab_tools, "tool", "Herramientas")


with tab_campaigns:
    st.subheader("Campañas")
    campaigns = sorted(
        [obj for obj in indexes["by_type"].get("campaign", []) if obj.get("name")],
        key=lambda obj: obj.get("name", "").casefold(),
    )
    if not campaigns:
        st.info("No hay campañas activas en esta base.")
    else:
        selected_campaign_id = st.selectbox(
            "Selecciona una campaña",
            [obj["id"] for obj in campaigns],
            format_func=lambda object_id: indexes["by_id"][object_id].get("name", "Campaña"),
            key="campaign_choice",
        )
        campaign = indexes["by_id"][selected_campaign_id]
        col1, col2 = st.columns([2, 1])
        with col1:
            st.markdown(f"### {campaign.get('name', 'Campaña')}")
            st.text(campaign.get("description", "Sin descripción disponible."))
        with col2:
            link = _mitre_link(campaign)
            if link:
                st.link_button("Abrir en MITRE ATT&CK ↗", link)
            first_seen = campaign.get("first_seen")
            last_seen = campaign.get("last_seen")
            if first_seen or last_seen:
                st.caption(f"Periodo: {first_seen or '?'} – {last_seen or '?'}")
            targets = _values(campaign.get("targets"))
            if targets:
                st.caption("Objetivos: " + ", ".join(targets))
        attributed_groups = sorted(
            [
                group.get("name", "")
                for group in groups
                if selected_campaign_id in indexes["campaigns_by_group"].get(group.get("id"), set())
            ],
            key=str.casefold,
        )
        if attributed_groups:
            st.markdown("**Grupos atribuidos:** " + ", ".join(attributed_groups))


with tab_stats:
    st.subheader("Resumen de actividad documentada")
    countries_count = _count_values(groups, "countries")
    sectors_count = _count_values(groups, "sectors")
    malware_count = _count_values(groups, "malware")
    technique_count = _count_values(groups, "techniques")

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("#### Grupos por país")
        if countries_count:
            country_frame = pd.DataFrame(
                countries_count.most_common(15), columns=["País", "Grupos"]
            ).set_index("País")
            st.bar_chart(country_frame)
        else:
            st.info("La base no incluye países para los grupos.")
    with col2:
        st.markdown("#### Sectores objetivo")
        if sectors_count:
            sector_frame = pd.DataFrame(
                sectors_count.most_common(15), columns=["Sector", "Grupos"]
            ).set_index("Sector")
            st.bar_chart(sector_frame)
        else:
            st.info("La base no incluye sectores objetivo para los grupos.")

    col3, col4 = st.columns(2)
    with col3:
        st.markdown("#### Técnicas asociadas a grupos")
        if technique_count:
            technique_frame = pd.DataFrame(
                technique_count.most_common(10), columns=["Técnica", "Grupos"]
            ).set_index("Técnica")
            st.bar_chart(technique_frame)
        else:
            st.info("No hay relaciones de técnicas disponibles.")
    with col4:
        st.markdown("#### Malware asociado a grupos")
        if malware_count:
            malware_frame = pd.DataFrame(
                malware_count.most_common(10), columns=["Malware", "Grupos"]
            ).set_index("Malware")
            st.bar_chart(malware_frame)
        else:
            st.info("No hay relaciones de malware disponibles en esta base.")

st.divider()
st.caption("APTHunter · Datos de MITRE ATT&CK. Las atribuciones reflejan la fuente y requieren contexto.")
