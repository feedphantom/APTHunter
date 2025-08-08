def filter_by_country(groups, country):
    country = country.lower()
    filtered = []
    for g in groups:
        desc = g.get("description", "")
        if isinstance(desc, str) and country in desc.lower():
            filtered.append(g)
    return filtered


def filter_by_sector(groups, sector):
    sector = sector.lower()
    filtered = []
    for g in groups:
        desc = g.get("description", "") if isinstance(g, dict) else ""
        if isinstance(desc, str) and sector in desc.lower():
            filtered.append(g)
    return filtered


def find_group_by_alias(groups, alias):
    alias = alias.lower()
    matched_groups = []
    for g in groups:
        aliases = g.get("aliases", [])
        if any(alias in a.lower() for a in aliases):
            matched_groups.append(g)
    return matched_groups
