def _as_values(value):
    """Normalize a scalar or collection field to comparable strings."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple, set)):
        return [item for item in value if isinstance(item, str)]
    return []


def filter_by_country(groups, country):
    country = country.strip().casefold()
    if not country:
        return []
    return [
        group
        for group in groups
        if isinstance(group, dict)
        and any(value.casefold() == country for value in _as_values(group.get("countries")))
    ]


def filter_by_sector(groups, sector):
    sector = sector.strip().casefold()
    if not sector:
        return []
    return [
        group
        for group in groups
        if isinstance(group, dict)
        and any(value.casefold() == sector for value in _as_values(group.get("sectors")))
    ]


def find_group_by_alias(groups, alias):
    alias = alias.strip().casefold()
    if not alias:
        return []
    matched_groups = []
    for group in groups:
        if not isinstance(group, dict):
            continue
        aliases = _as_values(group.get("aliases"))
        if any(alias in value.casefold() for value in aliases):
            matched_groups.append(group)
    return matched_groups
