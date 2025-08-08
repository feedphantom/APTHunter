import argparse
import json
import os
import pandas as pd
from apt_hunter.filters import filter_by_country
from apt_hunter.filters import find_group_by_alias
from apt_hunter.filters import filter_by_sector
from apt_hunter.output import display_groups as print_groups
from apt_hunter.core import load_apt_groups


def load_choices():
    with open(
        os.path.join(os.path.dirname(__file__), "data/choices.json"), encoding="utf-8"
    ) as f:
        choices = json.load(f)
    return choices["countries"], choices["sectors"]


def show_list(title, items):
    print(f"\n🔹 {title}:")
    for i, item in enumerate(items, 1):
        print(f"  {i}. {item}")


def interactive_menu():
    print("🔍 Bienvenido a APT-Hunter")
    print("Selecciona una opción:")
    print("1. Buscar grupos por país")
    print("2. Buscar grupos por alias")
    print("3. Buscar grupos por sector")
    print("4. Ver todos los grupos APT")
    print("0. Salir")

    option = input("Introduce el número de tu elección: ").strip()
    choices = load_choices()
    COUNTRIES = choices["countries"]
    SECTORS = choices["sectors"]
    ALIASES = choices["alias"]

    if option == "1":
        show_list("Países comunes", COUNTRIES)
        return "country", input("🌍 Escribe el país: ").strip()
    elif option == "2":
        show_list("Aliases comunes", ALIASES)
        return "alias", input("🕵️ Escribe el alias: ").strip()
    elif option == "3":
        show_list("Sectores comunes", SECTORS)
        return "sector", input("🏢 Escribe el sector: ").strip()
    elif option == "4":
        return "all", None
    else:
        return "exit", None


def main():
    parser = argparse.ArgumentParser(description="APT-Hunter CLI")
    parser.add_argument("--country", type=str, help="Filtrar grupos por país")
    parser.add_argument("--alias", type=str, help="Buscar grupo por alias")
    parser.add_argument("--sector", type=str, help="Filtrar grupos por sector")
    args = parser.parse_args()

    # Si no se pasan argumentos, lanzar menú
    if not any(vars(args).values()):
        option, value = interactive_menu()
        if option == "exit":
            print("👋 Hasta pronto.")
            return
        elif option == "country":
            args.country = value
        elif option == "alias":
            args.alias = value
        elif option == "sector":
            args.sector = value
        elif option == "all":
            pass  # No filtros

    groups = load_apt_groups()

    if args.country:
        groups = filter_by_country(groups, args.country)

    if args.alias:
        groups = find_group_by_alias(groups, args.alias)

    if args.sector:
        groups = filter_by_sector(groups, args.sector)

    if args.export_csv:

        export_data = []
        for g in groups:
            export_data.append(
                {
                    "Nombre": g["name"],
                    "Alias": ", ".join(g["aliases"]),
                    "Tácticas": ", ".join(g.get("tactics", [])),
                    "Técnicas": ", ".join(g.get("techniques", [])),
                    "Sectores": ", ".join(g.get("sectors", [])),
                    "Descripción": g["description"],
                    "URL": g["url"],
                }
            )
        df = pd.DataFrame(export_data)
        df.to_csv(args.export_csv, index=False, encoding="utf-8")
        print(f"✅ Resultados exportados a {args.export_csv}")
    else:
        print_groups(groups)


if __name__ == "__main__":
    main()
