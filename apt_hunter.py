import argparse
import json
import os
import pandas as pd
from apt_hunter.filters import filter_by_country, find_group_by_alias, filter_by_sector
from apt_hunter.output import display_groups as print_groups
from apt_hunter.core import load_apt_groups


def load_choices():
    choices_path = os.path.join(os.path.dirname(__file__), "data", "choices.json")
    with open(choices_path, encoding="utf-8") as f:
        return json.load(f)


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
    countries = choices.get("countries", [])
    sectors = choices.get("sectors", [])
    aliases = choices.get("alias", [])

    if option == "1":
        show_list("Países comunes", countries)
        return "country", input("🌍 Escribe el país: ").strip()
    if option == "2":
        show_list("Aliases comunes", aliases)
        return "alias", input("🕵️ Escribe el alias: ").strip()
    if option == "3":
        show_list("Sectores comunes", sectors)
        return "sector", input("🏢 Escribe el sector: ").strip()
    if option == "4":
        return "all", None
    return "exit", None


def main():
    parser = argparse.ArgumentParser(description="APT-Hunter CLI")
    parser.add_argument("--country", type=str, help="Filtrar grupos por país")
    parser.add_argument("--alias", type=str, help="Buscar grupo por alias")
    parser.add_argument("--sector", type=str, help="Filtrar grupos por sector")
    parser.add_argument(
        "--export-csv",
        metavar="PATH",
        help="Exportar resultados a un archivo CSV",
    )
    args = parser.parse_args()

    # Si no se pasan argumentos, lanzar menú
    if not any(vars(args).values()):
        option, value = interactive_menu()
        if option == "exit":
            print("👋 Hasta pronto.")
            return
        if option == "country":
            args.country = value
        elif option == "alias":
            args.alias = value
        elif option == "sector":
            args.sector = value

    groups = load_apt_groups()

    if args.country:
        groups = filter_by_country(groups, args.country)
    if args.alias:
        groups = find_group_by_alias(groups, args.alias)
    if args.sector:
        groups = filter_by_sector(groups, args.sector)

    if args.export_csv:
        export_data = [
            {
                "Nombre": group["name"],
                "Alias": ", ".join(group.get("aliases", [])),
                "Tácticas": ", ".join(group.get("tactics", [])),
                "Técnicas": ", ".join(group.get("techniques", [])),
                "Sectores": ", ".join(group.get("sectors", [])),
                "Descripción": group.get("description", ""),
                "URL": group.get("url", ""),
            }
            for group in groups
        ]
        df = pd.DataFrame(export_data)
        df.to_csv(args.export_csv, index=False, encoding="utf-8")
        print(f"✅ Resultados exportados a {args.export_csv}")
    else:
        print_groups(groups)


if __name__ == "__main__":
    main()
