def display_groups(groups):
    if not groups:
        print("No matching APT groups found.")
        return

    for g in groups:
        print(f"\n🎯 Name: {g['name']}")
        if g["aliases"]:
            print(f"🔁 Aliases: {', '.join(g['aliases'])}")
        print(f"🔗 MITRE Link: {g['url']}")
        print(f"📝 Description: {g['description'][:300]}...\n")
