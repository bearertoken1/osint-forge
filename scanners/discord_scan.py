import requests
import webbrowser

def discord_user_scan(discord_user, avatar=False, servers=False, breaches=False, social=False):
    print(f"[+] Discord OSINT for: {discord_user}")
    if avatar:
        if discord_user.isdigit() and len(discord_user) >= 17:
            print("-> For avatars, use: https://cdn.discordapp.com/avatars/<user_id>/<avatar_hash>.png")
            print("-> Use https://discord.id/ to get avatar hash.")
            webbrowser.open("https://discord.id/")
        else:
            print("-> Please provide a valid user ID (17+ digit number) for avatar lookup.")
    if servers:
        print("-> Searching Discord servers (manual):")
        print("   - https://discord.me/search")
        webbrowser.open("https://discord.me/search")
        print("   - https://disboard.org/search")
        webbrowser.open("https://disboard.org/search")
        print("   - https://discordlist.net/search")
        webbrowser.open("https://discordlist.net/search")
        print("   - Try searching for the username in server member lists.")
    if breaches:
        print("-> Searching for breaches (manual):")
        print("   - https://raidforums.com (if available)")
        print("   - https://pastebin.com/search?q={}".format(discord_user))
        webbrowser.open(f"https://pastebin.com/search?q={discord_user}")
        print("   - https://intelx.io/?s={}".format(discord_user))
        webbrowser.open(f"https://intelx.io/?s={discord_user}")
        print("   - https://dehashed.com/search?query={}".format(discord_user))
        webbrowser.open(f"https://dehashed.com/search?query={discord_user}")
    if social:
        print("-> Searching on social platforms:")
        print("   - Twitter: https://twitter.com/search?q={}".format(discord_user))
        webbrowser.open(f"https://twitter.com/search?q={discord_user}")
        print("   - GitHub: https://github.com/search?q={}".format(discord_user))
        webbrowser.open(f"https://github.com/search?q={discord_user}")
        print("   - Reddit: https://reddit.com/search?q={}".format(discord_user))
        webbrowser.open(f"https://reddit.com/search?q={discord_user}")
    if not any([avatar, servers, breaches, social]):
        print("-> Try searching this user on Discord servers, Discord.me, Disboard.org, and Discordlist.net.")
        print("-> Check for leaks on RaidForums, Pastebin, and other breach sites.")
        print("-> Google dork: site:discord.com intext:\"{}\"".format(discord_user))
        print("-> If you have the user ID, try https://discord.id/")
        print("-> For avatars, use: https://cdn.discordapp.com/avatars/<user_id>/<avatar_hash>.png")
        print("-> For more, try searching their tag on Twitter, GitHub, and other platforms.")
