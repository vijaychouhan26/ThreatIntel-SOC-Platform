"""Known threat-actor catalog used to enrich extracted APT/UNC/TA names."""

def mitre(gid):
    return f"https://attack.mitre.org/groups/{gid}/"

ACTORS = [
    {"name": "APT1", "aliases": ["Comment Crew", "Comment Panda"], "origin_country": "China",
     "target_sectors": ["government", "technology", "manufacturing"], "mitre_id": "G0006",
     "description": "China-nexus cyber espionage group associated with PLA Unit 61398. Long-running theft of intellectual property from Western organizations."},
    {"name": "APT3", "aliases": ["Gothic Panda", "UPS Team", "Buckeye"], "origin_country": "China",
     "target_sectors": ["aerospace", "defense", "technology"], "mitre_id": "G0022",
     "description": "China-nexus group known for zero-day exploitation and long-term access into defense and high-tech networks."},
    {"name": "APT28", "aliases": ["Fancy Bear", "Sofacy", "STRONTIUM", "Forest Blizzard", "Pawn Storm"], "origin_country": "Russia",
     "target_sectors": ["government", "military", "political", "media"], "mitre_id": "G0007",
     "description": "Russian military intelligence (GRU) actor. High-profile operations against governments, political parties, and military organizations, including destructive and influence campaigns."},
    {"name": "APT29", "aliases": ["Cozy Bear", "The Dukes", "NOBELIUM", "Midnight Blizzard", "SVR"], "origin_country": "Russia",
     "target_sectors": ["government", "diplomacy", "think tanks", "cloud"], "mitre_id": "G0016",
     "description": "Russian SVR-linked espionage group. Known for stealthy cloud identity abuse, SolarWinds-style supply-chain operations, and targeting diplomatic/government tenants."},
    {"name": "APT31", "aliases": ["Zirconium", "Judgment Panda", "Violet Typhoon"], "origin_country": "China",
     "target_sectors": ["government", "political", "telecommunications"], "mitre_id": "G0027",
     "description": "China-nexus espionage actor targeting governments, political organizations, and telecoms, often via spear-phishing and web compromise."},
    {"name": "APT32", "aliases": ["OceanLotus", "SeaLotus", "APT-C-00"], "origin_country": "Vietnam",
     "target_sectors": ["government", "media", "human rights", "private sector"], "mitre_id": "G0050",
     "description": "Vietnam-aligned actor conducting strategic web compromises and targeted malware campaigns against regional governments, journalists, and companies."},
    {"name": "APT33", "aliases": ["Elfin", "Peach Sandstorm", "HOLMIUM"], "origin_country": "Iran",
     "target_sectors": ["aerospace", "energy", "petrochemical"], "mitre_id": "G0064",
     "description": "Iran-nexus group focused on aerospace and energy. Mix of espionage and destructive tooling around industrial environments."},
    {"name": "APT34", "aliases": ["OilRig", "Helix Kitten", "EUROPIUM"], "origin_country": "Iran",
     "target_sectors": ["government", "energy", "finance", "telecommunications"], "mitre_id": "G0049",
     "description": "Iran-nexus cyber espionage actor using supply-chain and credential attacks against Middle East governments and critical infrastructure."},
    {"name": "APT35", "aliases": ["Charming Kitten", "Phosphorus", "Mint Sandstorm", "TA453"], "origin_country": "Iran",
     "target_sectors": ["academia", "journalism", "NGOs", "government"], "mitre_id": "G0059",
     "description": "Iran-nexus group specializing in social engineering, credential harvesting, and long-term surveillance of activists, journalists, and researchers."},
    {"name": "APT36", "aliases": ["Transparent Tribe", "Mythic Leopard", "Earth Karkaddan"], "origin_country": "Pakistan",
     "target_sectors": ["government", "military", "education", "defense"], "mitre_id": "G0134",
     "description": "Pakistan-nexus actor targeting Indian government, military, and education sectors with Crimson RAT and related malware."},
    {"name": "APT37", "aliases": ["Reaper", "ScarCruft", "Group123", "Ricochet Chollima"], "origin_country": "North Korea",
     "target_sectors": ["government", "media", "chemical", "aerospace"], "mitre_id": "G0067",
     "description": "DPRK-linked group using strategic web compromises and mobile/desktop implants against South Korean and other regional targets."},
    {"name": "APT38", "aliases": ["Lazarus Group", "HIDDEN COBRA", "Stardust Chollima", "BlueNoroff", "Andariel"], "origin_country": "North Korea",
     "target_sectors": ["finance", "cryptocurrency", "defense", "media"], "mitre_id": "G0082",
     "description": "DPRK financially motivated subset associated with SWIFT heists, cryptocurrency theft, and destructive wipers (WannaCry lineage). Closely tied to Lazarus."},
    {"name": "Lazarus Group", "aliases": ["HIDDEN COBRA", "Guardians of Peace", "APT38", "Andariel", "BlueNoroff"], "origin_country": "North Korea",
     "target_sectors": ["finance", "cryptocurrency", "defense", "media", "supply chain"], "mitre_id": "G0032",
     "description": "North Korean state-sponsored cluster spanning espionage, sabotage, and cybercrime. Responsible for high-profile bank heists, crypto theft, and destructive attacks."},
    {"name": "APT41", "aliases": ["Winnti", "Barium", "Wicked Panda", "Brass Typhoon"], "origin_country": "China",
     "target_sectors": ["healthcare", "telecom", "video games", "government", "technology"], "mitre_id": "G0096",
     "description": "China-nexus actor that blends state espionage with financially motivated intrusion. Frequent use of supply-chain compromise and dual-use malware."},
    {"name": "APT42", "aliases": ["Charming Kitten", "CALANQUE"], "origin_country": "Iran",
     "target_sectors": ["NGOs", "media", "academia", "legal"], "mitre_id": "",
     "description": "Iran-nexus intelligence collection set focused on personal-account compromise of NGOs, media, and academia rather than enterprise malware."},
    {"name": "APT43", "aliases": ["Kimsuky", "Thallium", "Velvet Chollima", "Black Banshee"], "origin_country": "North Korea",
     "target_sectors": ["government", "think tanks", "nuclear", "academia"], "mitre_id": "G0094",
     "description": "DPRK intelligence-focused cluster (Kimsuky) targeting foreign policy, nuclear, and peninsula-related research through spear-phishing and credential theft."},
    {"name": "Kimsuky", "aliases": ["APT43", "Thallium", "Velvet Chollima"], "origin_country": "North Korea",
     "target_sectors": ["government", "think tanks", "academia"], "mitre_id": "G0094",
     "description": "North Korean cyber-espionage group specializing in spear-phishing, document stealers, and credential harvesting against policy and academic targets."},
    {"name": "APT44", "aliases": ["Sandworm", "Voodoo Bear", "IRIDIUM", "Seashell Blizzard"], "origin_country": "Russia",
     "target_sectors": ["energy", "government", "critical infrastructure"], "mitre_id": "G0034",
     "description": "GRU-linked Sandworm team. Known for NotPetya, Ukraine power-grid attacks, and other disruptive operations against critical infrastructure."},
    {"name": "Sandworm", "aliases": ["APT44", "Voodoo Bear", "TeleBots"], "origin_country": "Russia",
     "target_sectors": ["energy", "government", "critical infrastructure"], "mitre_id": "G0034",
     "description": "Russian GRU unit 74455. Conducts destructive and disruptive attacks, including NotPetya and multiple Ukrainian energy-sector incidents."},
    {"name": "APT24", "aliases": ["PittyTiger", "OceanSalt"], "origin_country": "China",
     "target_sectors": ["government", "technology"], "mitre_id": "",
     "description": "China-nexus intrusion set observed in long-running espionage against government and technology organizations."},
    {"name": "Volt Typhoon", "aliases": ["BRONZE SILHOUETTE", "Vanguard Panda", "Insider", "UNC3236"], "origin_country": "China",
     "target_sectors": ["critical infrastructure", "communications", "energy", "transportation", "water"], "mitre_id": "G1017",
     "description": "PRC living-off-the-land actor pre-positioning in US critical infrastructure. Relies on valid accounts, built-in tools, and stealth rather than custom malware."},
    {"name": "Salt Typhoon", "aliases": ["UNC5807", "GhostEmperor"], "origin_country": "China",
     "target_sectors": ["telecommunications", "government"], "mitre_id": "",
     "description": "China-nexus actor associated with deep compromise of global telecommunications providers and lawful-intercept infrastructure."},
    {"name": "Flax Typhoon", "aliases": ["Ethereal Panda"], "origin_country": "China",
     "target_sectors": ["government", "education", "manufacturing", "IT"], "mitre_id": "G1014",
     "description": "China-nexus group using LOTL techniques and VPN appliances for persistent access into Taiwan and other regional targets."},
    {"name": "Mustang Panda", "aliases": ["TA416", "RedDelta", "Bronze President"], "origin_country": "China",
     "target_sectors": ["government", "NGOs", "religious organizations", "diplomacy"], "mitre_id": "G0129",
     "description": "China-nexus espionage actor using PlugX and related loaders in diplomatic and NGO targeting, often via USB and archive lures."},
    {"name": "Turla", "aliases": ["Snake", "Uroburos", "Venomous Bear", "Waterbug"], "origin_country": "Russia",
     "target_sectors": ["government", "diplomacy", "military", "research"], "mitre_id": "G0010",
     "description": "Russian FSB-linked actor known for the Snake/Uroburos rootkit, hijacking other actors' infrastructure, and long-term diplomatic espionage."},
    {"name": "Gamaredon", "aliases": ["Primitive Bear", "Armageddon", "Shuckworm"], "origin_country": "Russia",
     "target_sectors": ["government", "military", "NGOs"], "mitre_id": "G0047",
     "description": "Russia-nexus actor heavily targeting Ukrainian government and military with high-volume phishing and custom PowerShell/VBS malware."},
    {"name": "FIN7", "aliases": ["Carbanak", "ELBRUS", "Sangria Tempest"], "origin_country": "Unknown",
     "target_sectors": ["retail", "hospitality", "finance", "restaurants"], "mitre_id": "G0046",
     "description": "Financially motivated group behind point-of-sale and later ransomware/extortion operations. High operational security and custom malware."},
    {"name": "FIN8", "aliases": ["Syssphinx"], "origin_country": "Unknown",
     "target_sectors": ["hospitality", "retail", "finance"], "mitre_id": "G0061",
     "description": "Cybercrime actor using Badhatch/ Sardonic tooling against payment environments and later expanding into ransomware affiliate activity."},
    {"name": "Wizard Spider", "aliases": ["UNC1878", "Gold Blackburn", "Trickbot"], "origin_country": "Russia",
     "target_sectors": ["healthcare", "enterprise", "government"], "mitre_id": "G0102",
     "description": "Cybercrime syndicate behind TrickBot, BazarLoader, and Conti/Ryuk ransomware affiliate operations against enterprises worldwide."},
    {"name": "Scattered Spider", "aliases": ["UNC3944", "Starfraud", "Muddled Libra", "Octo Tempest"], "origin_country": "Unknown",
     "target_sectors": ["telecom", "BPO", "casino", "technology", "retail"], "mitre_id": "G1015",
     "description": "English-speaking cybercrime cluster using social engineering, SIM swap, and SaaS/identity abuse. Frequently partners with ransomware affiliates."},
    {"name": "UNC3944", "aliases": ["Scattered Spider", "Octo Tempest", "Muddled Libra"], "origin_country": "Unknown",
     "target_sectors": ["telecom", "BPO", "casino", "technology"], "mitre_id": "G1015",
     "description": "Mandiant designation for the Scattered Spider identity-focused cybercrime cluster."},
    {"name": "TA505", "aliases": ["Hive0065"], "origin_country": "Unknown",
     "target_sectors": ["finance", "retail", "healthcare"], "mitre_id": "G0092",
     "description": "High-volume cybercrime distributor of Dridex, Locky, Clop, and Get2. Known for large malspam campaigns and CL0P ransomware/extortion."},
    {"name": "TA578", "aliases": [], "origin_country": "Unknown",
     "target_sectors": ["enterprise", "finance"], "mitre_id": "",
     "description": "Cybercrime actor using callback phishing (BEC-style) and later delivering infostealers or ransomware access."},
    {"name": "TA582", "aliases": [], "origin_country": "Unknown",
     "target_sectors": ["enterprise"], "mitre_id": "",
     "description": "Email threat actor observed in credential-phishing and malware distribution campaigns tracked by Proofpoint."},
    {"name": "Andariel", "aliases": ["Onyx Sleet", "Silent Chollima", "APT45"], "origin_country": "North Korea",
     "target_sectors": ["defense", "government", "energy", "finance"], "mitre_id": "G0138",
     "description": "DPRK Reconnaissance General Bureau subset conducting espionage and ransomware/crypto theft to fund operations."},
    {"name": "Andromeda", "aliases": ["Gamarue"], "origin_country": "Unknown",
     "target_sectors": ["consumers", "enterprise"], "mitre_id": "",
     "description": "Long-running malware distribution botnet historically used to push additional payloads; remnants still appear in IOC feeds."},
    {"name": "MuddyWater", "aliases": ["Seedworm", "TEMP.Zagros", "Static Kitten", "Mango Sandstorm"], "origin_country": "Iran",
     "target_sectors": ["government", "telecom", "oil", "NGOs"], "mitre_id": "G0069",
     "description": "Iran-nexus actor using macros, remote-management tools, and phishing against Middle East and neighboring governments."},
    {"name": "OilRig", "aliases": ["APT34", "Helix Kitten"], "origin_country": "Iran",
     "target_sectors": ["government", "energy", "finance"], "mitre_id": "G0049",
     "description": "Iran-nexus cyber espionage group using DNS tunneling, supply-chain compromise, and credential theft in the Middle East."},
    {"name": "Hafnium", "aliases": ["Silk Typhoon"], "origin_country": "China",
     "target_sectors": ["exchange", "government", "law firms", "NGOs"], "mitre_id": "G0125",
     "description": "China-nexus actor that mass-exploited Microsoft Exchange ProxyLogon and later targeted identity/cloud access for espionage."},
    {"name": "Midnight Blizzard", "aliases": ["APT29", "NOBELIUM", "Cozy Bear"], "origin_country": "Russia",
     "target_sectors": ["government", "cloud", "think tanks"], "mitre_id": "G0016",
     "description": "Microsoft designation for APT29/SVR operations, including password-spray and OAuth application abuse against cloud tenants."},
    {"name": "Forest Blizzard", "aliases": ["APT28", "Fancy Bear", "STRONTIUM"], "origin_country": "Russia",
     "target_sectors": ["government", "military", "political"], "mitre_id": "G0007",
     "description": "Microsoft designation for GRU APT28 activity, including exploitation of edge devices and credential theft."},
    {"name": "Seashell Blizzard", "aliases": ["Sandworm", "APT44", "IRIDIUM"], "origin_country": "Russia",
     "target_sectors": ["critical infrastructure", "energy"], "mitre_id": "G0034",
     "description": "Microsoft designation for Sandworm disruptive operations against energy and government networks."},
    {"name": "Peach Sandstorm", "aliases": ["APT33", "HOLMIUM"], "origin_country": "Iran",
     "target_sectors": ["aerospace", "energy"], "mitre_id": "G0064",
     "description": "Microsoft designation for APT33 password-spray and intelligence operations against energy and defense."},
    {"name": "Mint Sandstorm", "aliases": ["APT35", "Phosphorus"], "origin_country": "Iran",
     "target_sectors": ["activists", "media", "research"], "mitre_id": "G0059",
     "description": "Microsoft designation for APT35/Phosphorus social-engineering and zero-day targeting of high-value individuals."},
    {"name": "LockBit", "aliases": ["LockBit ransomware"], "origin_country": "Russia",
     "target_sectors": ["enterprise", "healthcare", "manufacturing", "government"], "mitre_id": "",
     "description": "Prolific ransomware-as-a-service brand. Affiliates combine double extortion with automated encryption across Windows and ESXi."},
    {"name": "Clop", "aliases": ["CL0P", "TA505"], "origin_country": "Unknown",
     "target_sectors": ["enterprise", "education", "finance", "healthcare"], "mitre_id": "",
     "description": "Ransomware/extortion group known for mass exploitation of file-transfer appliances (MOVEit, Accellion, Fortra) for data theft."},
    {"name": "Akira", "aliases": ["Akira ransomware"], "origin_country": "Unknown",
     "target_sectors": ["enterprise", "education", "manufacturing"], "mitre_id": "",
     "description": "Ransomware operation targeting VPN appliances and Windows/Linux environments with double extortion."},
    {"name": "BianLian", "aliases": ["Bianlian"], "origin_country": "Unknown",
     "target_sectors": ["professional services", "healthcare", "manufacturing"], "mitre_id": "",
     "description": "Ransomware/extortion group that shifted toward encryption-less data theft and leak-site pressure."},
    {"name": "Qilin", "aliases": ["Agenda"], "origin_country": "Unknown",
     "target_sectors": ["healthcare", "education", "enterprise"], "mitre_id": "",
     "description": "Ransomware-as-a-service brand (Agenda/Qilin) used by affiliates against enterprises, including healthcare."},
    {"name": "Play", "aliases": ["Play ransomware"], "origin_country": "Unknown",
     "target_sectors": ["government", "enterprise"], "mitre_id": "",
     "description": "Closed ransomware group exploiting VPN and ESXi, with intermittent leak-site extortion."},
    {"name": "RansomHub", "aliases": [], "origin_country": "Unknown",
     "target_sectors": ["enterprise", "healthcare"], "mitre_id": "",
     "description": "Ransomware affiliate program that absorbed operators after LockBit/BlackCat disruptions."},
    {"name": "Black Basta", "aliases": [], "origin_country": "Unknown",
     "target_sectors": ["enterprise", "manufacturing", "healthcare"], "mitre_id": "",
     "description": "Ransomware group using Qakbot/social engineering initial access and double extortion."},
    {"name": "INC Ransom", "aliases": ["INC Ransomware"], "origin_country": "Unknown",
     "target_sectors": ["healthcare", "education", "government"], "mitre_id": "",
     "description": "Ransomware operation frequently targeting education and healthcare with data-leak extortion."},
]

# Longer aliases first so "Lazarus Group" matches before "Lazarus" if we add short forms.
_ALIAS_INDEX = []
for actor in ACTORS:
    names = [actor["name"], *(actor.get("aliases") or [])]
    for n in names:
        if n and n.strip():
            _ALIAS_INDEX.append((n.strip(), actor))
_ALIAS_INDEX.sort(key=lambda x: len(x[0]), reverse=True)


def lookup_actor(name: str):
    if not name:
        return None
    key = name.strip().lower()
    for alias, actor in _ALIAS_INDEX:
        if alias.lower() == key:
            return actor
    return None


def catalog_matches(text: str):
    """Return unique catalog actors whose name/alias appears as a whole phrase."""
    if not text:
        return []
    lowered = text
    found = {}
    import re
    for alias, actor in _ALIAS_INDEX:
        if alias.lower() in {"play", "clop"}:  # too generic without boundaries
            pat = rf"(?<![A-Za-z0-9]){re.escape(alias)}(?:\s+ransomware)?(?![A-Za-z0-9])"
        else:
            pat = rf"(?<![A-Za-z0-9]){re.escape(alias)}(?![A-Za-z0-9])"
        if re.search(pat, lowered, re.IGNORECASE):
            found[actor["name"]] = actor
    return list(found.values())
