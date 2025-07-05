# OSINT Forge Custom Commands

## Custom Scan
Scan a username on a custom list of sites:
```
python main.py customscan <username> --sites Twitter Instagram GitHub
```

## Discord User Scan
Scan a Discord user:
```
python main.py discord <discord_user#discriminator or user_id>
```

## Reverse Image Search
Get links for reverse image search:
```
python main.py reverseimg <image_path>
```

## Email Pattern Generator
Generate common email patterns:
```
python main.py emailpattern "First Last" example.com
```

## Metadata Extraction
Extract file metadata:
```
python main.py metadata <file_path>
```
