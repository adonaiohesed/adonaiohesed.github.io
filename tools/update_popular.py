import os
import re
import yaml
import requests
import json

# Configuration
POSTS_DIR = "_posts"
POPULAR_DATA_FILE = "_data/popular.yml"
BUSUANZI_URL = "https://busuanzi.ibruce.info/busuanzi?jsonpCallback=BusuanziCallback_777"
SITE_URL = "https://adonaiohesed.github.io"

def get_posts_slugs():
    slugs = []
    for filename in os.listdir(POSTS_DIR):
        if filename.endswith(".md"):
            # Jekyll slug is usually the filename without date and extension
            # Format: YYYY-MM-DD-title.md
            match = re.match(r"\d{4}-\d{2}-\d{2}-(.+)\.md", filename)
            if match:
                slugs.append(match.group(1))
    return slugs

def fetch_busuanzi_count(slug):
    # This is a best-effort fetch. Busuanzi relies on Referer.
    # The API call looks like this:
    # https://busuanzi.ibruce.info/busuanzi?jsonpCallback=BusuanziCallback_777
    # with Referer: https://adonaiohesed.github.io/posts/slug/
    target_url = f"{SITE_URL}/posts/{slug}/"
    headers = {
        "Referer": target_url,
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    try:
        response = requests.get(BUSUANZI_URL, headers=headers, timeout=5)
        if response.status_code == 200:
            # Response is like: BusuanziCallback_777({"page_pv": 123, ...})
            match = re.search(r'\{.*\}', response.text)
            if match:
                data = json.loads(match.group(0))
                return data.get("page_pv", 0)
    except Exception as e:
        print(f"Error fetching {slug}: {e}")
    return 0

def update_popular():
    print("Checking view counts for all posts (this may take a while)...")
    slugs = get_posts_slugs()
    results = []
    
    for slug in slugs:
        count = fetch_busuanzi_count(slug)
        if count > 0:
            results.append({"slug": slug, "count": count})
            print(f"Found: {slug} -> {count} views")
        else:
            # Fallback if brand new or fetch failed
            results.append({"slug": slug, "count": 0})

    # Sort by count descending
    top_7 = sorted(results, key=lambda x: x["count"], reverse=True)[:7]
    
    # Write to YAML (clean list of slugs)
    output_data = [{"slug": x["slug"]} for x in top_7]
    
    with open(POPULAR_DATA_FILE, "w") as f:
        yaml.dump(output_data, f, sort_keys=False)
    
    print(f"\nSuccessfully updated {POPULAR_DATA_FILE} with top 7 posts!")

if __name__ == "__main__":
    if not os.path.exists("_data"):
        os.makedirs("_data")
    update_popular()
