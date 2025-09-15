import requests
from dotenv import load_dotenv
import os

load_dotenv()

TOKEN = os.getenv("GITHUB_TOKEN")  # env var

session = requests.Session()
session.headers.update({
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/vnd.github.raw+json",
    "X-GitHub-Api-Version": "2022-11-28",
})

def get_vulnerable_source(owner, repo, url, file_path):
    try:
        parent_commit_sha = get_commit_parent_sha(url)

        url = f"https://raw.githubusercontent.com/{owner}/{repo}/{parent_commit_sha}{file_path}"

        resp = session.get(url)
        resp.raise_for_status()
        source_code = resp.text
    except requests.exceptions.HTTPError as err:
        raise ValueError(err)

    return parent_commit_sha, source_code


def get_commit_parent_sha(url):
    resp = session.get(url)
    resp.raise_for_status()

    data = resp.json()
    parents = data.get("parents", [])

    if parents:
        return parents[0].get("sha")
    return None
