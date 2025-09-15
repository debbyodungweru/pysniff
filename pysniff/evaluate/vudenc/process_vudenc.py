import json
import os
from pathlib import Path

from pysniff.evaluate import github_client


def _collect_file_info(data, file_name):
    results = []
    excluded = []
    for repo_url, commits in data.items():
        for fix_commit_sha, commit_data in commits.items():
            repo_url_parts = repo_url.split('/')
            owner = repo_url_parts[-2]
            repo = repo_url_parts[-1]
            url = commit_data.get("url")
            fix_html_url = commit_data.get("html_url")

            files = commit_data.get("files", {})
            for file_path, file_info in files.items():
                try:
                    vul_commit_sha, vulnerable_source = (
                        github_client.get_vulnerable_source(owner, repo, url, file_path))
                    vul_html_url = f"https://github.com/{owner}/{repo}/blob/{vul_commit_sha}"

                    results.append({
                        "html_url": vul_html_url,
                        "file_path": file_path,
                        "source": vulnerable_source,
                        "dataset" : file_name,
                    })
                except ValueError as e:
                    full_path = fix_html_url + file_path
                    excluded.append(full_path)

    return results, excluded


def _read_json_file(path):
    with open(path, "r", encoding="utf-8") as json_file:
        data = json.loads(json_file.read())

    return data


def process_datasets():
    """ Transform original dataset file to a simple format with necessary values only """
    dataset_dir = os.path.join(os.path.dirname(__file__), "datasets")
    path = Path(dataset_dir)

    if path.exists() and path.is_dir():
        for p in path.iterdir():
            if p.is_file():
                print(f"Processing {p}...")
                json_data = (_read_json_file(p))
                dataset, excluded = _collect_file_info(json_data, p.name)

                # ensure directory exists
                os.makedirs("processed_datasets", exist_ok=True)

                # write dataset to a new file
                with open(f"processed_datasets/{p.name}", "w", encoding="utf-8") as file:
                    json.dump(dataset, file, indent=4, ensure_ascii=False)
                    print(f"Saved {file.name}")

                # write excluded files to a file if any
                if excluded:
                    os.makedirs("processed_datasets/excluded", exist_ok=True)

                    with open(f"processed_datasets/excluded/{p.name}", "w", encoding="utf-8") as file:
                        json.dump(excluded, file, indent=4, ensure_ascii=False)
                        print(f"Saved exclusions for {file.name}")

                print(f"Total saved: {len(dataset)}")
                print(f"Excluded: {len(excluded)}")
if __name__ == "__main__":
    process_datasets()
