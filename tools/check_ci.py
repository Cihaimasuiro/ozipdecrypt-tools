import urllib.request
import json
import sys

def check_ci():
    url = 'https://api.github.com/repos/Cihaimasuiro/ozipdecrypt-tools/actions/runs?per_page=6'
    req = urllib.request.Request(url, headers={'User-Agent': 'Python-CI-Checker'})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            print(f"Total runs: {data.get('total_count', 0)}")
            for run in data.get('workflow_runs', []):
                sha = run['head_sha'][:7]
                status = run['status']
                conclusion = run.get('conclusion')
                name = run.get('display_title', '')[:40]
                print(f"Commit: {sha} | Status: {status:<10} | Conclusion: {str(conclusion):<10} | Title: {name}")
    except Exception as e:
        print(f"Error querying GitHub API: {e}")

if __name__ == '__main__':
    check_ci()
