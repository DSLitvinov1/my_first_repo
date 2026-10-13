def receipt_matches(record, repo, path, sha):
    if not isinstance(record, dict) or not isinstance(repo, str) or not isinstance(path, str) or not isinstance(sha, str):
        return False
    if repo != 'DSLitvinov1/my_first_repo' or path != 'bridge/neurofactory/development/stage4_receipt_rules.py':
        return False
    if len(record) != 3 or len(sha) != 40:
        return False
    if not all(c in '0123456789abcdef' for c in sha):
        return False
    return record.get('repo') == repo and record.get('path') == path and record.get('sha') == sha
