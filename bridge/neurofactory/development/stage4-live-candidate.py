def receipt_matches(record, repo, path, sha):
    if not isinstance(record, dict):
        return False
    if len(record) != 3:
        return False
    if record.get('repo') != repo:
        return False
    if record.get('path') != path:
        return False
    if record.get('sha') != sha:
        return False
    if not isinstance(sha, str) or len(sha) != 40 or not all(c in 'abcdef0123456789' for c in sha):
        return False
    return True
