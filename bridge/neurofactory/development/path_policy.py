def approved_change_path(path):
    if not isinstance(path, str) or len(path) < 5 or len(path) > 240 or not path.isascii():
        return False
    if '\\\\' in path:
        return False
    parts = path.split('/')
    if not all(part != '' and part != '.' and part != '..' and all(c.isalnum() or c in '._-' for c in part) for part in parts):
        return False
    if path.startswith('bridge/neurofactory/'):
        return True
    if path.startswith('.github/workflows/neurofactory-') and path.endswith('.yml'):
        return True
    return False
