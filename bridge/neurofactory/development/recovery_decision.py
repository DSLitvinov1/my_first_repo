def resume_unfinished(task, now, max_attempts):
    task = task.copy()
    state = task.get('state')
    attempts = task.get('attempts')
    lease_until = task.get('lease_until')

    if state in ('verified_done', 'failed', 'queued', 'retry_exhausted', 'needs_receipt_check'):
        return task

    if state == 'publishing':
        task['state'] = 'needs_receipt_check'
        return task

    if state == 'running':
        if isinstance(lease_until, int) and lease_until > now:
            return task
        if lease_until is None or not isinstance(lease_until, int):
            task['state'] = 'needs_manual_review'
            return task
        if attempts is None or not isinstance(attempts, int):
            task['state'] = 'needs_manual_review'
            return task
        if attempts < 0:
            task['state'] = 'needs_manual_review'
            return task
        if attempts >= max_attempts:
            task['state'] = 'retry_exhausted'
            task['lease_until'] = None
            return task
        if attempts < max_attempts:
            task['state'] = 'queued'
            task['lease_until'] = None
            return task

    return task
