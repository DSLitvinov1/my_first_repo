import storage

class CRM:
    def __init__(self, path):
        self.path = path
        self.records = storage.load_records(path)

    def add(self, name, phone, note=''):
        new_id = len(self.records) + 1
        new_record = {
            'id': new_id,
            'name': name,
            'phone': phone,
            'note': note,
            'status': 'new'
        }
        self.records.append(new_record)
        storage.save_records(self.path, self.records)
        return new_record

    def all(self):
        return self.records

    def search(self, query):
        query = query.lower()
        return [
            record for record in self.records
            if query in record['name'].lower() or
            query in record['phone'].lower() or
            query in record['note'].lower()
        ]

    def edit(self, id, name=None, phone=None, note=None):
        for record in self.records:
            if record['id'] == id:
                if name is not None:
                    record['name'] = name
                if phone is not None:
                    record['phone'] = phone
                if note is not None:
                    record['note'] = note
                storage.save_records(self.path, self.records)
                return record
        return None

    def set_status(self, id, status):
        for record in self.records:
            if record['id'] == id:
                record['status'] = status
                storage.save_records(self.path, self.records)
                return record
        return None
