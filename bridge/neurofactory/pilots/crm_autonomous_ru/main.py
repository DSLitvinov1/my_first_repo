# crm.py
import json
import pathlib
import argparse
import sys

class CRM:
    def __init__(self, path):
        self.path = pathlib.Path(path)
        self.data = self.load_data()

    def load_data(self):
        if self.path.exists():
            with self.path.open('r') as file:
                return json.load(file)
        return []

    def save_data(self):
        with self.path.open('w') as file:
            json.dump(self.data, file, indent=4)

    def add(self, name, phone, note=''):
        new_id = len(self.data) + 1
        new_entry = {
            'id': new_id,
            'name': name,
            'phone': phone,
            'note': note,
            'status': 'new'
        }
        self.data.append(new_entry)
        self.save_data()
        return new_entry

    def all(self):
        return self.data

    def search(self, query):
        return [entry for entry in self.data if query.lower() in entry['name'].lower() or query.lower() in entry['phone'].lower() or query.lower() in entry['note'].lower()]

    def edit(self, id, name=None, phone=None, note=None):
        for entry in self.data:
            if entry['id'] == id:
                if name is not None:
                    entry['name'] = name
                if phone is not None:
                    entry['phone'] = phone
                if note is not None:
                    entry['note'] = note
                self.save_data()
                return entry
        return None

    def set_status(self, id, status):
        for entry in self.data:
            if entry['id'] == id:
                if status in ['new', 'in_progress', 'done']:
                    entry['status'] = status
                    self.save_data()
                    return entry
        return None

# main.py
import json
import pathlib
import argparse
import sys

def main():
    parser = argparse.ArgumentParser(description='CRM for fictional requests')
    parser.add_argument('--db', default='crm.json', help='Path to the JSON file')
    subparsers = parser.add_subparsers(dest='command')

    add_parser = subparsers.add_parser('add', help='Add a new request')
    add_parser.add_argument('name', help='Name of the request')
    add_parser.add_argument('phone', help='Phone number')
    add_parser.add_argument('note', nargs='?', help='Note')

    list_parser = subparsers.add_parser('list', help='List all requests')

    search_parser = subparsers.add_parser('search', help='Search for a request')
    search_parser.add_argument('query', help='Search query')

    edit_parser = subparsers.add_parser('edit', help='Edit a request')
    edit_parser.add_argument('id', type=int, help='ID of the request')
    edit_parser.add_argument('name', nargs='?', help='New name')
    edit_parser.add_argument('phone', nargs='?', help='New phone number')
    edit_parser.add_argument('note', nargs='?', help='New note')

    status_parser = subparsers.add_parser('status', help='Set the status of a request')
    status_parser.add_argument('id', type=int, help='ID of the request')
    status_parser.add_argument('status', help='New status (new, in_progress, done)')

    args = parser.parse_args()

    crm = CRM(args.db)

    if args.command == 'add':
        result = crm.add(args.name, args.phone, args.note)
        print(f"Added request: {result}")
    elif args.command == 'list':
        print(json.dumps(crm.all(), indent=4))
    elif args.command == 'search':
        results = crm.search(args.query)
        print(json.dumps(results, indent=4))
    elif args.command == 'edit':
        result = crm.edit(args.id, args.name, args.phone, args.note)
        if result:
            print(f"Edited request: {result}")
        else:
            print("Request not found")
    elif args.command == 'status':
        result = crm.set_status(args.id, args.status)
        if result:
            print(f"Updated status of request {args.id}: {result}")
        else:
            print("Request not found")

if __name__ == '__main__':
    main()
