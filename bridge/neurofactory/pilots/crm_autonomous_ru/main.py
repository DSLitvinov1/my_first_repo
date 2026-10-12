import argparse
from crm import CRM

def main():
    parser = argparse.ArgumentParser(description='Console mini-CRM for fictional requests.')
    parser.add_argument('--db', default='crm.json', help='Path to the JSON file for storing records.')
    subparsers = parser.add_subparsers(dest='command')

    # add command
    add_parser = subparsers.add_parser('add', help='Add a new request.')
    add_parser.add_argument('name', help='Name of the request.')
    add_parser.add_argument('phone', help='Phone number of the request.')
    add_parser.add_argument('--note', help='Note for the request.', default='')

    # list command
    list_parser = subparsers.add_parser('list', help='List all requests.')

    # search command
    search_parser = subparsers.add_parser('search', help='Search for requests.')
    search_parser.add_argument('query', help='Query to search for.')

    # edit command
    edit_parser = subparsers.add_parser('edit', help='Edit a request.')
    edit_parser.add_argument('id', type=int, help='ID of the request to edit.')
    edit_parser.add_argument('--name', help='New name for the request.')
    edit_parser.add_argument('--phone', help='New phone number for the request.')
    edit_parser.add_argument('--note', help='New note for the request.')

    # status command
    status_parser = subparsers.add_parser('status', help='Set the status of a request.')
    status_parser.add_argument('id', type=int, help='ID of the request to set status.')
    status_parser.add_argument('status', help='New status of the request.')

    args = parser.parse_args()

    if args.command == 'add':
        crm = CRM(args.db)
        new_record = crm.add(args.name, args.phone, args.note)
        print(f'New request added: {new_record}')
    elif args.command == 'list':
        crm = CRM(args.db)
        records = crm.all()
        for record in records:
            print(record)
    elif args.command == 'search':
        crm = CRM(args.db)
        results = crm.search(args.query)
        for result in results:
            print(result)
    elif args.command == 'edit':
        crm = CRM(args.db)
        edited_record = crm.edit(args.id, args.name, args.phone, args.note)
        if edited_record:
            print(f'Request edited: {edited_record}')
        else:
            print('Request not found.')
    elif args.command == 'status':
        crm = CRM(args.db)
        updated_record = crm.set_status(args.id, args.status)
        if updated_record:
            print(f'Request status updated: {updated_record}')
        else:
            print('Request not found.')

if __name__ == '__main__':
    main()
