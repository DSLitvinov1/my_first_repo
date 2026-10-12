from celsius_to_fahrenheit import celsius_to_fahrenheit
from fahrenheit_to_celsius import fahrenheit_to_celsius
import argparse

def main():
    parser = argparse.ArgumentParser(description='Synthetic offline training app')
    parser.add_argument('operation', choices=['celsius_to_fahrenheit', 'fahrenheit_to_celsius'])
    parser.add_argument('values', nargs='+', type=float)
    args = parser.parse_args()
    mapping = {'celsius_to_fahrenheit': (celsius_to_fahrenheit, 1), 'fahrenheit_to_celsius': (fahrenheit_to_celsius, 1)}
    fn, arity = mapping[args.operation]
    if len(args.values) != arity:
        parser.error('Incorrect argument count')
    print(format(fn(*args.values), '.12g'))

if __name__ == '__main__':
    main()
