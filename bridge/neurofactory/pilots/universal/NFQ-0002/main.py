from fuel_liters import fuel_liters
from fuel_cost import fuel_cost
import argparse

def main():
    parser = argparse.ArgumentParser(description='Synthetic offline training app')
    parser.add_argument('operation', choices=['fuel_liters', 'fuel_cost'])
    parser.add_argument('values', nargs='+', type=float)
    args = parser.parse_args()
    mapping = {'fuel_liters': (fuel_liters, 2), 'fuel_cost': (fuel_cost, 2)}
    fn, arity = mapping[args.operation]
    if len(args.values) != arity:
        parser.error('Incorrect argument count')
    print(format(fn(*args.values), '.12g'))

if __name__ == '__main__':
    main()
