"""Small offline, noncommercial, multi-file application."""
import argparse
from pricing import line_total
from discount import discounted_total

def quote(quantity, unit_price, discount_percent):
    if any(type(value) is not int for value in (quantity, unit_price, discount_percent)):
        raise TypeError("Only integer amounts are allowed")
    if quantity < 0 or unit_price < 0 or not 0 <= discount_percent <= 100:
        raise ValueError("Inputs out of the accepted range")
    return discounted_total(line_total(quantity, unit_price), discount_percent)

def main():
    parser = argparse.ArgumentParser(description="Offline order quote")
    parser.add_argument("quantity", type=int)
    parser.add_argument("unit_price", type=int)
    parser.add_argument("discount_percent", type=int)
    args = parser.parse_args()
    print(quote(args.quantity,args.unit_price,args.discount_percent))

if __name__=="__main__":
    main()
