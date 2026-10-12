"""Synthetic offline packaging estimator; never accesses external services."""
import argparse
from volume import parcel_volume
from boxes import boxes_needed

def estimate(length, width, height, items, per_box):
    values=(length,width,height,items,per_box)
    if any(type(x) is not int for x in values):
        raise TypeError("Whole numbers only")
    if min(length,width,height)<=0 or items<0 or per_box<=0:
        raise ValueError("Invalid parcel dimensions or box capacity")
    return parcel_volume(length,width,height),boxes_needed(items,per_box)

def main():
    p=argparse.ArgumentParser(description="Synthetic packaging estimate")
    for item in ("length","width","height","items","per_box"):
        p.add_argument(item,type=int)
    args=p.parse_args()
    volume,boxes=estimate(args.length,args.width,args.height,args.items,args.per_box)
    print(str(volume)+" "+str(boxes))

if __name__=="__main__":
    main()
