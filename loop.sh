#/bin/bash
for f in ./input/out_10_exe/*; do
    python3 obfustat.py $f
done