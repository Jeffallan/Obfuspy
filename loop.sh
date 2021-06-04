#/bin/bash
#pass me a dir of files to process and I will do that for you :)

for f in $1/*; do
    #echo $1
    RES=$(echo $1 | cut -c 3-)
    mkdir -p `pwd`/results/$RES
    python3 obfustat.py $f --out `pwd`/results/$RES
done