tamarin-prover +RTS -N24 -RTS --derivcheck-timeout=0 --output=$1.spthy --prove=$1 $1-partial.spthy > $1.log 2>&1
