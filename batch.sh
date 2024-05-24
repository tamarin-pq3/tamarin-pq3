tamarin-prover +RTS -N24 -RTS --derivcheck-timeout=0 --output=$1.spthy "${@:2}" model.spthy > $1.log 2>&1
