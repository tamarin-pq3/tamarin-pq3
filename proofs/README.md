# Proofs

This folder contains proofs for the lemmas that cannot be proven automatically.
You can check a proof by running (`<PROOF-FILE>` to be replaced with the respective proof you want to check):

```sh
./check.sh <PROOF-FILE>
```

Every file contains proofs for lemmas similarly named.

## Computational Resources Required

Below statistics were collected using the `time` utility.
Memory consumption is estimated from the process's maximum resident set size.

| Lemma | Time | Memory |
| ----- | ---- | ------ |
| `CkCompromise` | 3h | 140 GB |
| `ECDHSSCompromise` | 16h | 140 GB |
| `Executability*` | 10min | 3.5 GB |
| `KemSSCompromise` | 17.5h | 124 GB |
| `RkFixesKEMSS` | 45min | 32 GB |
