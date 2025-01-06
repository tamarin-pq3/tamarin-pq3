# Formal Analysis of the iMessage PQ3 Protocol

This repository contains the formal models, proofs, and a pseudocode specification of iMessage PQ3, a state-of-the-art messaging protocol providing strong security guarantees even against adversaries with quantum-computing capabilities.
This work is currently under submission for scientific publication.

## Prerequisites

To construct or check proofs, you need to have `python3` installed and on the path, as well as [Tamarin](https://tamarin-prover.com/manual/master/book/002_installation.html).
We used Tamarin version 1.8.0 and Maude versions 3.1 and 3.2.1.

## Contents of this Repository

| Path | Description |
|---|---|
| `/case-study`| Contains the example theories used to illustrate our proof methodology. |
| `/dev` | Contains scripts used by the modelers to construct proofs. Please ignore. |
| `/proofs` | Contains proofs for lemmas that cannot be proven automatically. The folder contains more documentation. |
| `/spec` | Contains a pseudocode specification of iMessage PQ3. |
| `/model.spthy` | Our formal model of iMessage PQ3. |
| `/oracle.py` | A custom proof heuristic aiding proof construction. |
| `/prove-auto.sh` | A script that constructs proves for all automatically provable lemmas. |
| `/time.sh` | A script used for timing proof construction/verification. |
| `/wellformedness.sh` | A that checks that our model is well-formed. To keep things separate, all other proof checking/constructing scripts skip some well-formedness checks. |

## Constructing & Checking Proofs

You can verify that our model has no well-formedness issues by running:

```sh
./wellformedness.sh
```

You can construct all automatically provable lemmas by running:
```sh
./prove-auto.sh
```

Some lemmas are not automatically provable (those not prefixed by `Auto_`).
We provide already constructed proofs for these lemmas in `/proofs`.
See the README in that folder for more information on how to verify these proofs.
