# Formal Analysis of the iMessage PQ3 Protocol

This repository contains the formal models for the Tamarin prover, associated proofs, and a pseudocode specification of iMessage PQ3, a state-of-the-art messaging protocol providing strong security guarantees even against adversaries with quantum-computing capabilities.

This work is part of a scientific paper available as a pre-print here: https://eprint.iacr.org/2024/1395

The paper has been accepted for publication at USENIX Security 2025.

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
| `/prove-expensive.sh` | A script that constructs the proof for an automatically provable but computationally expensive lemma. |
| `/time.sh` | A script used for timing proof construction/verification. |
| `/wellformedness.sh` | A script that checks that our model is well-formed. To keep things separate, all other proof checking/constructing scripts skip some well-formedness checks. |

## Constructing & Checking Proofs

To verify our proofs of iMessage PQ3's security (as described in Section 5 of our paper), follow the four steps below.

First, verify that our model has no well-formedness issues by running:

```sh
./wellformedness.sh
```

Second, construct most automatically provable lemmas by running:
```sh
./prove-auto.sh
```

There is one automatically provable lemma for which proof search is computationally expensive.
Proving this lemma took around 1-2 days using our setup.
As a third step, prove this lemma by running:
```sh
./prove-expensive.sh
```

Some lemmas are not automatically provable (those not prefixed by `Auto_` or `Expensive_Auto_`).
We provide already constructed proofs for these lemmas in `/proofs`.
As a final step, verify all these proofs.
See the README in that folder for more information on how to verify these proofs.

## Computational Resources Required

Proofs were constructed on a server with 252 GB of memory and two Intel Xeon E5-2650 v4 CPUs, i.e., a 48-thread server.
We note approximate time and memory requirements for each script below, which were collected using the `time` utility.
We note similar requirements for stored proofs in `proofs/`.
Memory consumption is estimated from the process's maximum resident set size.

Note that Tamarin can use RAM inefficiently.
Tamarin stores the entire proof tree, but a proof only needs to access a path in the proof tree.
Therefore, memory compression can help you check proofs on machines with much less physical memory than indicated.
For example, some proofs were constructed on a Macbook with 32 GB of RAM, where we observed 100 GB of virtual memory usage but only 5-10 GB of physical memory usage.

| Script | Time | Memory |
| ------ | ---- | ------ |
| `prove-auto.sh` | 8h | 10 GB |
| `prove-expensive.sh` | 8h | 100 GB |
