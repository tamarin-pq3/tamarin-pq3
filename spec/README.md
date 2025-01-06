# iMessage PQ3 Pseudocode

This folder provides a specification of PQ3 using pseudocode.
The description is based upon technical material received from Apple researchers.

The formal model only abstracts from the pseudocode as presented here in that it operates in the symbolic model.
For example, the root key derivation is actually done using two extract and one expand calls (see `rootAndChainKey` in `code.txt`).
In the symbolic model, however, it only matters which entropy sources and domain separators are used to derive a value.
Additionally, as the extract and expand operations are done by each party locally and without any interleaving, we faithfully model root-key derivation using one application of the `hkdf` function (see the paper's Appendix B).

The pseudocode provides no specification of the session handling layer.
Thus, the two functions `lookupSession` and `storeSession` will be left undefined.
The effect of these functions should be clear from context, though.
The pseudocode follows Python syntax, and the type-definitions follow TypeScript conventions.
Variables that are followed by a `?` are optional and might have the value `None`.
