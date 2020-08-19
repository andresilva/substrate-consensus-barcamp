# Substrate Consensus Barcamp

A very dumb/simple consensus engine for block production and finality written as
an exercise to showcase Substrate's consensus framework abstractions.

Relevant code exists in the `consensus` crate.

## Build

``` bash
cargo build --release
```

## Start block authoring validator

This node should only bake new blocks but not finalize them. Although it is
listening for gossip finality notifications (`--finality-gadget`).

```bash
./node-template -d val1 --validator --port 12345 --node-key 0000000000000000000000000000000000000000000000000000000000000001 --finality-gadget
```

## Start finality validator

This node is not a regular validator and therefore won't be baking any new
blocks. But it is a finality gadget validator and it should finalize new blocks
it imports and gossip those notifications on the network
(`--finality-gadget-validator`).

```bash
./node-template -d val2 --bootnodes "/ip4/127.0.0.1/tcp/12345/p2p/QmRpheLN4JWdAnY7HGJfWFNbfkQCb6tFf4vvA6hgjMZKrR" --finality-gadget-validator
```
