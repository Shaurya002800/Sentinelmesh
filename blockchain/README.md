# SentinelMesh Blockchain

This package deploys the on-chain evidence ledger used by SentinelMesh.

## Contract

`SentinelLog.sol` stores a unique `bytes32` incident hash, the reporter address, and the block timestamp.

## Setup

1. Install packages:
   `npm install`
2. Compile the contract:
   `npm run compile`
3. Run tests:
   `npm test`
4. Deploy to Polygon Amoy:
   `npm run deploy:amoy`

## Environment variables

Put these in `blockchain/.env`:

`RPC_URL=...`
`PRIVATE_KEY=...`

## After deploy

Copy the deployed contract address into `backend/.env` as `CONTRACT_ADDRESS`.
Also copy the same `RPC_URL` and `PRIVATE_KEY` into `backend/.env` so the Flask backend can anchor incident hashes on-chain.
