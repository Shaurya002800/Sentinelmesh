import { network } from "hardhat";

const { ethers } = await network.connect();

const [signer] = await ethers.getSigners();
console.log("Deploying with:", signer.address);
console.log("Balance:", (await ethers.provider.getBalance(signer.address)).toString());

const sentinelLog = await ethers.deployContract("SentinelLog");
await sentinelLog.waitForDeployment();

const contractAddress = await sentinelLog.getAddress();
console.log(`SentinelLog deployed to ${contractAddress}`);
console.log("Copy this into backend/.env as CONTRACT_ADDRESS");
