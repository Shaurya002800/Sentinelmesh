import { expect } from "chai";
import { network } from "hardhat";

const { ethers } = await network.connect();

describe("SentinelLog", function () {
  it("stores a new incident and exposes it through getters", async function () {
    const [reporter] = await ethers.getSigners();
    const sentinelLog = await ethers.deployContract("SentinelLog");
    await sentinelLog.waitForDeployment();

    const incidentHash = ethers.keccak256(ethers.toUtf8Bytes("tamper-event-1"));
    const tx = await sentinelLog.storeIncident(incidentHash);
    await expect(tx).to.emit(sentinelLog, "IncidentStored");

    const stored = await sentinelLog.getIncident(incidentHash);
    expect(stored.incidentHash).to.equal(incidentHash);
    expect(stored.reporter).to.equal(reporter.address);
    expect(await sentinelLog.incidentExists(incidentHash)).to.equal(true);
    expect(await sentinelLog.getIncidentCount()).to.equal(1n);
    expect(await sentinelLog.getIncidentHashAt(0)).to.equal(incidentHash);
  });

  it("rejects duplicate incident hashes", async function () {
    const sentinelLog = await ethers.deployContract("SentinelLog");
    await sentinelLog.waitForDeployment();

    const incidentHash = ethers.keccak256(ethers.toUtf8Bytes("duplicate-event"));
    await sentinelLog.storeIncident(incidentHash);

    await expect(sentinelLog.storeIncident(incidentHash)).to.be.revertedWithCustomError(
      sentinelLog,
      "IncidentAlreadyStored"
    );
  });
});
