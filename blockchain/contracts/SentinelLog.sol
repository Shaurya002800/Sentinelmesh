// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract SentinelLog {
    struct IncidentRecord {
        bytes32 incidentHash;
        uint256 timestamp;
        address reporter;
    }

    mapping(bytes32 => IncidentRecord) private incidents;
    bytes32[] private incidentHashes;

    event IncidentStored(bytes32 indexed incidentHash, address indexed reporter, uint256 timestamp);

    error IncidentAlreadyStored(bytes32 incidentHash);
    error IncidentNotFound(bytes32 incidentHash);

    function storeIncident(bytes32 incidentHash) external {
        if (incidents[incidentHash].timestamp != 0) {
            revert IncidentAlreadyStored(incidentHash);
        }

        IncidentRecord memory record = IncidentRecord({
            incidentHash: incidentHash,
            timestamp: block.timestamp,
            reporter: msg.sender
        });

        incidents[incidentHash] = record;
        incidentHashes.push(incidentHash);

        emit IncidentStored(incidentHash, msg.sender, block.timestamp);
    }

    function getIncident(bytes32 incidentHash) external view returns (IncidentRecord memory) {
        IncidentRecord memory record = incidents[incidentHash];
        if (record.timestamp == 0) {
            revert IncidentNotFound(incidentHash);
        }
        return record;
    }

    function incidentExists(bytes32 incidentHash) external view returns (bool) {
        return incidents[incidentHash].timestamp != 0;
    }

    function getIncidentCount() external view returns (uint256) {
        return incidentHashes.length;
    }

    function getIncidentHashAt(uint256 index) external view returns (bytes32) {
        return incidentHashes[index];
    }
}
