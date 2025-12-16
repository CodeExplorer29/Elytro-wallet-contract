// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Data bound to a ZKPassport proof.
struct BoundData {
    address senderAddress;
    uint256 chainId;
    string customData;
}

/// @notice Metadata describing the verifier service configuration.
struct ServiceConfig {
    uint256 validityPeriodInSeconds;
    string domain;
    string scope;
    bool devMode;
}

/// @notice Internal data required to verify a proof.
struct ProofVerificationData {
    bytes32 vkeyHash;
    bytes proof;
    bytes32[] publicInputs;
}

/// @notice Complete parameters forwarded to the on-chain verifier.
struct ProofVerificationParams {
    bytes32 version;
    ProofVerificationData proofVerificationData;
    bytes committedInputs;
    ServiceConfig serviceConfig;
}

interface IZKPassportHelper {
    function verifyScopes(bytes32[] calldata publicInputs, string calldata domain, string calldata scope)
        external
        view
        returns (bool);

    function getBoundData(bytes calldata committedInputs) external view returns (BoundData memory);
}

interface IZKPassportVerifier {
    function verify(ProofVerificationParams calldata params)
        external
        returns (bool verified, bytes32 uniqueIdentifier, IZKPassportHelper helper);
}
