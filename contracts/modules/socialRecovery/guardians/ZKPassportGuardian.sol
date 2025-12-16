// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/interfaces/IERC1271.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "../../../interfaces/zkpassport/IZKPassportVerifier.sol";

error ZKGuardianAlreadyInitialized();
error ZKGuardianInvalidVerifier();
error ZKGuardianInvalidWallet();
error ZKGuardianProofVerificationFailed();
error ZKGuardianScopeMismatch();
error ZKGuardianBoundSenderMismatch();
error ZKGuardianChainIdMismatch();
error ZKGuardianDigestMismatch();
error ZKGuardianIdentifierMismatch();
error ZKGuardianDevModeNotAllowed();
error ZKGuardianNotInitialized();
error ZKGuardianVerifierCallFailed();
error ZKGuardianDigestAlreadyApproved();
error ZKGuardianInvalidDigestFormat();

struct ZKPassportGuardianInit {
    address wallet;
    bytes32 uniqueIdentifier;
    string domain;
    string scope;
    bool allowDevMode;
    IZKPassportVerifier verifier;
}

struct ZKPassportGuardianSignature {
    ProofVerificationParams params;
    bool isIDCard;
}

/**
 * @title ZKPassportGuardian
 * @notice ERC-1271 guardian proxy that validates ZKPassport proofs for Elytro social recovery approvals.
 * @dev Designed to be deployed through a minimal proxy factory so each wallet/identity pair has its own guardian.
 */
contract ZKPassportGuardian is IERC1271 {

    IZKPassportVerifier public verifier;
    address public wallet;
    bytes32 public uniqueIdentifier;
    bool public allowDevMode;
    bool public initialized;
    address public factory;

    mapping(bytes32 => bool) public approved;

    string private _domain;
    string private _scope;

    event GuardianInitialized(address indexed wallet, bytes32 indexed uniqueIdentifier, string domain, string scope);
    event DigestApproved(bytes32 indexed digest);

    /**
     * @notice Initializes a freshly deployed clone.
     * @param init Initialization config containing wallet binding and verifier metadata.
     */
    function initialize(ZKPassportGuardianInit calldata init) external {
        if (initialized) revert ZKGuardianAlreadyInitialized();
        if (address(init.verifier) == address(0)) revert ZKGuardianInvalidVerifier();
        if (init.wallet == address(0)) revert ZKGuardianInvalidWallet();

        verifier = init.verifier;
        wallet = init.wallet;
        uniqueIdentifier = init.uniqueIdentifier;
        _domain = init.domain;
        _scope = init.scope;
        allowDevMode = init.allowDevMode;
        factory = msg.sender;
        initialized = true;

        emit GuardianInitialized(init.wallet, init.uniqueIdentifier, init.domain, init.scope);
    }

    function domain() external view returns (string memory) {
        return _domain;
    }

    function scope() external view returns (string memory) {
        return _scope;
    }

    /**
     * @notice Verifies a ZKPassport proof and marks the embedded digest as approved.
     * @param signature ABI-encoded ZKPassportGuardianSignature payload.
     * @return digest Recovery digest extracted from the proof.
     */
    function approve(bytes calldata signature) external returns (bytes32 digest) {
        if (!initialized) revert ZKGuardianNotInitialized();

        ZKPassportGuardianSignature memory payload = abi.decode(signature, (ZKPassportGuardianSignature));
        BoundData memory bound = _verifyProofAndGetBoundData(payload.params);
        digest = _parseDigest(bound.customData);
        if (approved[digest]) revert ZKGuardianDigestAlreadyApproved();
        approved[digest] = true;
        emit DigestApproved(digest);
    }

    /**
     * @inheritdoc IERC1271
     */
    function isValidSignature(bytes32 digest, bytes calldata signature) external view override returns (bytes4) {
        if (!initialized) revert ZKGuardianNotInitialized();

        ZKPassportGuardianSignature memory payload = abi.decode(signature, (ZKPassportGuardianSignature));
        _validateProof(digest, payload.params);
        return IERC1271.isValidSignature.selector;
    }

    function _validateProof(bytes32 digest, ProofVerificationParams memory params) internal view {
        BoundData memory bound = _verifyProofAndGetBoundData(params);

        string memory expectedDigest = _digestString(digest);
        if (keccak256(bytes(bound.customData)) != keccak256(bytes(expectedDigest))) {
            revert ZKGuardianDigestMismatch();
        }
    }

    function _verifyProofAndGetBoundData(ProofVerificationParams memory params) internal view returns (BoundData memory bound) {
        if (!allowDevMode && params.serviceConfig.devMode) {
            revert ZKGuardianDevModeNotAllowed();
        }

        (bool verified, bytes32 proofIdentifier, IZKPassportHelper helper) = _callVerifier(params);
        if (!verified) revert ZKGuardianProofVerificationFailed();

        if (
            keccak256(bytes(params.serviceConfig.domain)) != keccak256(bytes(_domain))
                || keccak256(bytes(params.serviceConfig.scope)) != keccak256(bytes(_scope))
        ) {
            revert ZKGuardianScopeMismatch();
        }

        if (!helper.verifyScopes(params.proofVerificationData.publicInputs, _domain, _scope)) {
            revert ZKGuardianScopeMismatch();
        }

        bound = helper.getBoundData(params.committedInputs);
        if (bound.senderAddress != wallet) revert ZKGuardianBoundSenderMismatch();
        if (bound.chainId != block.chainid) revert ZKGuardianChainIdMismatch();

        if (uniqueIdentifier != bytes32(0) && proofIdentifier != uniqueIdentifier) {
            revert ZKGuardianIdentifierMismatch();
        }
    }

    function _digestString(bytes32 digest) internal pure returns (string memory) {
        return Strings.toHexString(uint256(digest), 32);
    }

    function _parseDigest(string memory customData) internal pure returns (bytes32 digest) {
        bytes memory data = bytes(customData);
        if (data.length != 66 || data[0] != "0" || (data[1] != "x" && data[1] != "X")) {
            revert ZKGuardianInvalidDigestFormat();
        }

        for (uint256 i = 2; i < 66; i += 2) {
            uint8 high = _fromHexChar(data[i]);
            uint8 low = _fromHexChar(data[i + 1]);
            digest = (digest << 8) | bytes32(uint256((high << 4) | low));
        }
    }

    function _fromHexChar(bytes1 c) private pure returns (uint8) {
        uint8 char = uint8(c);
        if (char >= 48 && char <= 57) return char - 48;
        if (char >= 65 && char <= 70) return char - 55;
        if (char >= 97 && char <= 102) return char - 87;
        revert ZKGuardianInvalidDigestFormat();
    }

    function _callVerifier(ProofVerificationParams memory params)
        internal
        view
        returns (bool verified, bytes32 proofIdentifier, IZKPassportHelper helper)
    {
        (bool success, bytes memory data) =
            address(verifier).staticcall(abi.encodeWithSelector(IZKPassportVerifier.verify.selector, params));
        if (!success) revert ZKGuardianVerifierCallFailed();
        return abi.decode(data, (bool, bytes32, IZKPassportHelper));
    }
}
