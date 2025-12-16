pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@source/modules/socialRecovery/guardians/ZKPassportGuardian.sol";
import "@source/modules/socialRecovery/guardians/ZKPassportGuardianFactory.sol";

contract ZKPassportGuardianTest is Test {

    MockZKPassportVerifier verifier;
    MockZKPassportHelper helper;
    ZKPassportGuardian implementation;
    ZKPassportGuardianFactory factory;

    address wallet;
    bytes32 identifier;
    string constant DOMAIN = "elytro.id";
    string constant SCOPE = "social-recovery";

    function setUp() public {
        helper = new MockZKPassportHelper();
        verifier = new MockZKPassportVerifier();
        implementation = new ZKPassportGuardian();
        factory = new ZKPassportGuardianFactory(address(implementation));

        wallet = makeAddr("wallet");
        identifier = keccak256("identifier");

        verifier.setResult(true, identifier, helper);
        helper.setScopeResult(true);
    }

    function testPredictAddressMatchesDeployment() public {
        ZKPassportGuardianInit memory init =
            ZKPassportGuardianInit(wallet, identifier, DOMAIN, SCOPE, false, verifier);
        bytes32 salt = bytes32(uint256(1));
        address predicted = factory.predictGuardianAddress(wallet, identifier, salt);
        address deployed = factory.deployGuardian(init, salt);
        assertEq(predicted, deployed);
    }

    function testValidSignatureFlow() public {
        ZKPassportGuardianInit memory init =
            ZKPassportGuardianInit(wallet, identifier, DOMAIN, SCOPE, false, verifier);
        address guardian = factory.deployGuardian(init, bytes32(0));
        bytes32 digest = keccak256("recovery");
        ProofVerificationParams memory params = _defaultParams();
        bytes memory signature =
            _encodeSignature(digest, params, BoundData(wallet, block.chainid, Strings.toHexString(uint256(digest), 32)));
        bytes4 res = IERC1271(guardian).isValidSignature(digest, signature);
        assertEq(res, IERC1271.isValidSignature.selector);
    }

    function testRevertsWhenVerifierReturnsFalse() public {
        verifier.setResult(false, identifier, helper);
        ZKPassportGuardianInit memory init =
            ZKPassportGuardianInit(wallet, identifier, DOMAIN, SCOPE, false, verifier);
        address guardian = factory.deployGuardian(init, bytes32(0));
        bytes32 digest = keccak256("recovery");
        ProofVerificationParams memory params = _defaultParams();
        bytes memory signature =
            _encodeSignature(digest, params, BoundData(wallet, block.chainid, Strings.toHexString(uint256(digest), 32)));
        vm.expectRevert(ZKGuardianProofVerificationFailed.selector);
        IERC1271(guardian).isValidSignature(digest, signature);
    }

    function testRevertsOnIdentifierMismatch() public {
        ZKPassportGuardianInit memory init =
            ZKPassportGuardianInit(wallet, identifier, DOMAIN, SCOPE, false, verifier);
        address guardian = factory.deployGuardian(init, bytes32(0));
        verifier.setResult(true, keccak256("another"), helper);
        bytes32 digest = keccak256("recovery");
        ProofVerificationParams memory params = _defaultParams();
        bytes memory signature =
            _encodeSignature(digest, params, BoundData(wallet, block.chainid, Strings.toHexString(uint256(digest), 32)));
        vm.expectRevert(ZKGuardianIdentifierMismatch.selector);
        IERC1271(guardian).isValidSignature(digest, signature);
    }

    function testRevertsOnDevModeWhenDisallowed() public {
        ZKPassportGuardianInit memory init =
            ZKPassportGuardianInit(wallet, identifier, DOMAIN, SCOPE, false, verifier);
        address guardian = factory.deployGuardian(init, bytes32(0));
        bytes32 digest = keccak256("recovery");
        ProofVerificationParams memory params = _defaultParams();
        params.serviceConfig.devMode = true;
        bytes memory signature =
            _encodeSignature(digest, params, BoundData(wallet, block.chainid, Strings.toHexString(uint256(digest), 32)));
        vm.expectRevert(ZKGuardianDevModeNotAllowed.selector);
        IERC1271(guardian).isValidSignature(digest, signature);
    }

    function testAllowsDevModeWhenConfigured() public {
        ZKPassportGuardianInit memory init =
            ZKPassportGuardianInit(wallet, identifier, DOMAIN, SCOPE, true, verifier);
        address guardian = factory.deployGuardian(init, bytes32(0));
        bytes32 digest = keccak256("recovery");
        ProofVerificationParams memory params = _defaultParams();
        params.serviceConfig.devMode = true;
        bytes memory signature =
            _encodeSignature(digest, params, BoundData(wallet, block.chainid, Strings.toHexString(uint256(digest), 32)));
        bytes4 res = IERC1271(guardian).isValidSignature(digest, signature);
        assertEq(res, IERC1271.isValidSignature.selector);
    }

    function testRevertsOnScopeMismatch() public {
        ZKPassportGuardianInit memory init =
            ZKPassportGuardianInit(wallet, identifier, DOMAIN, SCOPE, false, verifier);
        address guardian = factory.deployGuardian(init, bytes32(0));
        bytes32 digest = keccak256("recovery");
        ProofVerificationParams memory params = _defaultParams();
        params.serviceConfig.domain = "invalid";
        bytes memory signature =
            _encodeSignature(digest, params, BoundData(wallet, block.chainid, Strings.toHexString(uint256(digest), 32)));
        vm.expectRevert(ZKGuardianScopeMismatch.selector);
        IERC1271(guardian).isValidSignature(digest, signature);
    }

    function testRevertsWhenHelperScopeCheckFails() public {
        helper.setScopeResult(false);
        ZKPassportGuardianInit memory init =
            ZKPassportGuardianInit(wallet, identifier, DOMAIN, SCOPE, false, verifier);
        address guardian = factory.deployGuardian(init, bytes32(0));
        bytes32 digest = keccak256("recovery");
        ProofVerificationParams memory params = _defaultParams();
        bytes memory signature =
            _encodeSignature(digest, params, BoundData(wallet, block.chainid, Strings.toHexString(uint256(digest), 32)));
        vm.expectRevert(ZKGuardianScopeMismatch.selector);
        IERC1271(guardian).isValidSignature(digest, signature);
    }

    function testRevertsWhenSenderMismatch() public {
        ZKPassportGuardianInit memory init =
            ZKPassportGuardianInit(wallet, identifier, DOMAIN, SCOPE, false, verifier);
        address guardian = factory.deployGuardian(init, bytes32(0));
        bytes32 digest = keccak256("recovery");
        ProofVerificationParams memory params = _defaultParams();
        bytes memory signature =
            _encodeSignature(digest, params, BoundData(makeAddr("attacker"), block.chainid, Strings.toHexString(uint256(digest), 32)));
        vm.expectRevert(ZKGuardianBoundSenderMismatch.selector);
        IERC1271(guardian).isValidSignature(digest, signature);
    }

    function testRevertsWhenChainIdMismatch() public {
        ZKPassportGuardianInit memory init =
            ZKPassportGuardianInit(wallet, identifier, DOMAIN, SCOPE, false, verifier);
        address guardian = factory.deployGuardian(init, bytes32(0));
        bytes32 digest = keccak256("recovery");
        ProofVerificationParams memory params = _defaultParams();
        bytes memory signature =
            _encodeSignature(digest, params, BoundData(wallet, block.chainid + 1, Strings.toHexString(uint256(digest), 32)));
        vm.expectRevert(ZKGuardianChainIdMismatch.selector);
        IERC1271(guardian).isValidSignature(digest, signature);
    }

    function testRevertsWhenDigestMismatch() public {
        ZKPassportGuardianInit memory init =
            ZKPassportGuardianInit(wallet, identifier, DOMAIN, SCOPE, false, verifier);
        address guardian = factory.deployGuardian(init, bytes32(0));
        bytes32 digest = keccak256("recovery");
        ProofVerificationParams memory params = _defaultParams();
        bytes memory signature =
            _encodeSignature(digest, params, BoundData(wallet, block.chainid, Strings.toHexString(uint256(keccak256("other")), 32)));
        vm.expectRevert(ZKGuardianDigestMismatch.selector);
        IERC1271(guardian).isValidSignature(digest, signature);
    }

    function testApproveMarksDigest() public {
        ZKPassportGuardianInit memory init =
            ZKPassportGuardianInit(wallet, identifier, DOMAIN, SCOPE, false, verifier);
        ZKPassportGuardian guardian = ZKPassportGuardian(factory.deployGuardian(init, bytes32(0)));
        bytes32 digest = keccak256("recovery");
        bytes memory signature =
            _encodeSignature(digest, _defaultParams(), BoundData(wallet, block.chainid, Strings.toHexString(uint256(digest), 32)));
        bytes32 approvedDigest = guardian.approve(signature);
        assertEq(approvedDigest, digest);
        assertTrue(guardian.approved(digest));
    }

    function testApproveRevertsOnDuplicateDigest() public {
        ZKPassportGuardian guardian =
            ZKPassportGuardian(factory.deployGuardian(ZKPassportGuardianInit(wallet, identifier, DOMAIN, SCOPE, false, verifier), bytes32(0)));
        bytes32 digest = keccak256("recovery");
        bytes memory signature =
            _encodeSignature(digest, _defaultParams(), BoundData(wallet, block.chainid, Strings.toHexString(uint256(digest), 32)));
        guardian.approve(signature);
        vm.expectRevert(ZKGuardianDigestAlreadyApproved.selector);
        guardian.approve(signature);
    }

    function testRevertsOnUninitializedClone() public {
        address clone = address(new ZKPassportGuardian());
        vm.expectRevert(ZKGuardianNotInitialized.selector);
        IERC1271(clone).isValidSignature(bytes32(0), hex"");
    }

    function _defaultParams() internal pure returns (ProofVerificationParams memory params) {
        bytes32[] memory publicInputs = new bytes32[](8);
        ProofVerificationData memory proofData =
            ProofVerificationData(bytes32(uint256(1)), hex"1234", publicInputs);
        params = ProofVerificationParams({
            version: bytes32(uint256(2)),
            proofVerificationData: proofData,
            committedInputs: hex"beef",
            serviceConfig: ServiceConfig({
                validityPeriodInSeconds: 1 days,
                domain: DOMAIN,
                scope: SCOPE,
                devMode: false
            })
        });
    }

    function _encodeSignature(bytes32 digest, ProofVerificationParams memory params, BoundData memory bound)
        internal
        returns (bytes memory)
    {
        helper.setBoundData(bound);
        ZKPassportGuardianSignature memory payload = ZKPassportGuardianSignature({params: params, isIDCard: false});
        return abi.encode(payload);
    }
}

contract MockZKPassportVerifier is IZKPassportVerifier {
    bool public verifyResult;
    bytes32 public identifier;
    IZKPassportHelper public helper;

    function setResult(bool result, bytes32 id, IZKPassportHelper helper_) external {
        verifyResult = result;
        identifier = id;
        helper = helper_;
    }

    function verify(ProofVerificationParams calldata)
        external
        override
        returns (bool, bytes32, IZKPassportHelper)
    {
        return (verifyResult, identifier, helper);
    }
}

contract MockZKPassportHelper is IZKPassportHelper {
    BoundData internal bound;
    bool internal scopeResult;

    function setBoundData(BoundData memory data) external {
        bound = data;
    }

    function setScopeResult(bool result) external {
        scopeResult = result;
    }

    function verifyScopes(bytes32[] calldata, string calldata, string calldata) external view returns (bool) {
        return scopeResult;
    }

    function getBoundData(bytes calldata) external view returns (BoundData memory) {
        return bound;
    }
}
