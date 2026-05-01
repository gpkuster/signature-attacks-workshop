// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/SecureSignatureContract.sol";

contract SecureSignatureAttacksTest is Test {
    uint256 internal constant ALICE_PK = 1;
    uint256 internal constant ATTACKER_PK = 2;

    SecureSignatureContract public secureContract;
    
    // Test accounts
    address public alice;
    address public bob = address(0xB0B);
    address public attacker;
    
    function setUp() public {
        alice = vm.addr(ALICE_PK);
        attacker = vm.addr(ATTACKER_PK);
        secureContract = new SecureSignatureContract(alice);
    }

    function _signPacked(
        uint256 privateKey,
        bytes32 hash
    ) internal returns (bytes memory signature) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, hash);
        return abi.encodePacked(r, s, v);
    }
    
    function testValidSignature() public {
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 1 days;
        bytes32 hash = secureContract.getAuthorizationHash(bob, nonce, deadline);
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PK, hash);
        
        secureContract.authorizeUser(v, r, s, bob, nonce, deadline);
        
        assertTrue(secureContract.isAuthorized(bob));
    }
    
    function testRejectsInvalidSignature() public {
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 1 days;
        
        uint8 v = 0;
        bytes32 r = bytes32(0);
        bytes32 s = bytes32(0);
        
        vm.expectRevert("Invalid signature");
        secureContract.authorizeUser(v, r, s, attacker, nonce, deadline);
        
        assertFalse(secureContract.isAuthorized(attacker));
    }
    
    function testRejectsMalformedSignature() public {
        uint256 nonce = 2;
        uint256 deadline = block.timestamp + 1 days;
        
        uint8 v = 255;
        bytes32 r = bytes32(uint256(1));
        bytes32 s = bytes32(uint256(1));
        
        vm.expectRevert("Invalid signature");
        secureContract.authorizeUser(v, r, s, attacker, nonce, deadline);
        
        assertFalse(secureContract.isAuthorized(attacker));
    }
    
    function testRecoverSignerRejectsInvalidSignature() public {
        // Test the recoverSigner function with invalid signature
        uint8 v = 0;
        bytes32 r = bytes32(0);
        bytes32 s = bytes32(0);
        bytes32 hash = keccak256("test");
        
        // This should revert due to the security fix
        vm.expectRevert("Invalid signature");
        secureContract.recoverSigner(v, r, s, hash);
    }
    
    function testReplayAttack() public {
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 1 days;
        bytes32 hash = secureContract.getAuthorizationHash(bob, nonce, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PK, hash);
        
        secureContract.authorizeUser(v, r, s, bob, nonce, deadline);
        
        vm.expectRevert("Hash already used");
        secureContract.authorizeUser(v, r, s, bob, nonce, deadline);
    }
    
    function testProcessDataRequiresAuthorization() public {
        vm.expectRevert("Not authorized");
        secureContract.processData("test data");
        
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 1 days;
        bytes32 hash = secureContract.getAuthorizationHash(address(this), nonce, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PK, hash);
        secureContract.authorizeUser(v, r, s, address(this), nonce, deadline);
        
        assertTrue(secureContract.processData("test data"));
    }

    function testRejectsUnauthorizedSigner() public {
        uint256 nonce = 7;
        uint256 deadline = block.timestamp + 1 days;
        bytes32 hash = secureContract.getAuthorizationHash(bob, nonce, deadline);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ATTACKER_PK, hash);

        vm.expectRevert("Unauthorized signer");
        secureContract.authorizeUser(v, r, s, bob, nonce, deadline);

        assertFalse(secureContract.isAuthorized(bob));
    }

    function testRejectsExpiredSignature() public {
        uint256 nonce = 8;
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 hash = secureContract.getAuthorizationHash(bob, nonce, deadline);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PK, hash);

        vm.warp(deadline + 1);

        vm.expectRevert("Signature expired");
        secureContract.authorizeUser(v, r, s, bob, nonce, deadline);
    }

    function testAuthorizeUserWithECDSAValidSignature() public {
        uint256 nonce = 10;
        uint256 deadline = block.timestamp + 1 days;
        bytes32 hash = secureContract.getAuthorizationHash(bob, nonce, deadline);
        bytes memory signature = _signPacked(ALICE_PK, hash);

        secureContract.authorizeUserWithECDSA(signature, bob, nonce, deadline);

        assertTrue(secureContract.isAuthorized(bob));
    }

    function testAuthorizeUserWithECDSARejectsInvalidLength() public {
        uint256 nonce = 11;
        uint256 deadline = block.timestamp + 1 days;
        bytes memory signature = hex"1234";

        vm.expectRevert("Invalid signature length");
        secureContract.authorizeUserWithECDSA(signature, bob, nonce, deadline);
    }

    function testAuthorizeUserWithECDSARejectsInvalidV() public {
        uint256 nonce = 12;
        uint256 deadline = block.timestamp + 1 days;
        bytes32 hash = secureContract.getAuthorizationHash(bob, nonce, deadline);
        bytes memory signature = _signPacked(ALICE_PK, hash);
        signature[64] = bytes1(uint8(29));

        vm.expectRevert("Invalid signature 'v' value");
        secureContract.authorizeUserWithECDSA(signature, bob, nonce, deadline);
    }

    function testAuthorizeUserWithECDSARejectsMalleableS() public {
        uint256 nonce = 13;
        uint256 deadline = block.timestamp + 1 days;
        bytes32 hash = secureContract.getAuthorizationHash(bob, nonce, deadline);
        bytes memory signature = _signPacked(ALICE_PK, hash);

        bytes32 highS = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A1;
        assembly {
            mstore(add(signature, 64), highS)
        }

        vm.expectRevert("Invalid signature 's' value");
        secureContract.authorizeUserWithECDSA(signature, bob, nonce, deadline);
    }

    function testAuthorizeUserWithECDSARejectsUnauthorizedSigner() public {
        uint256 nonce = 14;
        uint256 deadline = block.timestamp + 1 days;
        bytes32 hash = secureContract.getAuthorizationHash(bob, nonce, deadline);
        bytes memory signature = _signPacked(ATTACKER_PK, hash);

        vm.expectRevert("Unauthorized signer");
        secureContract.authorizeUserWithECDSA(signature, bob, nonce, deadline);
    }

    function testAuthorizeUserWithECDSARejectsReplay() public {
        uint256 nonce = 15;
        uint256 deadline = block.timestamp + 1 days;
        bytes32 hash = secureContract.getAuthorizationHash(bob, nonce, deadline);
        bytes memory signature = _signPacked(ALICE_PK, hash);

        secureContract.authorizeUserWithECDSA(signature, bob, nonce, deadline);

        vm.expectRevert("Hash already used");
        secureContract.authorizeUserWithECDSA(signature, bob, nonce, deadline);
    }

    function testAuthorizeUserWithECDSARejectsExpiredSignature() public {
        uint256 nonce = 16;
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 hash = secureContract.getAuthorizationHash(bob, nonce, deadline);
        bytes memory signature = _signPacked(ALICE_PK, hash);

        vm.warp(deadline + 1);

        vm.expectRevert("Signature expired");
        secureContract.authorizeUserWithECDSA(signature, bob, nonce, deadline);
    }
}
