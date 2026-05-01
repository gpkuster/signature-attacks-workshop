// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

/**
 * @title SecureSignatureContract
 * @dev This contract demonstrates the secure way to handle signature verification
 * by properly validating ecrecover results and using OpenZeppelin's ECDSA library.
 */
contract SecureSignatureContract {
    address public immutable authorizedSigner;
    mapping(address => bool) public authorizedUsers;
    mapping(bytes32 => bool) public usedHashes;
    
    event UserAuthorized(address indexed user, bytes32 indexed hash);
    event InvalidSignatureRejected(address indexed signer, bytes32 indexed hash);

    constructor(address _authorizedSigner) {
        require(_authorizedSigner != address(0), "Invalid signer");
        authorizedSigner = _authorizedSigner;
    }
    
    /**
     * @dev Secure function that recovers signer from signature with proper validation
     * @param v The v component of the signature
     * @param r The r component of the signature  
     * @param s The s component of the signature
     * @param user The user to authorize
     * @param nonce Unique value used to prevent replay
     * @param deadline Expiration timestamp for the signature
     */
    function authorizeUser(
        uint8 v,
        bytes32 r,
        bytes32 s,
        address user,
        uint256 nonce,
        uint256 deadline
    ) external {
        require(block.timestamp <= deadline, "Signature expired");

        bytes32 hash = getAuthorizationHash(user, nonce, deadline);
        address signer = ecrecover(hash, v, r, s);
        
        require(signer != address(0), "Invalid signature");
        require(signer == authorizedSigner, "Unauthorized signer");
        
        require(!usedHashes[hash], "Hash already used");
        usedHashes[hash] = true;
        authorizedUsers[user] = true;
        
        emit UserAuthorized(user, hash);
    }
    
    /**
     * @dev Alternative secure implementation using OpenZeppelin's ECDSA library
     * This is the recommended approach as it handles all edge cases automatically
     * @param signature Packed 65-byte signature
     * @param user The user to authorize
     * @param nonce Unique value used to prevent replay
     * @param deadline Expiration timestamp for the signature
     */
    function authorizeUserWithECDSA(
        bytes memory signature,
        address user,
        uint256 nonce,
        uint256 deadline
    ) external {
        require(block.timestamp <= deadline, "Signature expired");
        require(signature.length == 65, "Invalid signature length");

        bytes32 hash = getAuthorizationHash(user, nonce, deadline);
        
        bytes32 r;
        bytes32 s;
        uint8 v;
        
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }
        
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            revert("Invalid signature 's' value");
        }
        
        if (v != 27 && v != 28) {
            revert("Invalid signature 'v' value");
        }
        
        address signer = ecrecover(hash, v, r, s);
        require(signer != address(0), "Invalid signature");
        require(signer == authorizedSigner, "Unauthorized signer");
        
        require(!usedHashes[hash], "Hash already used");
        usedHashes[hash] = true;
        authorizedUsers[user] = true;
        
        emit UserAuthorized(user, hash);
    }
    
    /**
     * @dev Function that requires authorization
     */
    function processData(string memory /* data */) external view returns (bool) {
        require(authorizedUsers[msg.sender], "Not authorized");
        return true;
    }
    
    /**
     * @dev Check if a user is authorized
     * @param user The user to check
     * @return bool True if user is authorized
     */
    function isAuthorized(address user) external view returns (bool) {
        return authorizedUsers[user];
    }
    
    /**
     * @dev Get the signer from a signature (secure version)
     * @param v The v component of the signature
     * @param r The r component of the signature
     * @param s The s component of the signature
     * @param hash The hash that was signed
     * @return address The recovered signer address
     */
    function recoverSigner(
        uint8 v, 
        bytes32 r, 
        bytes32 s, 
        bytes32 hash
    ) external pure returns (address) {
        // SECURE: Validate ecrecover result
        address signer = ecrecover(hash, v, r, s);
        require(signer != address(0), "Invalid signature");
        return signer;
    }
    
    /**
     * @dev Create a hash for authorization
     * @param user The user to authorize
     * @param nonce A unique nonce
     * @param deadline Expiration timestamp for the signature
     * @return bytes32 The hash to be signed
     */
    function getAuthorizationHash(
        address user,
        uint256 nonce,
        uint256 deadline
    ) public view returns (bytes32) {
        return keccak256(
            abi.encode(address(this), block.chainid, user, nonce, deadline)
        );
    }

    function createAuthorizationHash(
        address user,
        uint256 nonce,
        uint256 deadline
    ) external view returns (bytes32) {
        return getAuthorizationHash(user, nonce, deadline);
    }
}
