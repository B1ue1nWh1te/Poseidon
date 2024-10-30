// SPDX-License-Identifier: UNLICENSED
pragma solidity =0.8.28;

contract Test {
    string private slot0;

    constructor(string memory _slot0) {
        slot0 = _slot0;
    }

    function readSlot0() external view returns (string memory) {
        return slot0;
    }

    function writeSlot0(string memory _slot0) external {
        slot0 = _slot0;
    }
}
