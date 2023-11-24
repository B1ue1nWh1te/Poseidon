// SPDX-License-Identifier: UNLICENSED

pragma solidity ^0.8.0;

contract Test {
    string private nothing;

    receive() external payable {}

    constructor(string memory _nothing) {
        nothing = _nothing;
    }

    function readTest() public view returns (string memory) {
        return nothing;
    }

    function writeTest(string memory _nothing) public {
        nothing = _nothing;
    }
}
