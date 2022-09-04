pragma solidity ^0.8.0;

contract Test {
    string public s;
    uint256 public i;

    constructor(string memory _s, uint256 _i) public {
        s = _s;
        i = _i;
    }

    function change_s(string memory _s) public {
        s = _s;
    }

    function change_i(uint256 _i) public {
        i = _i;
    }
}
