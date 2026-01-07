// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

// Contracts
import { StandardBridge } from "src/universal/StandardBridge.sol";

// Libraries
import { Predeploys } from "src/libraries/Predeploys.sol";

// Interfaces
import { ISemver } from "interfaces/universal/ISemver.sol";
import { ICrossDomainMessenger } from "interfaces/universal/ICrossDomainMessenger.sol";
import { OptimismMintableERC20 } from "src/universal/OptimismMintableERC20.sol";

/// @custom:proxied true
/// @custom:predeploy 0x4200000000000000000000000000000000000010
/// @title L2StandardBridge
/// @notice L2StandardBridge 是 L2 侧的标准桥接合约，负责在 L1 和 L2 之间转移 ETH 和 ERC20 代币。
/// 
/// 核心功能：
/// 1. **提款（Withdrawal）**：从 L2 向 L1 桥接资产
///    - ETH：通过 CrossDomainMessenger 发送到 L1
///    - ERC20：L2 原生代币锁定在合约中，L1 原生代币在 L2 销毁
/// 
/// 2. **存款最终确认（Deposit Finalization）**：确认从 L1 到 L2 的存款
///    - 由 L1StandardBridge 通过跨链消息触发
///    - 验证消息来源后，铸造代币或转移代币
/// 
/// 代币处理：
/// - **L2 原生代币**：在 L2 锁定（escrow），在 L1 转移
/// - **L1 原生代币（OptimismMintableERC20）**：在 L2 销毁，在 L1 转移
/// 
/// 重要限制：
/// - 不支持所有类型的 ERC20 代币
/// - 不支持：有转账费用的代币、rebase 代币、有黑名单的代币等
contract L2StandardBridge is StandardBridge, ISemver {
    /// @custom:legacy
    /// @notice Emitted whenever a withdrawal from L2 to L1 is initiated.
    /// @param l1Token   Address of the token on L1.
    /// @param l2Token   Address of the corresponding token on L2.
    /// @param from      Address of the withdrawer.
    /// @param to        Address of the recipient on L1.
    /// @param amount    Amount of the ERC20 withdrawn.
    /// @param extraData Extra data attached to the withdrawal.
    event WithdrawalInitiated(
        address indexed l1Token,
        address indexed l2Token,
        address indexed from,
        address to,
        uint256 amount,
        bytes extraData
    );

    /// @custom:legacy
    /// @notice Emitted whenever an ERC20 deposit is finalized.
    /// @param l1Token   Address of the token on L1.
    /// @param l2Token   Address of the corresponding token on L2.
    /// @param from      Address of the depositor.
    /// @param to        Address of the recipient on L2.
    /// @param amount    Amount of the ERC20 deposited.
    /// @param extraData Extra data attached to the deposit.
    event DepositFinalized(
        address indexed l1Token,
        address indexed l2Token,
        address indexed from,
        address to,
        uint256 amount,
        bytes extraData
    );

    /// @notice Semantic version.
    /// @custom:semver 1.13.0
    function version() public pure virtual returns (string memory) {
        return "1.13.0";
    }

    /// @notice Constructs the L2StandardBridge contract.
    constructor() StandardBridge() {
        _disableInitializers();
    }

    /// @notice Initializer.
    /// @param _otherBridge Contract for the corresponding bridge on the other chain.
    function initialize(StandardBridge _otherBridge) external initializer {
        __StandardBridge_init({
            _messenger: ICrossDomainMessenger(Predeploys.L2_CROSS_DOMAIN_MESSENGER),
            _otherBridge: _otherBridge
        });
    }

    /// @notice Allows EOAs to bridge ETH by sending directly to the bridge.
    receive() external payable override onlyEOA {
        _initiateWithdrawal(
            Predeploys.LEGACY_ERC20_ETH, msg.sender, msg.sender, msg.value, RECEIVE_DEFAULT_GAS_LIMIT, bytes("")
        );
    }

    /// @custom:legacy
    /// @notice 发起从 L2 到 L1 的提款
    /// 
    /// 这是传统的提款函数，用于向后兼容。
    /// 只适用于 OptimismMintableERC20 代币或 ETH。
    /// 对于原生 L2 代币，请使用 `bridgeERC20` 函数。
    /// 
    /// 注意：此函数可能在将来被弃用。
    /// 
    /// @param _l2Token    要提款的 L2 代币地址
    /// @param _amount     要提款的 L2 代币数量
    /// @param _minGasLimit 交易使用的最小 gas 限制
    /// @param _extraData   附加到提款的额外数据
    function withdraw(
        address _l2Token,
        uint256 _amount,
        uint32 _minGasLimit,
        bytes calldata _extraData
    )
        external
        payable
        virtual
        onlyEOA
    {
        _initiateWithdrawal(_l2Token, msg.sender, msg.sender, _amount, _minGasLimit, _extraData);
    }

    /// @custom:legacy
    /// @notice 发起从 L2 到 L1 的提款，发送到 L1 上的目标账户
    /// 
    /// 重要警告：
    /// - 如果 ETH 发送到 L1 上的智能合约且调用失败，ETH 将被锁定在 L1StandardBridge 中
    /// - 如果可以通过增加 gas 成功重放调用，ETH 可能可以恢复
    /// - 如果调用在任何数量的 gas 下都会失败，ETH 将永久锁定
    /// 
    /// 只适用于 OptimismMintableERC20 代币或 ETH。
    /// 对于原生 L2 代币，请使用 `bridgeERC20To` 函数。
    /// 
    /// 注意：此函数可能在将来被弃用。
    /// 
    /// @param _l2Token    要提款的 L2 代币地址
    /// @param _to         L1 上的接收者账户
    /// @param _amount     要提款的 L2 代币数量
    /// @param _minGasLimit 交易使用的最小 gas 限制
    /// @param _extraData   附加到提款的额外数据
    function withdrawTo(
        address _l2Token,
        address _to,
        uint256 _amount,
        uint32 _minGasLimit,
        bytes calldata _extraData
    )
        external
        payable
        virtual
    {
        _initiateWithdrawal(_l2Token, msg.sender, _to, _amount, _minGasLimit, _extraData);
    }

    /// @custom:legacy
    /// @notice Retrieves the access of the corresponding L1 bridge contract.
    /// @return Address of the corresponding L1 bridge contract.
    function l1TokenBridge() external view returns (address) {
        return address(otherBridge);
    }

    /// @custom:legacy
    /// @notice 内部函数：发起从 L2 到 L1 的提款，发送到 L1 上的目标账户
    /// 
    /// 这个函数根据代币类型选择不同的处理方式：
    /// 1. **ETH**：调用 `_initiateBridgeETH` 处理 ETH 提款
    /// 2. **ERC20 代币**：获取对应的 L1 代币地址，调用 `_initiateBridgeERC20` 处理
    /// 
    /// 对于 OptimismMintableERC20 代币，会通过 `l1Token()` 获取对应的 L1 代币地址。
    /// 
    /// @param _l2Token    要提款的 L2 代币地址
    /// @param _from       提款者地址
    /// @param _to         L1 上的接收者账户
    /// @param _amount     要提款的 L2 代币数量
    /// @param _minGasLimit 交易使用的最小 gas 限制
    /// @param _extraData   附加到提款的额外数据
    function _initiateWithdrawal(
        address _l2Token,
        address _from,
        address _to,
        uint256 _amount,
        uint32 _minGasLimit,
        bytes memory _extraData
    )
        internal
    {
        // 判断是 ETH 还是 ERC20 代币
        if (_l2Token == Predeploys.LEGACY_ERC20_ETH) {
            // ETH 提款：直接调用 ETH 桥接函数
            _initiateBridgeETH(_from, _to, _amount, _minGasLimit, _extraData);
        } else {
            // ERC20 代币提款：获取对应的 L1 代币地址
            // 对于 OptimismMintableERC20，l1Token() 返回对应的 L1 代币地址
            address l1Token = OptimismMintableERC20(_l2Token).l1Token();
            _initiateBridgeERC20(_l2Token, l1Token, _from, _to, _amount, _minGasLimit, _extraData);
        }
    }

    /// @notice Emits the legacy WithdrawalInitiated event followed by the ETHBridgeInitiated event.
    ///         This is necessary for backwards compatibility with the legacy bridge.
    /// @inheritdoc StandardBridge
    function _emitETHBridgeInitiated(
        address _from,
        address _to,
        uint256 _amount,
        bytes memory _extraData
    )
        internal
        override
    {
        emit WithdrawalInitiated(address(0), Predeploys.LEGACY_ERC20_ETH, _from, _to, _amount, _extraData);
        super._emitETHBridgeInitiated(_from, _to, _amount, _extraData);
    }

    /// @notice Emits the legacy DepositFinalized event followed by the ETHBridgeFinalized event.
    ///         This is necessary for backwards compatibility with the legacy bridge.
    /// @inheritdoc StandardBridge
    function _emitETHBridgeFinalized(
        address _from,
        address _to,
        uint256 _amount,
        bytes memory _extraData
    )
        internal
        override
    {
        emit DepositFinalized(address(0), Predeploys.LEGACY_ERC20_ETH, _from, _to, _amount, _extraData);
        super._emitETHBridgeFinalized(_from, _to, _amount, _extraData);
    }

    /// @notice Emits the legacy WithdrawalInitiated event followed by the ERC20BridgeInitiated
    ///         event. This is necessary for backwards compatibility with the legacy bridge.
    /// @inheritdoc StandardBridge
    function _emitERC20BridgeInitiated(
        address _localToken,
        address _remoteToken,
        address _from,
        address _to,
        uint256 _amount,
        bytes memory _extraData
    )
        internal
        override
    {
        emit WithdrawalInitiated(_remoteToken, _localToken, _from, _to, _amount, _extraData);
        super._emitERC20BridgeInitiated(_localToken, _remoteToken, _from, _to, _amount, _extraData);
    }

    /// @notice Emits the legacy DepositFinalized event followed by the ERC20BridgeFinalized event.
    ///         This is necessary for backwards compatibility with the legacy bridge.
    /// @inheritdoc StandardBridge
    function _emitERC20BridgeFinalized(
        address _localToken,
        address _remoteToken,
        address _from,
        address _to,
        uint256 _amount,
        bytes memory _extraData
    )
        internal
        override
    {
        emit DepositFinalized(_remoteToken, _localToken, _from, _to, _amount, _extraData);
        super._emitERC20BridgeFinalized(_localToken, _remoteToken, _from, _to, _amount, _extraData);
    }
}
