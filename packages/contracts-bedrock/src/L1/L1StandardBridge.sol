// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

// Contracts
import { ProxyAdminOwnedBase } from "src/L1/ProxyAdminOwnedBase.sol";
import { ReinitializableBase } from "src/universal/ReinitializableBase.sol";
import { StandardBridge } from "src/universal/StandardBridge.sol";

// Libraries
import { Predeploys } from "src/libraries/Predeploys.sol";

// Interfaces
import { ISemver } from "interfaces/universal/ISemver.sol";
import { ICrossDomainMessenger } from "interfaces/universal/ICrossDomainMessenger.sol";
import { ISystemConfig } from "interfaces/L1/ISystemConfig.sol";
import { ISuperchainConfig } from "interfaces/L1/ISuperchainConfig.sol";

/// @custom:proxied true
/// @title L1StandardBridge
/// @notice L1StandardBridge 是 L1 侧的标准桥接合约，负责在 L1 和 L2 之间转移 ETH 和 ERC20 代币。
/// 
/// 核心功能：
/// 1. **存款（Deposit）**：从 L1 向 L2 桥接资产
///    - ETH：通过 OptimismPortal 发送到 L2
///    - ERC20：L1 原生代币锁定在合约中，L2 原生代币在 L1 销毁
/// 
/// 2. **提款最终确认（Withdrawal Finalization）**：确认从 L2 到 L1 的提款
///    - 由 L2StandardBridge 通过跨链消息触发
///    - 验证消息来源后，释放锁定的代币或铸造代币
/// 
/// 代币处理：
/// - **L1 原生代币**：在 L1 锁定（escrow），在 L2 铸造
/// - **L2 原生代币（OptimismMintableERC20）**：在 L1 销毁，在 L2 转移
/// 
/// ETH 处理：
/// - Bedrock 之前：ETH 存储在 L1StandardBridge 中
/// - Bedrock 之后：ETH 存储在 OptimismPortal 中
/// 
/// 重要限制：
/// - 不支持所有类型的 ERC20 代币
/// - 不支持：有转账费用的代币、rebase 代币、有黑名单的代币等
contract L1StandardBridge is StandardBridge, ProxyAdminOwnedBase, ReinitializableBase, ISemver {
    /// @custom:legacy
    /// @notice Emitted whenever a deposit of ETH from L1 into L2 is initiated.
    /// @param from      Address of the depositor.
    /// @param to        Address of the recipient on L2.
    /// @param amount    Amount of ETH deposited.
    /// @param extraData Extra data attached to the deposit.
    event ETHDepositInitiated(address indexed from, address indexed to, uint256 amount, bytes extraData);

    /// @custom:legacy
    /// @notice Emitted whenever a withdrawal of ETH from L2 to L1 is finalized.
    /// @param from      Address of the withdrawer.
    /// @param to        Address of the recipient on L1.
    /// @param amount    Amount of ETH withdrawn.
    /// @param extraData Extra data attached to the withdrawal.
    event ETHWithdrawalFinalized(address indexed from, address indexed to, uint256 amount, bytes extraData);

    /// @custom:legacy
    /// @notice Emitted whenever an ERC20 deposit is initiated.
    /// @param l1Token   Address of the token on L1.
    /// @param l2Token   Address of the corresponding token on L2.
    /// @param from      Address of the depositor.
    /// @param to        Address of the recipient on L2.
    /// @param amount    Amount of the ERC20 deposited.
    /// @param extraData Extra data attached to the deposit.
    event ERC20DepositInitiated(
        address indexed l1Token,
        address indexed l2Token,
        address indexed from,
        address to,
        uint256 amount,
        bytes extraData
    );

    /// @custom:legacy
    /// @notice Emitted whenever an ERC20 withdrawal is finalized.
    /// @param l1Token   Address of the token on L1.
    /// @param l2Token   Address of the corresponding token on L2.
    /// @param from      Address of the withdrawer.
    /// @param to        Address of the recipient on L1.
    /// @param amount    Amount of the ERC20 withdrawn.
    /// @param extraData Extra data attached to the withdrawal.
    event ERC20WithdrawalFinalized(
        address indexed l1Token,
        address indexed l2Token,
        address indexed from,
        address to,
        uint256 amount,
        bytes extraData
    );

    /// @notice Semantic version.
    /// @custom:semver 2.8.0
    string public constant version = "2.8.0";

    /// @custom:legacy
    /// @custom:spacer superchainConfig
    /// @notice Spacer taking up the legacy `superchainConfig` slot.
    address private spacer_50_0_20;

    /// @custom:legacy
    /// @custom:spacer systemConfig
    /// @notice Spacer taking up the legacy `systemConfig` slot.
    address private spacer_51_0_20;

    /// @notice Address of the SystemConfig contract.
    ISystemConfig public systemConfig;

    /// @notice Constructs the L1StandardBridge contract.
    constructor() StandardBridge() ReinitializableBase(3) {
        _disableInitializers();
    }

    /// @notice Initializer.
    /// @param _messenger        Contract for the CrossDomainMessenger on this network.
    /// @param _systemConfig Contract for the SystemConfig on this network.
    function initialize(
        ICrossDomainMessenger _messenger,
        ISystemConfig _systemConfig
    )
        external
        reinitializer(initVersion())
    {
        // Initialization transactions must come from the ProxyAdmin or its owner.
        _assertOnlyProxyAdminOrProxyAdminOwner();

        // Now perform initialization logic.
        systemConfig = _systemConfig;
        __StandardBridge_init({
            _messenger: _messenger,
            _otherBridge: StandardBridge(payable(Predeploys.L2_STANDARD_BRIDGE))
        });
    }

    /// @inheritdoc StandardBridge
    function paused() public view override returns (bool) {
        return systemConfig.paused();
    }

    /// @notice Returns the SuperchainConfig contract.
    /// @return ISuperchainConfig The SuperchainConfig contract.
    function superchainConfig() public view returns (ISuperchainConfig) {
        return systemConfig.superchainConfig();
    }

    /// @notice 允许外部账户（EOA）通过直接向桥接合约发送 ETH 来桥接
    /// 
    /// 这是一个便利函数，用户可以直接向合约地址发送 ETH 来触发桥接。
    /// 使用默认的 gas 限制（RECEIVE_DEFAULT_GAS_LIMIT）。
    receive() external payable override onlyEOA {
        _initiateETHDeposit(msg.sender, msg.sender, RECEIVE_DEFAULT_GAS_LIMIT, bytes(""));
    }

    /// @custom:legacy
    /// @notice 将一定数量的 ETH 存入发送者在 L2 的账户
    /// 
    /// 这是传统的存款函数，用于向后兼容。
    /// 
    /// @param _minGasLimit L2 上存款消息的最小 gas 限制
    /// @param _extraData   可选数据，转发到 L2
    ///                    这些数据不会用于在 L2 上执行代码，仅作为额外数据发出，
    ///                    方便链下工具使用
    function depositETH(uint32 _minGasLimit, bytes calldata _extraData) external payable onlyEOA {
        _initiateETHDeposit(msg.sender, msg.sender, _minGasLimit, _extraData);
    }

    /// @custom:legacy
    /// @notice 将一定数量的 ETH 存入 L2 上的目标账户
    /// 
    /// 重要警告：
    /// - 如果 ETH 发送到 L2 上的智能合约且调用失败，ETH 将被锁定在 L2StandardBridge 中
    /// - 如果可以通过增加 gas 成功重放调用，ETH 可能可以恢复
    /// - 如果调用在任何数量的 gas 下都会失败，ETH 将永久锁定
    /// 
    /// @param _to          L2 上的接收者地址
    /// @param _minGasLimit L2 上存款消息的最小 gas 限制
    /// @param _extraData   可选数据，转发到 L2
    ///                    这些数据不会用于在 L2 上执行代码，仅作为额外数据发出，
    ///                    方便链下工具使用
    function depositETHTo(address _to, uint32 _minGasLimit, bytes calldata _extraData) external payable {
        _initiateETHDeposit(msg.sender, _to, _minGasLimit, _extraData);
    }

    /// @custom:legacy
    /// @notice 将一定数量的 ERC20 代币存入发送者在 L2 的账户
    /// 
    /// 这是传统的 ERC20 存款函数，用于向后兼容。
    /// 
    /// 代币处理：
    /// - L1 原生代币：锁定在 L1StandardBridge 中，在 L2 铸造
    /// - L2 原生代币（OptimismMintableERC20）：在 L1 销毁，在 L2 转移
    /// 
    /// @param _l1Token    正在存入的 L1 代币地址
    /// @param _l2Token    L2 上对应的代币地址
    /// @param _amount     要存入的 ERC20 数量
    /// @param _minGasLimit L2 上存款消息的最小 gas 限制
    /// @param _extraData   可选数据，转发到 L2
    ///                    这些数据不会用于在 L2 上执行代码，仅作为额外数据发出，
    ///                    方便链下工具使用
    function depositERC20(
        address _l1Token,
        address _l2Token,
        uint256 _amount,
        uint32 _minGasLimit,
        bytes calldata _extraData
    )
        external
        virtual
        onlyEOA
    {
        _initiateERC20Deposit(_l1Token, _l2Token, msg.sender, msg.sender, _amount, _minGasLimit, _extraData);
    }

    /// @custom:legacy
    /// @notice 将一定数量的 ERC20 代币存入 L2 上的目标账户
    /// 
    /// 代币处理：
    /// - L1 原生代币：锁定在 L1StandardBridge 中，在 L2 铸造
    /// - L2 原生代币（OptimismMintableERC20）：在 L1 销毁，在 L2 转移
    /// 
    /// @param _l1Token    正在存入的 L1 代币地址
    /// @param _l2Token    L2 上对应的代币地址
    /// @param _to         L2 上的接收者地址
    /// @param _amount     要存入的 ERC20 数量
    /// @param _minGasLimit L2 上存款消息的最小 gas 限制
    /// @param _extraData   可选数据，转发到 L2
    ///                    这些数据不会用于在 L2 上执行代码，仅作为额外数据发出，
    ///                    方便链下工具使用
    function depositERC20To(
        address _l1Token,
        address _l2Token,
        address _to,
        uint256 _amount,
        uint32 _minGasLimit,
        bytes calldata _extraData
    )
        external
        virtual
    {
        _initiateERC20Deposit(_l1Token, _l2Token, msg.sender, _to, _amount, _minGasLimit, _extraData);
    }

    /// @custom:legacy
    /// @notice 最终确认从 L2 到 L1 的 ETH 提款
    /// 
    /// 这是提款流程的最后一步。由 L2StandardBridge 通过跨链消息调用。
    /// 在 OptimismPortal 中证明提款后，最终在这里确认并释放 ETH。
    /// 
    /// @param _from      L2 上的提款者地址
    /// @param _to        L1 上的接收者地址
    /// @param _amount    要提款的 ETH 数量
    /// @param _extraData 从 L2 转发的可选数据
    function finalizeETHWithdrawal(
        address _from,
        address _to,
        uint256 _amount,
        bytes calldata _extraData
    )
        external
        payable
    {
        // 调用基类的 finalizeBridgeETH，它会验证消息来源并执行转账
        finalizeBridgeETH(_from, _to, _amount, _extraData);
    }

    /// @custom:legacy
    /// @notice 最终确认从 L2 到 L1 的 ERC20 代币提款
    /// 
    /// 这是提款流程的最后一步。由 L2StandardBridge 通过跨链消息调用。
    /// 
    /// 代币处理：
    /// - L1 原生代币：从 deposits 映射中扣除并转账给接收者
    /// - L2 原生代币（OptimismMintableERC20）：在 L1 铸造给接收者
    /// 
    /// @param _l1Token   L1 上的代币地址
    /// @param _l2Token   L2 上对应的代币地址
    /// @param _from      L2 上的提款者地址
    /// @param _to        L1 上的接收者地址
    /// @param _amount    要提款的 ERC20 数量
    /// @param _extraData 从 L2 转发的可选数据
    function finalizeERC20Withdrawal(
        address _l1Token,
        address _l2Token,
        address _from,
        address _to,
        uint256 _amount,
        bytes calldata _extraData
    )
        external
    {
        // 调用基类的 finalizeBridgeERC20，它会验证消息来源并处理代币
        finalizeBridgeERC20(_l1Token, _l2Token, _from, _to, _amount, _extraData);
    }

    /// @custom:legacy
    /// @notice Retrieves the access of the corresponding L2 bridge contract.
    /// @return Address of the corresponding L2 bridge contract.
    function l2TokenBridge() external view returns (address) {
        return address(otherBridge);
    }

    /// @notice Internal function for initiating an ETH deposit.
    /// @param _from        Address of the sender on L1.
    /// @param _to          Address of the recipient on L2.
    /// @param _minGasLimit Minimum gas limit for the deposit message on L2.
    /// @param _extraData   Optional data to forward to L2.
    function _initiateETHDeposit(address _from, address _to, uint32 _minGasLimit, bytes memory _extraData) internal {
        _initiateBridgeETH(_from, _to, msg.value, _minGasLimit, _extraData);
    }

    /// @notice Internal function for initiating an ERC20 deposit.
    /// @param _l1Token     Address of the L1 token being deposited.
    /// @param _l2Token     Address of the corresponding token on L2.
    /// @param _from        Address of the sender on L1.
    /// @param _to          Address of the recipient on L2.
    /// @param _amount      Amount of the ERC20 to deposit.
    /// @param _minGasLimit Minimum gas limit for the deposit message on L2.
    /// @param _extraData   Optional data to forward to L2.
    function _initiateERC20Deposit(
        address _l1Token,
        address _l2Token,
        address _from,
        address _to,
        uint256 _amount,
        uint32 _minGasLimit,
        bytes memory _extraData
    )
        internal
    {
        _initiateBridgeERC20(_l1Token, _l2Token, _from, _to, _amount, _minGasLimit, _extraData);
    }

    /// @inheritdoc StandardBridge
    /// @notice Emits the legacy ETHDepositInitiated event followed by the ETHBridgeInitiated event.
    ///         This is necessary for backwards compatibility with the legacy bridge.
    function _emitETHBridgeInitiated(
        address _from,
        address _to,
        uint256 _amount,
        bytes memory _extraData
    )
        internal
        override
    {
        emit ETHDepositInitiated(_from, _to, _amount, _extraData);
        super._emitETHBridgeInitiated(_from, _to, _amount, _extraData);
    }

    /// @inheritdoc StandardBridge
    /// @notice Emits the legacy ERC20DepositInitiated event followed by the ERC20BridgeInitiated
    ///         event. This is necessary for backwards compatibility with the legacy bridge.
    function _emitETHBridgeFinalized(
        address _from,
        address _to,
        uint256 _amount,
        bytes memory _extraData
    )
        internal
        override
    {
        emit ETHWithdrawalFinalized(_from, _to, _amount, _extraData);
        super._emitETHBridgeFinalized(_from, _to, _amount, _extraData);
    }

    /// @inheritdoc StandardBridge
    /// @notice Emits the legacy ERC20WithdrawalFinalized event followed by the ERC20BridgeFinalized
    ///         event. This is necessary for backwards compatibility with the legacy bridge.
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
        emit ERC20DepositInitiated(_localToken, _remoteToken, _from, _to, _amount, _extraData);
        super._emitERC20BridgeInitiated(_localToken, _remoteToken, _from, _to, _amount, _extraData);
    }

    /// @inheritdoc StandardBridge
    /// @notice Emits the legacy ERC20WithdrawalFinalized event followed by the ERC20BridgeFinalized
    ///         event. This is necessary for backwards compatibility with the legacy bridge.
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
        emit ERC20WithdrawalFinalized(_localToken, _remoteToken, _from, _to, _amount, _extraData);
        super._emitERC20BridgeFinalized(_localToken, _remoteToken, _from, _to, _amount, _extraData);
    }
}
