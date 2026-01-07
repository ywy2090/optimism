// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

// Contracts
import { Initializable } from "@openzeppelin/contracts/proxy/utils/Initializable.sol";

// Libraries
import { ERC165Checker } from "@openzeppelin/contracts/utils/introspection/ERC165Checker.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { SafeCall } from "src/libraries/SafeCall.sol";
import { EOA } from "src/libraries/EOA.sol";

// Interfaces
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { IOptimismMintableERC20 } from "interfaces/universal/IOptimismMintableERC20.sol";
import { ILegacyMintableERC20 } from "interfaces/legacy/ILegacyMintableERC20.sol";
import { ICrossDomainMessenger } from "interfaces/universal/ICrossDomainMessenger.sol";

/// @custom:upgradeable
/// @title StandardBridge
/// @notice StandardBridge 是 L1 和 L2 标准 ERC20 桥接合约的基类。
/// 
/// 核心功能：
/// 1. **桥接发起**：处理从本地链到远程链的资产桥接
/// 2. **桥接确认**：处理从远程链到本地链的桥接最终确认
/// 3. **代币管理**：
///    - 本地链原生代币：在本地链锁定（escrow），在远程链铸造
///    - 远程链原生代币：在本地链销毁，在远程链转移
/// 
/// 桥接流程：
/// - **发起桥接**：用户调用 bridgeETH/bridgeERC20 → 通过 CrossDomainMessenger 发送消息
/// - **最终确认**：远程链的桥接合约通过 CrossDomainMessenger 调用 finalizeBridgeETH/finalizeBridgeERC20
/// 
/// 安全机制：
/// - onlyEOA：防止智能合约钱包意外桥接
/// - onlyOtherBridge：确保只有对侧链的桥接合约可以最终确认
/// - paused()：支持暂停机制
abstract contract StandardBridge is Initializable {
    using SafeERC20 for IERC20;

    /// @notice The L2 gas limit set when eth is depoisited using the receive() function.
    uint32 internal constant RECEIVE_DEFAULT_GAS_LIMIT = 200_000;

    /// @custom:legacy
    /// @custom:spacer messenger
    /// @notice Spacer for backwards compatibility.
    bytes30 private spacer_0_2_30;

    /// @custom:legacy
    /// @custom:spacer l2TokenBridge
    /// @notice Spacer for backwards compatibility.
    address private spacer_1_0_20;

    /// @notice 存储本地代币和远程代币对的存款数量
    /// 
    /// 映射结构：deposits[localToken][remoteToken] = amount
    /// 
    /// 用途：
    /// - 对于本地链原生代币（非 OptimismMintableERC20），记录锁定在桥接合约中的数量
    /// - 当远程链的桥接最终确认时，从这个映射中扣除相应的数量
    /// 
    /// 示例：
    /// - L1 上的 USDC（本地代币）桥接到 L2：deposits[L1_USDC][L2_USDC] += amount
    /// - L2 上的桥接最终确认时：deposits[L1_USDC][L2_USDC] -= amount
    mapping(address => mapping(address => uint256)) public deposits;

    /// @notice Messenger contract on this domain.
    /// @custom:network-specific
    ICrossDomainMessenger public messenger;

    /// @notice Corresponding bridge on the other domain.
    /// @custom:network-specific
    StandardBridge public otherBridge;

    /// @notice Reserve extra slots (to a total of 50) in the storage layout for future upgrades.
    ///         A gap size of 45 was chosen here, so that the first slot used in a child contract
    ///         would be a multiple of 50.
    uint256[45] private __gap;

    /// @notice Emitted when an ETH bridge is initiated to the other chain.
    /// @param from      Address of the sender.
    /// @param to        Address of the receiver.
    /// @param amount    Amount of ETH sent.
    /// @param extraData Extra data sent with the transaction.
    event ETHBridgeInitiated(address indexed from, address indexed to, uint256 amount, bytes extraData);

    /// @notice Emitted when an ETH bridge is finalized on this chain.
    /// @param from      Address of the sender.
    /// @param to        Address of the receiver.
    /// @param amount    Amount of ETH sent.
    /// @param extraData Extra data sent with the transaction.
    event ETHBridgeFinalized(address indexed from, address indexed to, uint256 amount, bytes extraData);

    /// @notice Emitted when an ERC20 bridge is initiated to the other chain.
    /// @param localToken  Address of the ERC20 on this chain.
    /// @param remoteToken Address of the ERC20 on the remote chain.
    /// @param from        Address of the sender.
    /// @param to          Address of the receiver.
    /// @param amount      Amount of the ERC20 sent.
    /// @param extraData   Extra data sent with the transaction.
    event ERC20BridgeInitiated(
        address indexed localToken,
        address indexed remoteToken,
        address indexed from,
        address to,
        uint256 amount,
        bytes extraData
    );

    /// @notice Emitted when an ERC20 bridge is finalized on this chain.
    /// @param localToken  Address of the ERC20 on this chain.
    /// @param remoteToken Address of the ERC20 on the remote chain.
    /// @param from        Address of the sender.
    /// @param to          Address of the receiver.
    /// @param amount      Amount of the ERC20 sent.
    /// @param extraData   Extra data sent with the transaction.
    event ERC20BridgeFinalized(
        address indexed localToken,
        address indexed remoteToken,
        address indexed from,
        address to,
        uint256 amount,
        bytes extraData
    );

    /// @notice 只允许外部账户（EOA）调用函数
    /// 
    /// 安全考虑：
    /// - 防止智能合约钱包意外桥接资产
    /// - 注意：这不完全安全，因为合约可以在构造函数中调用代码
    /// - 但主要目的是防止用户意外使用智能合约钱包进行桥接
    modifier onlyEOA() {
        require(EOA.isSenderEOA(), "StandardBridge: function can only be called from an EOA");
        _;
    }

    /// @notice 确保调用者是对侧链桥接合约通过跨链消息发送的
    /// 
    /// 验证逻辑：
    /// 1. msg.sender 必须是 messenger 合约地址
    /// 2. messenger.xDomainMessageSender() 必须是对侧链的桥接合约地址
    /// 
    /// 这是关键的安全检查，确保只有对侧链的桥接合约可以最终确认桥接操作
    modifier onlyOtherBridge() {
        require(
            msg.sender == address(messenger) && messenger.xDomainMessageSender() == address(otherBridge),
            "StandardBridge: function can only be called from the other bridge"
        );
        _;
    }

    /// @notice Initializer.
    /// @param _messenger   Contract for CrossDomainMessenger on this network.
    /// @param _otherBridge Contract for the other StandardBridge contract.
    function __StandardBridge_init(
        ICrossDomainMessenger _messenger,
        StandardBridge _otherBridge
    )
        internal
        onlyInitializing
    {
        messenger = _messenger;
        otherBridge = _otherBridge;
    }

    /// @notice Allows EOAs to bridge ETH by sending directly to the bridge.
    ///         Must be implemented by contracts that inherit.
    receive() external payable virtual;

    /// @notice Getter for messenger contract.
    ///         Public getter is legacy and will be removed in the future. Use `messenger` instead.
    /// @return Contract of the messenger on this domain.
    /// @custom:legacy
    function MESSENGER() external view returns (ICrossDomainMessenger) {
        return messenger;
    }

    /// @notice Getter for the other bridge contract.
    ///         Public getter is legacy and will be removed in the future. Use `otherBridge` instead.
    /// @return Contract of the bridge on the other network.
    /// @custom:legacy
    function OTHER_BRIDGE() external view returns (StandardBridge) {
        return otherBridge;
    }

    /// @notice This function should return true if the contract is paused.
    ///         On L1 this function will check the SuperchainConfig for its paused status.
    ///         On L2 this function should be a no-op.
    /// @return Whether or not the contract is paused.
    function paused() public view virtual returns (bool) {
        return false;
    }

    /// @notice 将 ETH 桥接到发送者在对侧链的地址
    /// 
    /// 流程：
    /// 1. 接收 ETH（通过 msg.value）
    /// 2. 通过 CrossDomainMessenger 发送消息到对侧链的桥接合约
    /// 3. 对侧链的桥接合约最终确认并转账 ETH
    /// 
    /// @param _minGasLimit 桥接可以中继的最小 gas 数量
    /// @param _extraData    额外数据，不会触发接收者，但会发出事件，可用于识别交易
    function bridgeETH(uint32 _minGasLimit, bytes calldata _extraData) public payable onlyEOA {
        _initiateBridgeETH(msg.sender, msg.sender, msg.value, _minGasLimit, _extraData);
    }

    /// @notice 将 ETH 桥接到指定接收者在对侧链的地址
    /// 
    /// 重要警告：
    /// - 如果 ETH 发送到智能合约且调用失败，ETH 会暂时锁定在对侧链的 StandardBridge 中
    /// - 如果调用无法用任何数量的 gas 重放（总是回滚），ETH 将永久锁定
    /// - 如果接收者是对侧链的桥接合约，ETH 也会被锁定（因为 finalizeBridgeETH 会回滚）
    /// 
    /// @param _to          接收者地址
    /// @param _minGasLimit 桥接可以中继的最小 gas 数量
    /// @param _extraData   额外数据，不会触发接收者，但会发出事件，可用于识别交易
    function bridgeETHTo(address _to, uint32 _minGasLimit, bytes calldata _extraData) public payable {
        _initiateBridgeETH(msg.sender, _to, msg.value, _minGasLimit, _extraData);
    }

    /// @notice Sends ERC20 tokens to the sender's address on the other chain.
    /// @param _localToken  Address of the ERC20 on this chain.
    /// @param _remoteToken Address of the corresponding token on the remote chain.
    /// @param _amount      Amount of local tokens to deposit.
    /// @param _minGasLimit Minimum amount of gas that the bridge can be relayed with.
    /// @param _extraData   Extra data to be sent with the transaction. Note that the recipient will
    ///                     not be triggered with this data, but it will be emitted and can be used
    ///                     to identify the transaction.
    function bridgeERC20(
        address _localToken,
        address _remoteToken,
        uint256 _amount,
        uint32 _minGasLimit,
        bytes calldata _extraData
    )
        public
        virtual
        onlyEOA
    {
        _initiateBridgeERC20(_localToken, _remoteToken, msg.sender, msg.sender, _amount, _minGasLimit, _extraData);
    }

    /// @notice Sends ERC20 tokens to a receiver's address on the other chain.
    /// @param _localToken  Address of the ERC20 on this chain.
    /// @param _remoteToken Address of the corresponding token on the remote chain.
    /// @param _to          Address of the receiver.
    /// @param _amount      Amount of local tokens to deposit.
    /// @param _minGasLimit Minimum amount of gas that the bridge can be relayed with.
    /// @param _extraData   Extra data to be sent with the transaction. Note that the recipient will
    ///                     not be triggered with this data, but it will be emitted and can be used
    ///                     to identify the transaction.
    function bridgeERC20To(
        address _localToken,
        address _remoteToken,
        address _to,
        uint256 _amount,
        uint32 _minGasLimit,
        bytes calldata _extraData
    )
        public
        virtual
    {
        _initiateBridgeERC20(_localToken, _remoteToken, msg.sender, _to, _amount, _minGasLimit, _extraData);
    }

    /// @notice 在本链上最终确认 ETH 桥接
    /// 
    /// 这是桥接流程的第二阶段（第一阶段在对侧链发起）。
    /// 只能由对侧链的 StandardBridge 合约通过跨链消息触发。
    /// 
    /// 流程：
    /// 1. 验证调用来源（onlyOtherBridge 修饰符）
    /// 2. 检查合约未暂停
    /// 3. 验证发送的 ETH 数量匹配
    /// 4. 验证目标地址安全（不能是桥接合约自身或 messenger）
    /// 5. 发出事件
    /// 6. 执行 ETH 转账
    /// 
    /// @param _from      发送者地址（在对侧链）
    /// @param _to        接收者地址（在本链）
    /// @param _amount    桥接的 ETH 数量
    /// @param _extraData 额外数据，不会触发接收者，但会发出事件，可用于识别交易
    function finalizeBridgeETH(
        address _from,
        address _to,
        uint256 _amount,
        bytes calldata _extraData
    )
        public
        payable
        onlyOtherBridge  // 关键安全检查：只能由对侧链的桥接合约调用
    {
        // 检查合约未暂停
        require(paused() == false, "StandardBridge: paused");
        
        // 验证发送的 ETH 数量必须等于桥接数量
        // 这些 ETH 来自 CrossDomainMessenger，它从对侧链的桥接合约接收
        require(msg.value == _amount, "StandardBridge: amount sent does not match amount required");
        
        // 安全检查：不能发送到桥接合约自身（防止资金锁定）
        require(_to != address(this), "StandardBridge: cannot send to self");
        
        // 安全检查：不能发送到 messenger（防止资金锁定）
        require(_to != address(messenger), "StandardBridge: cannot send to messenger");

        // 发出桥接最终确认事件
        // 子合约可以重写此函数以发出传统事件
        _emitETHBridgeFinalized(_from, _to, _amount, _extraData);

        // 使用 SafeCall 执行 ETH 转账
        // SafeCall.call 确保即使目标合约回滚，也不会影响整个交易
        bool success = SafeCall.call(_to, gasleft(), _amount, hex"");
        require(success, "StandardBridge: ETH transfer failed");
    }

    /// @notice 在本链上最终确认 ERC20 桥接
    /// 
    /// 这是桥接流程的第二阶段（第一阶段在对侧链发起）。
    /// 只能由对侧链的 StandardBridge 合约通过跨链消息触发。
    /// 
    /// 代币处理逻辑：
    /// 1. **OptimismMintableERC20（远程链原生代币）**：
    ///    - 在对侧链被销毁，在本链铸造
    ///    - 验证代币对正确性
    ///    - 调用 mint() 铸造代币给接收者
    /// 
    /// 2. **本地链原生代币**：
    ///    - 在对侧链被锁定，在本链从 deposits 映射中扣除
    ///    - 从桥接合约转账给接收者
    /// 
    /// @param _localToken  本链上的 ERC20 代币地址
    /// @param _remoteToken 对侧链上对应的 ERC20 代币地址
    /// @param _from         发送者地址（在对侧链）
    /// @param _to           接收者地址（在本链）
    /// @param _amount       桥接的 ERC20 数量
    /// @param _extraData    额外数据，不会触发接收者，但会发出事件，可用于识别交易
    function finalizeBridgeERC20(
        address _localToken,
        address _remoteToken,
        address _from,
        address _to,
        uint256 _amount,
        bytes calldata _extraData
    )
        public
        onlyOtherBridge  // 关键安全检查：只能由对侧链的桥接合约调用
    {
        // 检查合约未暂停
        require(paused() == false, "StandardBridge: paused");
        
        // 判断代币类型并处理
        if (_isOptimismMintableERC20(_localToken)) {
            // 情况 1：OptimismMintableERC20（远程链原生代币）
            // 验证代币对正确性：本地代币的 remoteToken 必须等于传入的 _remoteToken
            require(
                _isCorrectTokenPair(_localToken, _remoteToken),
                "StandardBridge: wrong remote token for Optimism Mintable ERC20 local token"
            );

            // 在对侧链代币已被销毁，这里在本链铸造
            IOptimismMintableERC20(_localToken).mint(_to, _amount);
        } else {
            // 情况 2：本地链原生代币
            // 从 deposits 映射中扣除数量（这些代币在发起桥接时被锁定）
            deposits[_localToken][_remoteToken] = deposits[_localToken][_remoteToken] - _amount;
            
            // 从桥接合约转账给接收者
            IERC20(_localToken).safeTransfer(_to, _amount);
        }

        // 发出桥接最终确认事件
        // 子合约可以重写此函数以发出传统事件
        _emitERC20BridgeFinalized(_localToken, _remoteToken, _from, _to, _amount, _extraData);
    }

    /// @notice 通过 CrossDomainMessenger 发起 ETH 桥接
    /// 
    /// 这是桥接流程的第一阶段（内部函数）。
    /// 
    /// 流程：
    /// 1. 验证发送的 ETH 数量
    /// 2. 发出桥接发起事件
    /// 3. 通过 CrossDomainMessenger 发送消息到对侧链的桥接合约
    /// 4. 对侧链的桥接合约收到消息后调用 finalizeBridgeETH 完成桥接
    /// 
    /// 消息内容：
    /// - 目标：对侧链的桥接合约（otherBridge）
    /// - 函数：finalizeBridgeETH
    /// - 参数：from, to, amount, extraData
    /// - 附带 ETH：_amount（通过 { value: _amount } 发送）
    /// 
    /// @param _from        发送者地址
    /// @param _to          接收者地址（在对侧链）
    /// @param _amount      桥接的 ETH 数量
    /// @param _minGasLimit 桥接可以中继的最小 gas 数量
    /// @param _extraData   额外数据，不会触发接收者，但会发出事件，可用于识别交易
    function _initiateBridgeETH(
        address _from,
        address _to,
        uint256 _amount,
        uint32 _minGasLimit,
        bytes memory _extraData
    )
        internal
    {
        // 验证发送的 ETH 数量必须等于桥接数量
        require(msg.value == _amount, "StandardBridge: bridging ETH must include sufficient ETH value");

        // 发出桥接发起事件
        // 子合约可以重写此函数以发出传统事件
        _emitETHBridgeInitiated(_from, _to, _amount, _extraData);

        // 通过 CrossDomainMessenger 发送消息到对侧链
        // 消息包含调用 finalizeBridgeETH 的编码数据
        // ETH 通过 { value: _amount } 附带在消息中
        messenger.sendMessage{ value: _amount }({
            _target: address(otherBridge),  // 对侧链的桥接合约
            _message: abi.encodeWithSelector(
                this.finalizeBridgeETH.selector,  // 函数选择器
                _from, 
                _to, 
                _amount, 
                _extraData
            ),
            _minGasLimit: _minGasLimit
        });
    }

    /// @notice 将对侧链的接收者地址发送 ERC20 代币
    /// 
    /// 这是桥接流程的第一阶段（内部函数）。
    /// 
    /// 代币处理逻辑：
    /// 1. **OptimismMintableERC20（远程链原生代币）**：
    ///    - 验证代币对正确性
    ///    - 在本链销毁代币（burn）
    ///    - 在对侧链最终确认时会铸造
    /// 
    /// 2. **本地链原生代币**：
    ///    - 从用户转账到桥接合约（锁定）
    ///    - 更新 deposits 映射
    ///    - 在对侧链最终确认时会从 deposits 扣除并转账
    /// 
    /// 消息发送：
    /// - 注意：代币地址顺序在消息中被反转
    /// - 因为消息在对侧链执行，对侧链的 localToken 是本链的 remoteToken
    /// 
    /// @param _localToken  本链上的 ERC20 代币地址
    /// @param _remoteToken 对侧链上对应的 ERC20 代币地址
    /// @param _from        发送者地址
    /// @param _to          接收者地址（在对侧链）
    /// @param _amount      要桥接的本地代币数量
    /// @param _minGasLimit 桥接可以中继的最小 gas 数量
    /// @param _extraData   额外数据，不会触发接收者，但会发出事件，可用于识别交易
    function _initiateBridgeERC20(
        address _localToken,
        address _remoteToken,
        address _from,
        address _to,
        uint256 _amount,
        uint32 _minGasLimit,
        bytes memory _extraData
    )
        internal
    {
        // 验证不能同时发送 ETH（ERC20 桥接不涉及 ETH）
        require(msg.value == 0, "StandardBridge: cannot send value");

        // 判断代币类型并处理
        if (_isOptimismMintableERC20(_localToken)) {
            // 情况 1：OptimismMintableERC20（远程链原生代币）
            // 验证代币对正确性
            require(
                _isCorrectTokenPair(_localToken, _remoteToken),
                "StandardBridge: wrong remote token for Optimism Mintable ERC20 local token"
            );

            // 在本链销毁代币（在对侧链最终确认时会铸造）
            IOptimismMintableERC20(_localToken).burn(_from, _amount);
        } else {
            // 情况 2：本地链原生代币
            // 从用户转账到桥接合约（锁定代币）
            IERC20(_localToken).safeTransferFrom(_from, address(this), _amount);
            
            // 更新存款映射，记录锁定的代币数量
            deposits[_localToken][_remoteToken] = deposits[_localToken][_remoteToken] + _amount;
        }

        // 发出桥接发起事件
        // 子合约可以重写此函数以发出传统事件
        _emitERC20BridgeInitiated(_localToken, _remoteToken, _from, _to, _amount, _extraData);

        // 通过 CrossDomainMessenger 发送消息到对侧链
        // 注意：代币地址顺序被反转
        // 因为消息在对侧链执行，对侧链的 localToken 是本链的 remoteToken，反之亦然
        messenger.sendMessage({
            _target: address(otherBridge),  // 对侧链的桥接合约
            _message: abi.encodeWithSelector(
                this.finalizeBridgeERC20.selector,
                // 地址顺序反转：因为在对侧链执行，对侧链的 localToken 是本链的 remoteToken
                _remoteToken,  // 在对侧链这是 localToken
                _localToken,   // 在对侧链这是 remoteToken
                _from,
                _to,
                _amount,
                _extraData
            ),
            _minGasLimit: _minGasLimit
        });
    }

    /// @notice 检查给定地址是否是 OptimismMintableERC20
    /// 
    /// 使用 ERC165 接口检查来识别代币类型。
    /// 支持两种类型：
    /// - ILegacyMintableERC20：传统可铸造 ERC20（向后兼容）
    /// - IOptimismMintableERC20：Optimism 可铸造 ERC20
    /// 
    /// @param _token 要检查的代币地址
    /// @return 如果代币是 OptimismMintableERC20 返回 true
    function _isOptimismMintableERC20(address _token) internal view returns (bool) {
        return ERC165Checker.supportsInterface(_token, type(ILegacyMintableERC20).interfaceId)
            || ERC165Checker.supportsInterface(_token, type(IOptimismMintableERC20).interfaceId);
    }

    /// @notice 检查"另一个代币"是否是 OptimismMintableERC20 的正确配对代币
    /// 
    /// OptimismMintableERC20 代币有对应的配对代币：
    /// - LegacyMintableERC20：使用 l1Token() 获取配对代币
    /// - OptimismMintableERC20：使用 remoteToken() 获取配对代币
    /// 
    /// 这个检查确保桥接时使用正确的代币对，防止错误配对。
    /// 
    /// @param _mintableToken 要检查的 OptimismMintableERC20 代币
    /// @param _otherToken     要检查的配对代币
    /// @return 如果配对代币正确返回 true
    function _isCorrectTokenPair(address _mintableToken, address _otherToken) internal view returns (bool) {
        // 检查是否是传统可铸造 ERC20
        if (ERC165Checker.supportsInterface(_mintableToken, type(ILegacyMintableERC20).interfaceId)) {
            // 传统代币使用 l1Token() 获取配对代币
            return _otherToken == ILegacyMintableERC20(_mintableToken).l1Token();
        } else {
            // Optimism 可铸造 ERC20 使用 remoteToken() 获取配对代币
            return _otherToken == IOptimismMintableERC20(_mintableToken).remoteToken();
        }
    }

    /// @notice Emits the ETHBridgeInitiated event and if necessary the appropriate legacy event
    ///         when an ETH bridge is finalized on this chain.
    /// @param _from      Address of the sender.
    /// @param _to        Address of the receiver.
    /// @param _amount    Amount of ETH sent.
    /// @param _extraData Extra data sent with the transaction.
    function _emitETHBridgeInitiated(
        address _from,
        address _to,
        uint256 _amount,
        bytes memory _extraData
    )
        internal
        virtual
    {
        emit ETHBridgeInitiated(_from, _to, _amount, _extraData);
    }

    /// @notice Emits the ETHBridgeFinalized and if necessary the appropriate legacy event when an
    ///         ETH bridge is finalized on this chain.
    /// @param _from      Address of the sender.
    /// @param _to        Address of the receiver.
    /// @param _amount    Amount of ETH sent.
    /// @param _extraData Extra data sent with the transaction.
    function _emitETHBridgeFinalized(
        address _from,
        address _to,
        uint256 _amount,
        bytes memory _extraData
    )
        internal
        virtual
    {
        emit ETHBridgeFinalized(_from, _to, _amount, _extraData);
    }

    /// @notice Emits the ERC20BridgeInitiated event and if necessary the appropriate legacy
    ///         event when an ERC20 bridge is initiated to the other chain.
    /// @param _localToken  Address of the ERC20 on this chain.
    /// @param _remoteToken Address of the ERC20 on the remote chain.
    /// @param _from        Address of the sender.
    /// @param _to          Address of the receiver.
    /// @param _amount      Amount of the ERC20 sent.
    /// @param _extraData   Extra data sent with the transaction.
    function _emitERC20BridgeInitiated(
        address _localToken,
        address _remoteToken,
        address _from,
        address _to,
        uint256 _amount,
        bytes memory _extraData
    )
        internal
        virtual
    {
        emit ERC20BridgeInitiated(_localToken, _remoteToken, _from, _to, _amount, _extraData);
    }

    /// @notice Emits the ERC20BridgeFinalized event and if necessary the appropriate legacy
    ///         event when an ERC20 bridge is initiated to the other chain.
    /// @param _localToken  Address of the ERC20 on this chain.
    /// @param _remoteToken Address of the ERC20 on the remote chain.
    /// @param _from        Address of the sender.
    /// @param _to          Address of the receiver.
    /// @param _amount      Amount of the ERC20 sent.
    /// @param _extraData   Extra data sent with the transaction.
    function _emitERC20BridgeFinalized(
        address _localToken,
        address _remoteToken,
        address _from,
        address _to,
        uint256 _amount,
        bytes memory _extraData
    )
        internal
        virtual
    {
        emit ERC20BridgeFinalized(_localToken, _remoteToken, _from, _to, _amount, _extraData);
    }
}
