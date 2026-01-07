// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

// Libraries
import { Initializable } from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import { Math } from "@openzeppelin/contracts/utils/math/Math.sol";
import { SafeCall } from "src/libraries/SafeCall.sol";
import { Hashing } from "src/libraries/Hashing.sol";
import { Encoding } from "src/libraries/Encoding.sol";
import { Constants } from "src/libraries/Constants.sol";

/// @custom:legacy
/// @title CrossDomainMessengerLegacySpacer0
/// @notice Contract only exists to add a spacer to the CrossDomainMessenger where the
///         libAddressManager variable used to exist. Must be the first contract in the inheritance
///         tree of the CrossDomainMessenger.
contract CrossDomainMessengerLegacySpacer0 {
    /// @custom:legacy
    /// @custom:spacer libAddressManager
    /// @notice Spacer for backwards compatibility.
    address private spacer_0_0_20;
}

/// @custom:legacy
/// @title CrossDomainMessengerLegacySpacer1
/// @notice Contract only exists to add a spacer to the CrossDomainMessenger where the
///         PausableUpgradable and OwnableUpgradeable variables used to exist. Must be
///         the third contract in the inheritance tree of the CrossDomainMessenger.
contract CrossDomainMessengerLegacySpacer1 {
    /// @custom:legacy
    /// @custom:spacer ContextUpgradable's __gap
    /// @notice Spacer for backwards compatibility. Comes from OpenZeppelin
    ///         ContextUpgradable.
    uint256[50] private spacer_1_0_1600;

    /// @custom:legacy
    /// @custom:spacer OwnableUpgradeable's _owner
    /// @notice Spacer for backwards compatibility.
    ///         Come from OpenZeppelin OwnableUpgradeable.
    address private spacer_51_0_20;

    /// @custom:legacy
    /// @custom:spacer OwnableUpgradeable's __gap
    /// @notice Spacer for backwards compatibility. Comes from OpenZeppelin
    ///         OwnableUpgradeable.
    uint256[49] private spacer_52_0_1568;

    /// @custom:legacy
    /// @custom:spacer PausableUpgradable's _paused
    /// @notice Spacer for backwards compatibility. Comes from OpenZeppelin
    ///         PausableUpgradable.
    bool private spacer_101_0_1;

    /// @custom:legacy
    /// @custom:spacer PausableUpgradable's __gap
    /// @notice Spacer for backwards compatibility. Comes from OpenZeppelin
    ///         PausableUpgradable.
    uint256[49] private spacer_102_0_1568;

    /// @custom:legacy
    /// @custom:spacer ReentrancyGuardUpgradeable's `_status` field.
    /// @notice Spacer for backwards compatibility.
    uint256 private spacer_151_0_32;

    /// @custom:legacy
    /// @custom:spacer ReentrancyGuardUpgradeable's __gap
    /// @notice Spacer for backwards compatibility.
    uint256[49] private spacer_152_0_1568;

    /// @custom:legacy
    /// @custom:spacer blockedMessages
    /// @notice Spacer for backwards compatibility.
    mapping(bytes32 => bool) private spacer_201_0_32;

    /// @custom:legacy
    /// @custom:spacer relayedMessages
    /// @notice Spacer for backwards compatibility.
    mapping(bytes32 => bool) private spacer_202_0_32;
}

/// @custom:upgradeable
/// @title CrossDomainMessenger
/// @notice CrossDomainMessenger 是 L1 和 L2 跨链消息传递合约的基类，提供核心的消息传递逻辑。
/// 
/// 核心功能：
/// 1. **发送消息（sendMessage）**：向对侧链发送消息
///    - 消息包含目标地址、消息数据、最小 gas 限制
///    - 可以附带 ETH 值
///    - 消息通过底层机制（如 OptimismPortal）传递到对侧链
/// 
/// 2. **中继消息（relayMessage）**：在对侧链上执行收到的消息
///    - 验证消息来源和完整性
///    - 检查重放保护
///    - 执行目标合约调用
///    - 处理成功/失败状态
/// 
/// 安全机制：
/// - 消息哈希验证：防止消息被篡改
/// - 重放保护：使用 successfulMessages 映射防止重复执行
/// - 失败消息跟踪：使用 failedMessages 映射允许重放失败的消息
/// - Gas 检查：确保有足够的 gas 执行目标调用
/// - 重入保护：使用 xDomainMsgSender 防止重入
/// 
/// 设计限制：
/// - 目前只支持两个配对链之间的消息传递
/// - 不支持一对多的交互
/// 
/// 重要：对此合约的任何更改都必须导致继承合约的 semver 版本号增加。
abstract contract CrossDomainMessenger is
    CrossDomainMessengerLegacySpacer0,
    Initializable,
    CrossDomainMessengerLegacySpacer1
{
    /// @notice Current message version identifier.
    uint16 public constant MESSAGE_VERSION = 1;

    /// @notice Constant overhead added to the base gas for a message.
    uint64 public constant RELAY_CONSTANT_OVERHEAD = 200_000;

    /// @notice Numerator for dynamic overhead added to the base gas for a message.
    uint64 public constant MIN_GAS_DYNAMIC_OVERHEAD_NUMERATOR = 64;

    /// @notice Denominator for dynamic overhead added to the base gas for a message.
    uint64 public constant MIN_GAS_DYNAMIC_OVERHEAD_DENOMINATOR = 63;

    /// @notice Extra gas added to base gas for each byte of calldata in a message.
    uint64 public constant MIN_GAS_CALLDATA_OVERHEAD = 16;

    /// @notice Gas reserved for performing the external call in `relayMessage`.
    uint64 public constant RELAY_CALL_OVERHEAD = 40_000;

    /// @notice Gas reserved for finalizing the execution of `relayMessage` after the safe call.
    uint64 public constant RELAY_RESERVED_GAS = 40_000;

    /// @notice Gas reserved for the execution between the `hasMinGas` check and the external
    ///         call in `relayMessage`.
    uint64 public constant RELAY_GAS_CHECK_BUFFER = 5_000;

    /// @notice Base gas required for any transaction in the EVM.
    uint64 public constant TX_BASE_GAS = 21_000;

    /// @notice Floor overhead per byte of non-zero calldata in a message. Calldata floor was
    ///         introduced in EIP-7623.
    uint64 public constant FLOOR_CALLDATA_OVERHEAD = 40;

    /// @notice Overhead added to the internal message data when the full call to relayMessage is
    ///         ABI encoded. This is a constant value that is specific to the V1 message encoding
    ///         scheme. 260 is an upper bound, actual overhead can be as low as 228 bytes for an
    ///         empty message.
    uint64 public constant ENCODING_OVERHEAD = 260;

    /// @notice 消息哈希到布尔值的映射，用于重放保护
    /// 
    /// 用途：
    /// - 记录已成功中继的消息哈希
    /// - 防止消息被重复执行（重放攻击）
    /// 
    /// 注意：只有成功中继的消息才会出现在此映射中，因此不能再次中继。
    mapping(bytes32 => bool) public successfulMessages;

    /// @notice 当前正在执行的消息在对侧链上的发送者地址
    /// 
    /// 用途：
    /// - 在消息中继期间，存储对侧链的发送者地址
    /// - 允许被调用的合约知道是谁在对侧链触发了调用
    /// - 作为重入保护机制（如果值不是默认值，说明正在处理消息）
    /// 
    /// 默认值：Constants.DEFAULT_L2_SENDER（0x00000000...dead）
    /// 如果值等于默认值，说明当前没有消息正在执行。
    /// 使用 xDomainMessageSender getter 函数，如果值未设置会抛出错误。
    address internal xDomainMsgSender;

    /// @notice Nonce for the next message to be sent, without the message version applied. Use the
    ///         messageNonce getter which will insert the message version into the nonce to give you
    ///         the actual nonce to be used for the message.
    uint240 internal msgNonce;

    /// @notice 消息哈希到布尔值的映射，记录失败的消息
    /// 
    /// 用途：
    /// - 记录至少执行失败一次的消息哈希
    /// - 允许失败的消息被重放（通过手动调用 relayMessage）
    /// - 如果消息第一次执行就成功，不会出现在此映射中
    /// 
    /// 失败原因可能包括：
    /// - Gas 不足
    /// - 目标合约调用失败
    /// - 重入检测
    mapping(bytes32 => bool) public failedMessages;

    /// @notice CrossDomainMessenger contract on the other chain.
    /// @custom:network-specific
    CrossDomainMessenger public otherMessenger;

    /// @notice Reserve extra slots in the storage layout for future upgrades.
    ///         A gap size of 43 was chosen here, so that the first slot used in a child contract
    ///         would be 1 plus a multiple of 50.
    uint256[43] private __gap;

    /// @notice Emitted whenever a message is sent to the other chain.
    /// @param target       Address of the recipient of the message.
    /// @param sender       Address of the sender of the message.
    /// @param message      Message to trigger the recipient address with.
    /// @param messageNonce Unique nonce attached to the message.
    /// @param gasLimit     Minimum gas limit that the message can be executed with.
    event SentMessage(address indexed target, address sender, bytes message, uint256 messageNonce, uint256 gasLimit);

    /// @notice Additional event data to emit, required as of Bedrock. Cannot be merged with the
    ///         SentMessage event without breaking the ABI of this contract, this is good enough.
    /// @param sender Address of the sender of the message.
    /// @param value  ETH value sent along with the message to the recipient.
    event SentMessageExtension1(address indexed sender, uint256 value);

    /// @notice Emitted whenever a message is successfully relayed on this chain.
    /// @param msgHash Hash of the message that was relayed.
    event RelayedMessage(bytes32 indexed msgHash);

    /// @notice Emitted whenever a message fails to be relayed on this chain.
    /// @param msgHash Hash of the message that failed to be relayed.
    event FailedRelayedMessage(bytes32 indexed msgHash);

    /// @notice 向对侧链的某个目标地址发送消息
    /// 
    /// 这是跨链消息传递的第一阶段。消息会被编码并发送到对侧链的 CrossDomainMessenger。
    /// 
    /// 重要警告：
    /// - 如果目标合约的调用总是回滚，消息将无法中继，发送的 ETH 将永久锁定
    /// - 如果对侧链的目标地址被认为不安全（见 _isUnsafeTarget()），也会发生同样的情况
    /// 
    /// Gas 计算：
    /// - 提供给消息的 gas = 用户请求的 gas + 基础 gas 值
    /// - 这保证了目标合约调用始终至少有用户指定的最小 gas 限制
    /// 
    /// 消息编码：
    /// - 消息被编码为调用 relayMessage 的格式
    /// - 包含：nonce、sender、target、value、minGasLimit、message
    /// 
    /// @param _target      目标合约或钱包地址（在对侧链）
    /// @param _message     触发目标地址的消息数据
    /// @param _minGasLimit 消息可以执行的最小 gas 限制
    function sendMessage(address _target, bytes calldata _message, uint32 _minGasLimit) external payable {
        // 触发发送消息到对侧链的 messenger
        // 注意：提供给消息的 gas = 用户请求的 gas + 基础 gas 值
        // 这保证了目标合约调用始终至少有用户指定的最小 gas 限制
        _sendMessage({
            _to: address(otherMessenger),  // 对侧链的 CrossDomainMessenger
            _gasLimit: baseGas(_message, _minGasLimit),  // 计算总 gas（用户 gas + 基础 gas）
            _value: msg.value,  // 附带的 ETH 值
            _data: abi.encodeWithSelector(
                this.relayMessage.selector,  // 对侧链将调用 relayMessage
                messageNonce(),              // 消息 nonce
                msg.sender,                  // 发送者地址
                _target,                     // 目标地址
                msg.value,                   // ETH 值
                _minGasLimit,                // 最小 gas 限制
                _message                     // 消息数据
            )
        });

        // 发出消息发送事件
        emit SentMessage(_target, msg.sender, _message, messageNonce(), _minGasLimit);
        emit SentMessageExtension1(msg.sender, msg.value);

        // 增加 nonce（用于下一个消息）
        unchecked {
            ++msgNonce;
        }
    }

    /// @notice 中继由对侧链 CrossDomainMessenger 发送的消息
    /// 
    /// 这是跨链消息传递的第二阶段。在对侧链上执行收到的消息。
    /// 
    /// 执行条件：
    /// 1. 首次中继：只能通过对侧链 messenger 的跨链调用执行
    /// 2. 重放：如果消息之前失败，可以手动重放
    /// 
    /// 验证流程：
    /// 1. 检查合约未暂停
    /// 2. 验证消息版本（支持版本 0 和 1）
    /// 3. 版本 0 消息：检查传统消息哈希未被中继
    /// 4. 计算版本化消息哈希（v1 哈希包含 value 和 minGasLimit）
    /// 5. 验证消息来源和重放状态
    /// 6. 检查目标地址安全
    /// 7. 检查消息未被成功中继过
    /// 
    /// @param _nonce       正在中继的消息的 nonce
    /// @param _sender      发送消息的用户地址（在对侧链）
    /// @param _target      消息的目标地址（在本链）
    /// @param _value       随消息发送的 ETH 值
    /// @param _minGasLimit 消息可以执行的最小 gas 数量
    /// @param _message     发送给目标的消息数据
    function relayMessage(
        uint256 _nonce,
        address _sender,
        address _target,
        uint256 _value,
        uint256 _minGasLimit,
        bytes calldata _message
    )
        external
        payable
    {
        // 检查合约未暂停
        // 在 L1 上，此函数会检查 Portal 的暂停状态
        // 在 L2 上，这应该是一个空操作，因为 paused 总是返回 false
        require(paused() == false, "CrossDomainMessenger: paused");

        // 解码 nonce 获取消息版本
        (, uint16 version) = Encoding.decodeVersionedNonce(_nonce);
        require(version < 2, "CrossDomainMessenger: only version 0 or 1 messages are supported at this time");

        // 如果消息是版本 0，这是迁移的传统提款
        // 需要检查传统版本的消息未被中继过
        if (version == 0) {
            bytes32 oldHash = Hashing.hashCrossDomainMessageV0(_target, _sender, _message, _nonce);
            require(successfulMessages[oldHash] == false, "CrossDomainMessenger: legacy withdrawal already relayed");
        }

        // 使用 v1 消息哈希作为消息的唯一标识符
        // v1 哈希包含 value 和 minGasLimit，提供更强的承诺
        bytes32 versionedHash =
            Hashing.hashCrossDomainMessageV1(_nonce, _sender, _target, _value, _minGasLimit, _message);

        // 验证消息来源和重放状态
        if (_isOtherMessenger()) {
            // 首次提交消息时（非重放），这些属性应该始终成立
            assert(msg.value == _value);  // ETH 值必须匹配
            assert(!failedMessages[versionedHash]);  // 消息不应该已经失败
        } else {
            // 重放失败的消息时
            require(msg.value == 0, "CrossDomainMessenger: value must be zero unless message is from a system address");
            require(failedMessages[versionedHash], "CrossDomainMessenger: message cannot be replayed");
        }

        // 检查目标地址不是被阻止的系统地址
        require(
            _isUnsafeTarget(_target) == false, "CrossDomainMessenger: cannot send message to blocked system address"
        );

        // 检查消息未被成功中继过（重放保护）
        require(successfulMessages[versionedHash] == false, "CrossDomainMessenger: message has already been relayed");

        // Gas 检查和重入保护
        // 如果没有足够的 gas 执行外部调用并完成执行，提前返回并将消息标记为失败
        // 
        // 我们需要确保有足够的 gas 来：
        // 1. 调用目标合约（_minGasLimit + RELAY_CALL_OVERHEAD + RELAY_GAS_CHECK_BUFFER）
        //    - RELAY_CALL_OVERHEAD 包含在 `hasMinGas` 中
        // 2. 在外部调用后完成执行（RELAY_RESERVED_GAS）
        //
        // 如果 `xDomainMsgSender` 不是默认的 L2 发送者，说明此函数正在被重入
        // 这会将消息标记为失败，允许稍后重放
        if (
            !SafeCall.hasMinGas(_minGasLimit, RELAY_RESERVED_GAS + RELAY_GAS_CHECK_BUFFER)
                || xDomainMsgSender != Constants.DEFAULT_L2_SENDER
        ) {
            // 标记消息为失败
            failedMessages[versionedHash] = true;
            emit FailedRelayedMessage(versionedHash);

            // 如果交易由估算地址触发，回滚
            // 这应该只在 gas 估算期间可能，或者我们有更大的问题
            // 回滚将使 gas 估算行为改变，使得计算的 gas 限制是中继消息所需的数量，
            // 即使该数量大于用户指定的最小 gas 限制
            if (tx.origin == Constants.ESTIMATION_ADDRESS) {
                revert("CrossDomainMessenger: failed to relay message");
            }

            return;
        }

        // 设置跨域消息发送者（允许被调用的合约知道是谁在对侧链触发了调用）
        xDomainMsgSender = _sender;
        
        // 执行目标合约调用
        // 使用 SafeCall.call 确保即使目标合约回滚，也不会影响整个交易
        // 保留 RELAY_RESERVED_GAS 用于后续执行
        bool success = SafeCall.call(_target, gasleft() - RELAY_RESERVED_GAS, _value, _message);
        
        // 重置跨域消息发送者（重入保护）
        xDomainMsgSender = Constants.DEFAULT_L2_SENDER;

        // 处理调用结果
        if (success) {
            // 再次检查消息未被成功中继（与上面的检查相同）
            // 这确保同一消息不能被中继两次，并增加一层重入保护
            assert(successfulMessages[versionedHash] == false);
            
            // 标记消息为成功中继
            successfulMessages[versionedHash] = true;
            emit RelayedMessage(versionedHash);
        } else {
            // 调用失败，标记消息为失败（允许稍后重放）
            failedMessages[versionedHash] = true;
            emit FailedRelayedMessage(versionedHash);

            // 如果交易由估算地址触发，回滚
            if (tx.origin == Constants.ESTIMATION_ADDRESS) {
                revert("CrossDomainMessenger: failed to relay message");
            }
        }
    }

    /// @notice 获取在对侧链上发起当前正在执行的消息的合约或钱包地址
    /// 
    /// 用途：
    /// - 允许消息接收者查看是谁在对侧链触发了调用
    /// - 用于权限检查和访问控制
    /// 
    /// 如果当前没有消息正在执行，将抛出错误。
    /// 
    /// @return 在对侧链上发送当前正在执行的消息的地址
    function xDomainMessageSender() external view returns (address) {
        // 如果 xDomainMsgSender 是默认值，说明没有消息正在执行
        require(
            xDomainMsgSender != Constants.DEFAULT_L2_SENDER, "CrossDomainMessenger: xDomainMessageSender is not set"
        );

        return xDomainMsgSender;
    }

    /// @notice Retrieves the address of the paired CrossDomainMessenger contract on the other chain
    ///         Public getter is legacy and will be removed in the future. Use `otherMessenger()` instead.
    /// @return CrossDomainMessenger contract on the other chain.
    /// @custom:legacy
    function OTHER_MESSENGER() public view returns (CrossDomainMessenger) {
        return otherMessenger;
    }

    /// @notice Retrieves the next message nonce. Message version will be added to the upper two
    ///         bytes of the message nonce. Message version allows us to treat messages as having
    ///         different structures.
    /// @return Nonce of the next message to be sent, with added message version.
    function messageNonce() public view returns (uint256) {
        return Encoding.encodeVersionedNonce(msgNonce, MESSAGE_VERSION);
    }

    /// @notice Computes the amount of gas required to guarantee that a given message will be
    ///         received on the other chain without running out of gas. Guaranteeing that a message
    ///         will not run out of gas is important because this ensures that a message can always
    ///         be replayed on the other chain if it fails to execute completely.
    /// @param _message     Message to compute the amount of required gas for.
    /// @param _minGasLimit Minimum desired gas limit when message goes to target.
    /// @return Amount of gas required to guarantee message receipt.
    function baseGas(bytes memory _message, uint32 _minGasLimit) public pure returns (uint64) {
        // Base gas should really be computed on the fully encoded message but that would break the
        // expected API, so we instead just add the encoding overhead to the message length inside
        // of this function.

        // We need a minimum amount of execution gas to ensure that the message will be received on
        // the other side without running out of gas (stored within the failedMessages mapping).
        // If we get beyond the hasMinGas check, then we *must* supply more than minGasLimit to
        // the external call.
        uint64 executionGas = uint64(
            // Constant costs for relayMessage
            RELAY_CONSTANT_OVERHEAD
            // Covers dynamic parts of the CALL opcode
            + RELAY_CALL_OVERHEAD
            // Ensures execution of relayMessage completes after call
            + RELAY_RESERVED_GAS
            // Buffer between hasMinGas check and the CALL
            + RELAY_GAS_CHECK_BUFFER
            // Minimum gas limit, multiplied by 64/63 to account for EIP-150.
            + ((_minGasLimit * MIN_GAS_DYNAMIC_OVERHEAD_NUMERATOR) / MIN_GAS_DYNAMIC_OVERHEAD_DENOMINATOR)
        );

        // Total message size is the result of properly ABI encoding the call to relayMessage.
        // Since we only get the message data and not the rest of the calldata, we use the
        // ENCODING_OVERHEAD constant to conservatively account for the remaining bytes.
        uint64 totalMessageSize = uint64(_message.length + ENCODING_OVERHEAD);

        // Finally, replicate the transaction cost formula as defined after EIP-7623. This is
        // mostly relevant in the L1 -> L2 case because we need to be able to cover the intrinsic
        // cost of the message but it doesn't hurt in the L2 -> L1 case. After EIP-7623, the cost
        // of a transaction is floored by its calldata size. We don't need to account for the
        // contract creation case because this is always a call to relayMessage.
        return TX_BASE_GAS
            + uint64(
                Math.max(
                    executionGas + (totalMessageSize * MIN_GAS_CALLDATA_OVERHEAD),
                    (totalMessageSize * FLOOR_CALLDATA_OVERHEAD)
                )
            );
    }

    /// @notice Initializer.
    /// @param _otherMessenger CrossDomainMessenger contract on the other chain.
    function __CrossDomainMessenger_init(CrossDomainMessenger _otherMessenger) internal onlyInitializing {
        // We only want to set the xDomainMsgSender to the default value if it hasn't been initialized yet,
        // meaning that this is a fresh contract deployment.
        // This prevents resetting the xDomainMsgSender to the default value during an upgrade, which would enable
        // a reentrant withdrawal to sandwhich the upgrade replay a withdrawal twice.
        if (xDomainMsgSender == address(0)) {
            xDomainMsgSender = Constants.DEFAULT_L2_SENDER;
        }
        otherMessenger = _otherMessenger;
    }

    /// @notice Sends a low-level message to the other messenger. Needs to be implemented by child
    ///         contracts because the logic for this depends on the network where the messenger is
    ///         being deployed.
    /// @param _to       Recipient of the message on the other chain.
    /// @param _gasLimit Minimum gas limit the message can be executed with.
    /// @param _value    Amount of ETH to send with the message.
    /// @param _data     Message data.
    function _sendMessage(address _to, uint64 _gasLimit, uint256 _value, bytes memory _data) internal virtual;

    /// @notice Checks whether the message is coming from the other messenger. Implemented by child
    ///         contracts because the logic for this depends on the network where the messenger is
    ///         being deployed.
    /// @return Whether the message is coming from the other messenger.
    function _isOtherMessenger() internal view virtual returns (bool);

    /// @notice Checks whether a given call target is a system address that could cause the
    ///         messenger to peform an unsafe action. This is NOT a mechanism for blocking user
    ///         addresses. This is ONLY used to prevent the execution of messages to specific
    ///         system addresses that could cause security issues, e.g., having the
    ///         CrossDomainMessenger send messages to itself.
    /// @param _target Address of the contract to check.
    /// @return Whether or not the address is an unsafe system address.
    function _isUnsafeTarget(address _target) internal view virtual returns (bool);

    /// @notice This function should return true if the contract is paused.
    ///         On L1 this function will check the SuperchainConfig for its paused status.
    ///         On L2 this function should be a no-op.
    /// @return Whether or not the contract is paused.
    function paused() public view virtual returns (bool) {
        return false;
    }
}
