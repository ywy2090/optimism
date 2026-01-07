// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

// Contracts
import { ProxyAdminOwnedBase } from "src/L1/ProxyAdminOwnedBase.sol";
import { Initializable } from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import { ResourceMetering } from "src/L1/ResourceMetering.sol";
import { ReinitializableBase } from "src/universal/ReinitializableBase.sol";

// Libraries
import { EOA } from "src/libraries/EOA.sol";
import { SafeCall } from "src/libraries/SafeCall.sol";
import { Constants } from "src/libraries/Constants.sol";
import { Types } from "src/libraries/Types.sol";
import { Hashing } from "src/libraries/Hashing.sol";
import { SecureMerkleTrie } from "src/libraries/trie/SecureMerkleTrie.sol";
import { AddressAliasHelper } from "src/vendor/AddressAliasHelper.sol";
import { GameStatus, GameType } from "src/dispute/lib/Types.sol";
import { Features } from "src/libraries/Features.sol";

// Interfaces
import { ISemver } from "interfaces/universal/ISemver.sol";
import { ISystemConfig } from "interfaces/L1/ISystemConfig.sol";
import { IResourceMetering } from "interfaces/L1/IResourceMetering.sol";
import { IDisputeGameFactory } from "interfaces/dispute/IDisputeGameFactory.sol";
import { IDisputeGame } from "interfaces/dispute/IDisputeGame.sol";
import { IAnchorStateRegistry } from "interfaces/dispute/IAnchorStateRegistry.sol";
import { IETHLockbox } from "interfaces/L1/IETHLockbox.sol";
import { ISuperchainConfig } from "interfaces/L1/ISuperchainConfig.sol";

/// @custom:proxied true
/// @title OptimismPortal2
/// @notice OptimismPortal2 是 Optimism Bedrock 的核心合约，负责处理 L1 和 L2 之间的消息传递。
///         这是 L1 上的入口合约，处理两个主要功能：
///         1. 存款（Deposit）：从 L1 向 L2 发送交易和 ETH
///         2. 提款（Withdrawal）：从 L2 向 L1 提款，需要经过证明和最终确认两个阶段
///         
///         安全机制：
///         - 提款需要基于有效的 DisputeGame 进行证明
///         - 证明后需要等待成熟期（PROOF_MATURITY_DELAY_SECONDS）才能最终确认
///         - 使用重入保护（l2Sender）防止重入攻击
///         
///         注意：直接调用 OptimismPortal 的消息没有重放保护，建议使用 L1CrossDomainMessenger 作为高级接口。
contract OptimismPortal2 is Initializable, ResourceMetering, ReinitializableBase, ProxyAdminOwnedBase, ISemver {
    /// @notice 表示一个已证明的提款
    /// @custom:field disputeGameProxy 提款所基于的争议游戏代理合约地址
    /// @custom:field timestamp          提款被证明时的时间戳
    /// 
    /// 这个结构体用于记录提款的证明信息。每个提款哈希可以对应多个证明者，
    /// 这样可以防止恶意用户通过提交无效证明来阻止其他用户的提款。
    struct ProvenWithdrawal {
        IDisputeGame disputeGameProxy;  // 争议游戏合约，用于验证状态根的有效性
        uint64 timestamp;               // 证明时间戳，用于计算成熟期
    }

    /// @notice 提款证明成熟期延迟（秒）
    /// 
    /// 这是一个安全机制：提款在被证明后，必须等待这个时间才能最终确认。
    /// 这样可以给挑战者足够的时间来质疑无效的证明，防止恶意提款。
    /// 通常设置为 7 天（604800 秒）。
    uint256 internal immutable PROOF_MATURITY_DELAY_SECONDS;

    /// @notice Version of the deposit event.
    uint256 internal constant DEPOSIT_VERSION = 0;

    /// @notice The L2 gas limit set when eth is deposited using the receive() function.
    uint64 internal constant RECEIVE_DEFAULT_GAS_LIMIT = 100_000;

    /// @notice Address of the L2 account which initiated a withdrawal in this transaction.
    ///         If the value of this variable is the default L2 sender address, then we are NOT
    ///         inside of a call to finalizeWithdrawalTransaction.
    address public l2Sender;

    /// @notice A list of withdrawal hashes which have been successfully finalized.
    mapping(bytes32 => bool) public finalizedWithdrawals;

    /// @custom:legacy
    /// @custom:spacer provenWithdrawals
    /// @notice Spacer taking up the legacy `provenWithdrawals` mapping slot.
    bytes32 private spacer_52_0_32;

    /// @custom:legacy
    /// @custom:spacer paused
    /// @notice Spacer for backwards compatibility.
    bool private spacer_53_0_1;

    /// @custom:legacy
    /// @custom:spacer superchainConfig
    /// @notice Spacer for backwards compatibility.
    address private spacer_53_1_20;

    /// @custom:legacy
    /// @custom:spacer l2Oracle
    /// @notice Spacer taking up the legacy `l2Oracle` address slot.
    address private spacer_54_0_20;

    /// @notice Address of the SystemConfig contract.
    /// @custom:network-specific
    ISystemConfig public systemConfig;

    /// @custom:network-specific
    /// @custom:legacy
    /// @custom:spacer disputeGameFactory
    /// @notice Spacer taking up the legacy `disputeGameFactory` address slot.
    address private spacer_56_0_20;

    /// @notice A mapping of withdrawal hashes to proof submitters to ProvenWithdrawal data.
    mapping(bytes32 => mapping(address => ProvenWithdrawal)) public provenWithdrawals;

    /// @custom:legacy
    /// @custom:spacer disputeGameBlacklist
    bytes32 private spacer_58_0_32;

    /// @custom:legacy
    /// @custom:spacer respectedGameType
    GameType private spacer_59_0_4;

    /// @custom:legacy
    /// @custom:spacer respectedGameTypeUpdatedAt
    uint64 private spacer_59_4_8;

    /// @notice Mapping of withdrawal hashes to addresses that have submitted a proof for the
    ///         withdrawal. Original OptimismPortal contract only allowed one proof to be submitted
    ///         for any given withdrawal hash. Fault Proofs version of this contract must allow
    ///         multiple proofs for the same withdrawal hash to prevent a malicious user from
    ///         blocking other withdrawals by proving them against invalid proposals. Submitters
    ///         are tracked in an array to simplify the off-chain process of determining which
    ///         proof submission should be used when finalizing a withdrawal.
    mapping(bytes32 => address[]) public proofSubmitters;

    /// @custom:legacy
    /// @custom:spacer _balance
    uint256 private spacer_61_0_32;

    /// @notice Address of the AnchorStateRegistry contract.
    IAnchorStateRegistry public anchorStateRegistry;

    /// @notice Address of the ETHLockbox contract. NOTE that as of v4.1.0 it is not possible to
    ///         set this value in storage and it is only possible for this value to be set if the
    ///         chain was first upgraded to v4.0.0. Chains that skip v4.0.0 will not have any
    ///         ETHLockbox set here.
    IETHLockbox public ethLockbox;

    /// @custom:legacy
    /// @custom:spacer superRootsActive
    bool private spacer_63_20_1;

    /// @notice Emitted when a transaction is deposited from L1 to L2. The parameters of this event
    ///         are read by the rollup node and used to derive deposit transactions on L2.
    /// @param from       Address that triggered the deposit transaction.
    /// @param to         Address that the deposit transaction is directed to.
    /// @param version    Version of this deposit transaction event.
    /// @param opaqueData ABI encoded deposit data to be parsed off-chain.
    event TransactionDeposited(address indexed from, address indexed to, uint256 indexed version, bytes opaqueData);

    /// @notice Emitted when a withdrawal transaction is proven.
    /// @param withdrawalHash Hash of the withdrawal transaction.
    /// @param from           Address that triggered the withdrawal transaction.
    /// @param to             Address that the withdrawal transaction is directed to.
    event WithdrawalProven(bytes32 indexed withdrawalHash, address indexed from, address indexed to);

    /// @notice Emitted when a withdrawal transaction is proven. Exists as a separate event to
    ///         allow for backwards compatibility for tooling that observes the WithdrawalProven
    ///         event.
    /// @param withdrawalHash Hash of the withdrawal transaction.
    /// @param proofSubmitter Address of the proof submitter.
    event WithdrawalProvenExtension1(bytes32 indexed withdrawalHash, address indexed proofSubmitter);

    /// @notice Emitted when a withdrawal transaction is finalized.
    /// @param withdrawalHash Hash of the withdrawal transaction.
    /// @param success        Whether the withdrawal transaction was successful.
    event WithdrawalFinalized(bytes32 indexed withdrawalHash, bool success);

    /// @notice Thrown when a withdrawal has already been finalized.
    error OptimismPortal_AlreadyFinalized();

    /// @notice Thrown when the target of a withdrawal is unsafe.
    error OptimismPortal_BadTarget();

    /// @notice Thrown when the calldata for a deposit is too large.
    error OptimismPortal_CalldataTooLarge();

    /// @notice Thrown when the portal is paused.
    error OptimismPortal_CallPaused();

    /// @notice Thrown when a CGT withdrawal is not allowed.
    error OptimismPortal_NotAllowedOnCGTMode();

    /// @notice Thrown when a gas estimation transaction is being executed.
    error OptimismPortal_GasEstimation();

    /// @notice Thrown when the gas limit for a deposit is too low.
    error OptimismPortal_GasLimitTooLow();

    /// @notice Thrown when the target of a withdrawal is not a proper dispute game.
    error OptimismPortal_ImproperDisputeGame();

    /// @notice Thrown when a withdrawal has not been proven against a valid dispute game.
    error OptimismPortal_InvalidDisputeGame();

    /// @notice Thrown when a withdrawal has not been proven against a valid merkle proof.
    error OptimismPortal_InvalidMerkleProof();

    /// @notice Thrown when a withdrawal has not been proven against a valid output root proof.
    error OptimismPortal_InvalidOutputRootProof();

    /// @notice Thrown when a withdrawal's timestamp is not greater than the dispute game's creation timestamp.
    error OptimismPortal_InvalidProofTimestamp();

    /// @notice Thrown when the root claim of a dispute game is invalid.
    error OptimismPortal_InvalidRootClaim();

    /// @notice Thrown when a withdrawal is being finalized by a reentrant call.
    error OptimismPortal_NoReentrancy();

    /// @notice Thrown when a withdrawal has not been proven for long enough.
    error OptimismPortal_ProofNotOldEnough();

    /// @notice Thrown when a withdrawal has not been proven.
    error OptimismPortal_Unproven();

    /// @notice Thrown when ETHLockbox is set/unset incorrectly depending on the feature flag.
    error OptimismPortal_InvalidLockboxState();

    /// @notice Semantic version.
    /// @custom:semver 5.2.0
    function version() public pure virtual returns (string memory) {
        return "5.2.0";
    }

    /// @param _proofMaturityDelaySeconds The proof maturity delay in seconds.
    constructor(uint256 _proofMaturityDelaySeconds) ReinitializableBase(3) {
        PROOF_MATURITY_DELAY_SECONDS = _proofMaturityDelaySeconds;
        _disableInitializers();
    }

    /// @notice Initializer.
    /// @param _systemConfig Address of the SystemConfig.
    /// @param _anchorStateRegistry Address of the AnchorStateRegistry.
    function initialize(
        ISystemConfig _systemConfig,
        IAnchorStateRegistry _anchorStateRegistry
    )
        external
        reinitializer(initVersion())
    {
        // Initialization transactions must come from the ProxyAdmin or its owner.
        _assertOnlyProxyAdminOrProxyAdminOwner();

        // Now perform initialization logic.
        systemConfig = _systemConfig;
        anchorStateRegistry = _anchorStateRegistry;

        // Assert that the lockbox state is valid.
        _assertValidLockboxState();

        // Set the l2Sender slot, only if it is currently empty. This signals the first
        // initialization of the contract.
        if (l2Sender == address(0)) {
            l2Sender = Constants.DEFAULT_L2_SENDER;
        }

        // Initialize the ResourceMetering contract.
        __ResourceMetering_init();
    }

    /// @notice Getter for the current paused status.
    function paused() public view returns (bool) {
        return systemConfig.paused();
    }

    /// @notice Getter for the proof maturity delay.
    function proofMaturityDelaySeconds() public view returns (uint256) {
        return PROOF_MATURITY_DELAY_SECONDS;
    }

    /// @notice Getter for the address of the DisputeGameFactory contract.
    function disputeGameFactory() public view returns (IDisputeGameFactory) {
        return anchorStateRegistry.disputeGameFactory();
    }

    /// @notice Returns the SuperchainConfig contract.
    /// @return ISuperchainConfig The SuperchainConfig contract.
    function superchainConfig() external view returns (ISuperchainConfig) {
        return systemConfig.superchainConfig();
    }

    /// @custom:legacy
    /// @notice Getter function for the address of the guardian.
    function guardian() external view returns (address) {
        return systemConfig.guardian();
    }

    /// @custom:legacy
    /// @notice Getter for the dispute game finality delay.
    function disputeGameFinalityDelaySeconds() external view returns (uint256) {
        return anchorStateRegistry.disputeGameFinalityDelaySeconds();
    }

    /// @custom:legacy
    /// @notice Getter for the respected game type.
    function respectedGameType() external view returns (GameType) {
        return anchorStateRegistry.respectedGameType();
    }

    /// @custom:legacy
    /// @notice Getter for the retirement timestamp. Note that this value NO LONGER reflects the
    ///         timestamp at which the respected game type was updated. Game retirement and
    ///         respected game type value have been decoupled, this function now only returns the
    ///         retirement timestamp.
    function respectedGameTypeUpdatedAt() external view returns (uint64) {
        return anchorStateRegistry.retirementTimestamp();
    }

    /// @custom:legacy
    /// @notice Getter for the dispute game blacklist.
    /// @param _disputeGame The dispute game to check.
    /// @return Whether the dispute game is blacklisted.
    function disputeGameBlacklist(IDisputeGame _disputeGame) public view returns (bool) {
        return anchorStateRegistry.disputeGameBlacklist(_disputeGame);
    }

    /// @notice Computes the minimum gas limit for a deposit.
    ///         The minimum gas limit linearly increases based on the size of the calldata.
    ///         This is to prevent users from creating L2 resource usage without paying for it.
    ///         This function can be used when interacting with the portal to ensure forwards
    ///         compatibility.
    /// @param _byteCount Number of bytes in the calldata.
    /// @return The minimum gas limit for a deposit.
    function minimumGasLimit(uint64 _byteCount) public pure returns (uint64) {
        return _byteCount * 40 + 21000;
    }

    /// @notice Accepts value so that users can send ETH directly to this contract and have the
    ///         funds be deposited to their address on L2. This is intended as a convenience
    ///         function for EOAs. Contracts should call the depositTransaction() function directly
    ///         otherwise any deposited funds will be lost due to address aliasing.
    receive() external payable {
        depositTransaction(msg.sender, msg.value, RECEIVE_DEFAULT_GAS_LIMIT, false, bytes(""));
    }

    /// @notice Accepts ETH value without triggering a deposit to L2.
    function donateETH() external payable {
        // Intentionally empty.
    }

    /// @notice 使用输出根证明来证明一个提款交易
    /// 
    /// 这是提款流程的第二阶段（第一阶段在 L2 发起，第三阶段是最终确认）。
    /// 
    /// 证明过程：
    /// 1. 验证 DisputeGame 的有效性（必须是 Proper Game，必须是 Respected Game Type）
    /// 2. 验证输出根证明（确保状态根有效）
    /// 3. 验证 Merkle 包含证明（确保提款确实在 L2 上发生）
    /// 4. 记录证明信息，等待成熟期后可以最终确认
    /// 
    /// @param _tx               要证明的提款交易
    /// @param _disputeGameIndex 用于证明的争议游戏索引
    /// @param _outputRootProof  输出根证明，包含 L2ToL1MessagePasser 的存储根
    /// @param _withdrawalProof  Merkle 包含证明，证明提款在 L2ToL1MessagePasser 中
    function proveWithdrawalTransaction(
        Types.WithdrawalTransaction memory _tx,
        uint256 _disputeGameIndex,
        Types.OutputRootProof calldata _outputRootProof,
        bytes[] calldata _withdrawalProof
    )
        external
    {
        // 系统暂停时不能证明提款
        _assertNotPaused();

        // 确保目标地址是安全的（不能是 Portal 自身或 ETHLockbox）
        if (_isUnsafeTarget(_tx.target)) {
            revert OptimismPortal_BadTarget();
        }

        // 如果启用了自定义 Gas Token 模式，不能提款 ETH
        if (_isUsingCustomGasToken()) {
            if (_tx.value > 0) revert OptimismPortal_NotAllowedOnCGTMode();
        }

        // 从 DisputeGameFactory 获取争议游戏代理合约
        (,, IDisputeGame disputeGameProxy) = disputeGameFactory().gameAtIndex(_disputeGameIndex);

        // 验证：游戏必须是 Proper Game（有效的游戏）
        // Proper Game 意味着游戏类型已注册且配置正确
        if (!anchorStateRegistry.isGameProper(disputeGameProxy)) {
            revert OptimismPortal_ImproperDisputeGame();
        }

        // 验证：游戏创建时必须是 Respected Game Type（受尊重的游戏类型）
        // Respected Game Type 是当前系统认可的游戏类型，用于验证状态根
        if (!anchorStateRegistry.isGameRespected(disputeGameProxy)) {
            revert OptimismPortal_InvalidDisputeGame();
        }

        // 验证：游戏不能已判定挑战者获胜（即状态根无效）
        // 如果挑战者获胜，说明状态根是无效的，不能基于此证明提款
        if (disputeGameProxy.status() == GameStatus.CHALLENGER_WINS) {
            revert OptimismPortal_InvalidDisputeGame();
        }

        // 安全检查：确保当前时间戳大于争议游戏的创建时间戳
        // 这防止了在游戏创建的同一区块中证明提款，增加了安全性
        if (block.timestamp <= disputeGameProxy.createdAt().raw()) {
            revert OptimismPortal_InvalidProofTimestamp();
        }

        // 验证：输出根必须与证明中的元素匹配
        // 争议游戏的根声明（rootClaim）应该等于输出根证明的哈希
        if (disputeGameProxy.rootClaim().raw() != Hashing.hashOutputRootProof(_outputRootProof)) {
            revert OptimismPortal_InvalidOutputRootProof();
        }

        // 计算提款交易的哈希，作为唯一标识符
        bytes32 withdrawalHash = Hashing.hashWithdrawal(_tx);

        // 计算提款哈希在 L2ToL1MessagePasser 合约中的存储槽
        // 这是 Solidity mapping 的存储布局计算方式
        // sentMessages[withdrawalHash] 的存储槽 = keccak256(abi.encode(withdrawalHash, slot(0)))
        bytes32 storageKey = keccak256(
            abi.encode(
                withdrawalHash,
                uint256(0) // sentMessages mapping 在布局的第一个槽位
            )
        );

        // 验证：使用 Merkle 包含证明验证提款确实在 L2 上发生
        // 如果验证通过，说明：
        // 1. 提款确实在 L2ToL1MessagePasser 合约中被记录（sentMessages[withdrawalHash] = true）
        // 2. 该记录包含在输出根证明的存储根中
        // 3. 因此可以在 L1 上中继执行
        if (
            SecureMerkleTrie.verifyInclusionProof({
                _key: abi.encode(storageKey),                    // 存储键
                _value: hex"01",                                // 存储值（true 的编码）
                _proof: _withdrawalProof,                       // Merkle 证明路径
                _root: _outputRootProof.messagePasserStorageRoot // L2ToL1MessagePasser 的存储根
            }) == false
        ) {
            revert OptimismPortal_InvalidMerkleProof();
        }

        // 将提款标记为已证明，记录争议游戏代理和时间戳
        // 注意：同一个提款哈希可以被多个用户多次证明，每次证明都会重置计时器
        // 这防止了恶意用户通过提交无效证明来阻止其他用户的提款
        provenWithdrawals[withdrawalHash][msg.sender] =
            ProvenWithdrawal({ disputeGameProxy: disputeGameProxy, timestamp: uint64(block.timestamp) });

        // 将证明提交者添加到该提款哈希的证明提交者列表中
        // 链下工具可以使用这个列表来确定应该使用哪个证明来最终确认提款
        proofSubmitters[withdrawalHash].push(msg.sender);

        // Emit a WithdrawalProven events.
        emit WithdrawalProven(withdrawalHash, _tx.sender, _tx.target);
        emit WithdrawalProvenExtension1(withdrawalHash, msg.sender);
    }

    /// @notice 最终确认一个提款交易
    /// 
    /// 这是提款流程的第三阶段（最后阶段）。在证明成熟期过后，可以调用此函数来最终确认提款。
    /// 
    /// 流程：
    /// 1. 检查提款是否已证明且成熟期已过
    /// 2. 检查争议游戏是否仍然有效
    /// 3. 标记提款为已最终确认（防止重放）
    /// 4. 如果使用 ETHLockbox，解锁 ETH
    /// 5. 执行提款交易（调用目标合约）
    /// 
    /// @param _tx 要最终确认的提款交易
    function finalizeWithdrawalTransaction(Types.WithdrawalTransaction memory _tx) external {
        finalizeWithdrawalTransactionExternalProof(_tx, msg.sender);
    }

    /// @notice 最终确认提款交易，使用外部证明提交者
    /// 
    /// 这个函数允许指定使用哪个证明提交者的证明来最终确认提款。
    /// 这在有多个证明提交者时很有用。
    /// 
    /// @param _tx            要最终确认的提款交易
    /// @param _proofSubmitter 证明提交者的地址
    function finalizeWithdrawalTransactionExternalProof(
        Types.WithdrawalTransaction memory _tx,
        address _proofSubmitter
    )
        public
    {
        // 系统暂停时不能最终确认提款
        _assertNotPaused();

        // 如果启用了自定义 Gas Token 模式，不能提款 ETH
        if (_isUsingCustomGasToken()) {
            if (_tx.value > 0) revert OptimismPortal_NotAllowedOnCGTMode();
        }

        // 重入保护：确保 l2Sender 还未被设置
        // l2Sender 在最终确认提款时会被设置为非默认值，这个检查是事实上的重入保护
        // 如果 l2Sender 不是默认值，说明我们正在处理另一个提款，应该拒绝
        if (l2Sender != Constants.DEFAULT_L2_SENDER) {
            revert OptimismPortal_NoReentrancy();
        }

        // 确保目标地址是安全的
        if (_isUnsafeTarget(_tx.target)) {
            revert OptimismPortal_BadTarget();
        }

        // 计算提款哈希
        bytes32 withdrawalHash = Hashing.hashWithdrawal(_tx);

        // 检查提款是否可以最终确认（验证证明、成熟期、争议游戏有效性等）
        checkWithdrawal(withdrawalHash, _proofSubmitter);

        // 标记提款为已最终确认，防止重放攻击
        finalizedWithdrawals[withdrawalHash] = true;

        // 如果使用 ETHLockbox，从 ETHLockbox 解锁 ETH
        // ETHLockbox 是一个特殊的合约，用于在启用时管理 ETH 的锁定和解锁
        if (_isUsingLockbox()) {
            if (_tx.value > 0) ethLockbox.unlockETH(_tx.value);
        }

        // 设置 l2Sender，这样被调用的合约可以知道是谁在 L2 上触发了这个提款
        // 这对于跨链消息传递很重要
        l2Sender = _tx.sender;

        // 执行对目标合约的调用
        // 使用 SafeCall.callWithMinGas 确保两个关键属性：
        // 1. 目标合约不能通过返回大量数据来强制调用耗尽 gas（我们不关心返回值）
        // 2. 提供给目标合约执行上下文的 gas 至少是用户指定的 gas 限制
        //    如果当前上下文中没有足够的 gas，callWithMinGas 会回滚
        bool success = SafeCall.callWithMinGas(_tx.target, _tx.gasLimit, _tx.value, _tx.data);

        // 将 l2Sender 重置为默认值
        l2Sender = Constants.DEFAULT_L2_SENDER;

        // All withdrawals are immediately finalized. Replayability can
        // be achieved through contracts built on top of this contract
        emit WithdrawalFinalized(withdrawalHash, success);

        // If using ETHLockbox, send ETH back to the Lockbox in the case of a failed transaction or
        // it'll get stuck here and would need to be moved back via admin action.
        if (_isUsingLockbox()) {
            if (!success && _tx.value > 0) {
                ethLockbox.lockETH{ value: _tx.value }();
            }
        }

        // Reverting here is useful for determining the exact gas cost to successfully execute the
        // sub call to the target contract if the minimum gas limit specified by the user would not
        // be sufficient to execute the sub call.
        if (!success && tx.origin == Constants.ESTIMATION_ADDRESS) {
            revert OptimismPortal_GasEstimation();
        }
    }

    /// @notice 检查提款是否已证明且可以最终确认
    /// 
    /// 这个函数执行所有必要的检查，确保提款可以安全地最终确认：
    /// 1. 提款未被最终确认过（重放保护）
    /// 2. 提款已被证明（时间戳非零）
    /// 3. 证明时间戳有效（大于争议游戏创建时间）
    /// 4. 证明成熟期已过（等待时间足够）
    /// 5. 争议游戏的根声明仍然有效
    /// 
    /// @param _withdrawalHash 提款哈希
    /// @param _proofSubmitter 证明提交者地址
    function checkWithdrawal(bytes32 _withdrawalHash, address _proofSubmitter) public view {
        // 获取提款证明信息和争议游戏代理
        ProvenWithdrawal memory provenWithdrawal = provenWithdrawals[_withdrawalHash][_proofSubmitter];
        IDisputeGame disputeGameProxy = provenWithdrawal.disputeGameProxy;

        // 检查：提款未被最终确认过（重放保护）
        if (finalizedWithdrawals[_withdrawalHash]) {
            revert OptimismPortal_AlreadyFinalized();
        }

        // 检查：提款必须已被证明
        // 如果时间戳为零，说明提款未被证明
        if (provenWithdrawal.timestamp == 0) {
            revert OptimismPortal_Unproven();
        }

        // 安全检查：证明时间戳必须大于争议游戏的创建时间戳
        // 这防止了在游戏创建的同一区块中证明提款
        if (provenWithdrawal.timestamp <= disputeGameProxy.createdAt().raw()) {
            revert OptimismPortal_InvalidProofTimestamp();
        }

        // 检查：证明成熟期必须已过
        // 已证明的提款必须等待至少 PROOF_MATURITY_DELAY_SECONDS 秒才能最终确认
        // 这给挑战者足够的时间来质疑无效的证明
        if (block.timestamp - provenWithdrawal.timestamp <= PROOF_MATURITY_DELAY_SECONDS) {
            revert OptimismPortal_ProofNotOldEnough();
        }

        // 检查：争议游戏的根声明必须仍然有效
        // 如果游戏被标记为无效或已退休，不能基于此最终确认提款
        if (!anchorStateRegistry.isGameClaimValid(disputeGameProxy)) {
            revert OptimismPortal_InvalidRootClaim();
        }
    }

    /// @notice 接受 ETH 和数据存款，发出 TransactionDeposited 事件用于在 L2 上派生存款交易
    /// 
    /// 这是存款流程的核心函数。当用户想要从 L1 向 L2 发送交易时，调用此函数。
    /// 
    /// 工作流程：
    /// 1. 如果使用 ETHLockbox，锁定 ETH
    /// 2. 验证参数（gas 限制、calldata 大小等）
    /// 3. 处理地址别名（如果是合约调用）
    /// 4. 发出 TransactionDeposited 事件
    /// 5. Rollup 节点监听事件，在 L2 上构建并执行存款交易
    /// 
    /// 重要说明：
    /// - 如果存款由合约发起，地址会被别名化（使用 AddressAliasHelper）
    /// - 建议使用 CrossDomainMessenger 作为更高级的接口
    /// - msg.value 会被锁定在 ETHLockbox（如果启用），在 L2 上铸造为 ETH
    /// - _value 指定发送给接收者的 ETH 数量
    /// 
    /// @param _to          L2 上的目标地址
    /// @param _value       发送给接收者的 ETH 数量
    /// @param _gasLimit    通过燃烧 L1 gas 购买的 L2 gas 数量
    /// @param _isCreation  交易是否是合约创建
    /// @param _data        触发接收者的数据
    function depositTransaction(
        address _to,
        uint256 _value,
        uint64 _gasLimit,
        bool _isCreation,
        bytes memory _data
    )
        public
        payable
        metered(_gasLimit)  // ResourceMetering 修饰符，用于计量资源使用
    {
        // 如果启用了自定义 Gas Token 模式，不能发送 ETH
        if (_isUsingCustomGasToken()) {
            if (msg.value > 0) revert OptimismPortal_NotAllowedOnCGTMode();
        }

        // 如果使用 ETHLockbox，将 ETH 锁定在 ETHLockbox 中
        // ETHLockbox 是一个特殊的合约，用于管理 ETH 的锁定和解锁
        // 当存款到达 L2 时，ETH 会在 L2 上被铸造
        if (_isUsingLockbox()) {
            if (msg.value > 0) ethLockbox.lockETH{ value: msg.value }();
        }

        // 安全检查：合约创建时必须指定 address(0) 作为目标
        if (_isCreation && _to != address(0)) {
            revert OptimismPortal_BadTarget();
        }

        // 防止存款交易的 gas 限制太小
        // 最小 gas 限制根据 calldata 大小线性增加，防止用户不支付资源使用费用
        if (_gasLimit < minimumGasLimit(uint64(_data.length))) {
            revert OptimismPortal_GasLimitTooLow();
        }

        // 防止创建 calldata 过大的存款交易
        // 120kb 的限制确保交易可以适应 p2p 网络的 128kb 策略
        // 即使存款交易不在 p2p 网络上传播
        if (_data.length > 120_000) {
            revert OptimismPortal_CalldataTooLarge();
        }

        // 如果调用者是合约，将 from 地址转换为别名
        // 地址别名化是 Optimism 的安全机制，防止 L1 合约地址与 L2 地址冲突
        // 别名公式：L2地址 = L1地址 + 0x1111000000000000000000000000000000001111
        address from = msg.sender;
        if (!EOA.isSenderEOA()) {
            from = AddressAliasHelper.applyL1ToL2Alias(msg.sender);
        }

        // 计算不透明数据，将作为 TransactionDeposited 事件的一部分发出
        // 使用不透明数据允许我们在未来更新 TransactionDeposited 事件而不破坏当前接口
        bytes memory opaqueData = abi.encodePacked(msg.value, _value, _gasLimit, _isCreation, _data);

        // 发出 TransactionDeposited 事件，Rollup 节点监听此事件并在 L2 上派生存款交易
        // Rollup 节点会：
        // 1. 监听此事件
        // 2. 解析 opaqueData
        // 3. 在 L2 上构建并执行相应的存款交易
        emit TransactionDeposited(from, _to, DEPOSIT_VERSION, opaqueData);
    }

    /// @notice External getter for the number of proof submitters for a withdrawal hash.
    /// @param _withdrawalHash Hash of the withdrawal.
    /// @return The number of proof submitters for the withdrawal hash.
    function numProofSubmitters(bytes32 _withdrawalHash) external view returns (uint256) {
        return proofSubmitters[_withdrawalHash].length;
    }

    /// @notice Checks if the ETHLockbox feature is enabled.
    /// @return bool True if the ETHLockbox feature is enabled.
    function _isUsingLockbox() internal view returns (bool) {
        return systemConfig.isFeatureEnabled(Features.ETH_LOCKBOX) && address(ethLockbox) != address(0);
    }

    /// @notice Checks if the Custom Gas Token feature is enabled.
    /// @return bool True if the Custom Gas Token feature is enabled.
    function _isUsingCustomGasToken() internal view returns (bool) {
        // NOTE: Chains are not supposed to enable Custom Gas Token (CGT) mode after initial deployment.
        //       Enabling CGT post-deployment is strongly discouraged and may lead to unexpected behavior.
        return systemConfig.isFeatureEnabled(Features.CUSTOM_GAS_TOKEN);
    }

    /// @notice Asserts that the contract is not paused.
    function _assertNotPaused() internal view {
        if (paused()) {
            revert OptimismPortal_CallPaused();
        }
    }

    /// @notice Asserts that the ETHLockbox is set/unset correctly depending on the feature flag.
    function _assertValidLockboxState() internal view {
        if (
            systemConfig.isFeatureEnabled(Features.ETH_LOCKBOX) && address(ethLockbox) == address(0)
                || !systemConfig.isFeatureEnabled(Features.ETH_LOCKBOX) && address(ethLockbox) != address(0)
        ) {
            revert OptimismPortal_InvalidLockboxState();
        }
    }

    /// @notice Checks if a target address is unsafe.
    function _isUnsafeTarget(address _target) internal view virtual returns (bool) {
        // Prevent users from targeting an unsafe target address on a withdrawal transaction.
        return _target == address(this) || _target == address(ethLockbox);
    }

    /// @notice Getter for the resource config. Used internally by the ResourceMetering contract.
    ///         The SystemConfig is the source of truth for the resource config.
    /// @return config_ ResourceMetering ResourceConfig
    function _resourceConfig() internal view override returns (ResourceMetering.ResourceConfig memory config_) {
        IResourceMetering.ResourceConfig memory config = systemConfig.resourceConfig();
        assembly ("memory-safe") {
            config_ := config
        }
    }
}
