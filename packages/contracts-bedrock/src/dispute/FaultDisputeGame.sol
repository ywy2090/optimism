// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

// Libraries
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {FixedPointMathLib} from "@solady/utils/FixedPointMathLib.sol";
import {Clone} from "@solady/utils/Clone.sol";
import {Types} from "src/libraries/Types.sol";
import {Hashing} from "src/libraries/Hashing.sol";
import {RLPReader} from "src/libraries/rlp/RLPReader.sol";
import {
    GameStatus,
    GameType,
    BondDistributionMode,
    Claim,
    Clock,
    Duration,
    Timestamp,
    Hash,
    Proposal,
    LibClock,
    LocalPreimageKey,
    VMStatuses
} from "src/dispute/lib/Types.sol";
import {Position, LibPosition} from "src/dispute/lib/LibPosition.sol";
import {
    InvalidParent,
    ClaimAlreadyExists,
    ClaimAlreadyResolved,
    OutOfOrderResolution,
    InvalidChallengePeriod,
    InvalidSplitDepth,
    InvalidClockExtension,
    MaxDepthTooLarge,
    AnchorRootNotFound,
    AlreadyInitialized,
    UnexpectedRootClaim,
    GameNotInProgress,
    InvalidPrestate,
    ValidStep,
    GameDepthExceeded,
    L2BlockNumberChallenged,
    InvalidDisputedClaimIndex,
    ClockTimeExceeded,
    DuplicateStep,
    CannotDefendRootClaim,
    IncorrectBondAmount,
    InvalidLocalIdent,
    BlockNumberMatches,
    InvalidHeaderRLP,
    ClockNotExpired,
    BondTransferFailed,
    NoCreditToClaim,
    InvalidOutputRootProof,
    ClaimAboveSplit,
    GameNotFinalized,
    InvalidBondDistributionMode,
    GameNotResolved,
    GamePaused,
    BadExtraData,
    UnknownChainId
} from "src/dispute/lib/Errors.sol";

// Interfaces
import {ISemver} from "interfaces/universal/ISemver.sol";
import {IDelayedWETH} from "interfaces/dispute/IDelayedWETH.sol";
import {IBigStepper, IPreimageOracle} from "interfaces/dispute/IBigStepper.sol";
import {
    IAnchorStateRegistry
} from "interfaces/dispute/IAnchorStateRegistry.sol";
import {IDisputeGame} from "interfaces/dispute/IDisputeGame.sol";

/// @title FaultDisputeGame
/// @notice FaultDisputeGame 是故障争议游戏的实现，用于验证 L2 状态根的有效性。
///
/// 核心功能：
/// 1. **初始化游戏**：挑战者创建游戏，提交根声明（root claim）和保证金
/// 2. **交互式争议**：通过攻击（attack）和防御（defend）移动进行二分法争议
/// 3. **单步执行证明**：在分割深度（split depth）使用 MIPS64 虚拟机执行单步证明
/// 4. **解决游戏**：遍历子游戏树，确定最终获胜者并分配保证金
///
/// 争议流程：
/// - **输出根二分法**：从根声明开始，逐步缩小争议范围到分割深度
/// - **执行跟踪二分法**：在分割深度以下，继续二分法直到单步执行
/// - **单步执行验证**：使用 MIPS64 虚拟机执行单步，验证状态转换是否正确
///
/// 游戏状态：
/// - IN_PROGRESS：游戏进行中
/// - CHALLENGER_WINS：挑战者获胜（状态根无效）
/// - DEFENDER_WINS：防御者获胜（状态根有效）
///
/// 保证金机制：
/// - 双方都需要存入保证金
/// - 失败方损失保证金，获胜方获得保证金
contract FaultDisputeGame is Clone, ISemver {
    ////////////////////////////////////////////////////////////////
    //                         Structs                            //
    ////////////////////////////////////////////////////////////////

    /// @notice ClaimData 结构体表示与声明（Claim）相关的数据
    ///
    /// 字段说明：
    /// - parentIndex: 父声明的索引（在 claimData 数组中的位置）
    /// - counteredBy: 反驳此声明的地址（如果被反驳）
    /// - claimant: 提出此声明的地址
    /// - bond: 与此声明相关的保证金数量
    /// - claim: 声明本身（状态哈希）
    /// - position: 声明在游戏树中的位置
    /// - clock: 时钟信息（用于超时机制）
    struct ClaimData {
        uint32 parentIndex; // 父声明索引
        address counteredBy; // 反驳者地址
        address claimant; // 声明者地址
        uint128 bond; // 保证金数量
        Claim claim; // 声明（状态哈希）
        Position position; // 位置（在游戏树中）
        Clock clock; // 时钟（超时机制）
    }

    /// @notice The `ResolutionCheckpoint` struct represents the data associated with an in-progress claim resolution.
    struct ResolutionCheckpoint {
        bool initialCheckpointComplete;
        uint32 subgameIndex;
        Position leftmostPosition;
        address counteredBy;
    }

    /// @notice Parameters for creating a new FaultDisputeGame. We place this into a struct to
    ///         avoid stack-too-deep errors when compiling without the optimizer enabled.
    struct GameConstructorParams {
        uint256 maxGameDepth;
        uint256 splitDepth;
        Duration clockExtension;
        Duration maxClockDuration;
    }

    ////////////////////////////////////////////////////////////////
    //                         Events                             //
    ////////////////////////////////////////////////////////////////

    /// @notice Emitted when the game is resolved.
    /// @param status The status of the game after resolution.
    event Resolved(GameStatus indexed status);

    /// @notice Emitted when a new claim is added to the DAG by `claimant`
    /// @param parentIndex The index within the `claimData` array of the parent claim
    /// @param claim The claim being added
    /// @param claimant The address of the claimant
    event Move(
        uint256 indexed parentIndex,
        Claim indexed claim,
        address indexed claimant
    );

    /// @notice Emitted when the game is closed.
    event GameClosed(BondDistributionMode bondDistributionMode);

    ////////////////////////////////////////////////////////////////
    //                         State Vars                         //
    ////////////////////////////////////////////////////////////////

    /// @notice The max depth of the game.
    uint256 internal immutable MAX_GAME_DEPTH;

    /// @notice The max depth of the output bisection portion of the position tree. Immediately beneath
    ///         this depth, execution trace bisection begins.
    uint256 internal immutable SPLIT_DEPTH;

    /// @notice The maximum duration that may accumulate on a team's chess clock before they may no longer respond.
    Duration internal immutable MAX_CLOCK_DURATION;

    /// @notice The duration of the clock extension. Will be doubled if the grandchild is the root claim of an execution
    ///         trace bisection subgame.
    Duration internal immutable CLOCK_EXTENSION;

    /// @notice The global root claim's position is always at gindex 1.
    Position internal constant ROOT_POSITION = Position.wrap(1);

    /// @notice The index of the block number in the RLP-encoded block header.
    /// @dev Consensus encoding reference:
    /// https://github.com/paradigmxyz/reth/blob/5f82993c23164ce8ccdc7bf3ae5085205383a5c8/crates/primitives/src/header.rs#L368
    uint256 internal constant HEADER_BLOCK_NUMBER_INDEX = 8;

    /// @notice Semantic version.
    /// @custom:semver 2.4.0
    function version() public pure virtual returns (string memory) {
        return "2.4.0";
    }

    /// @notice The starting timestamp of the game
    Timestamp public createdAt;

    /// @notice The timestamp of the game's global resolution.
    Timestamp public resolvedAt;

    /// @notice Returns the current status of the game.
    GameStatus public status;

    /// @notice Flag for the `initialize` function to prevent re-initialization.
    bool internal initialized;

    /// @notice Flag for whether or not the L2 block number claim has been invalidated via `challengeRootL2Block`.
    bool public l2BlockNumberChallenged;

    /// @notice The challenger of the L2 block number claim. Should always be `address(0)` if `l2BlockNumberChallenged`
    ///         is `false`. Should be the address of the challenger if `l2BlockNumberChallenged` is `true`.
    address public l2BlockNumberChallenger;

    /// @notice An append-only array of all claims made during the dispute game.
    ClaimData[] public claimData;

    /// @notice Credited balances for winning participants.
    mapping(address => uint256) public normalModeCredit;

    /// @notice A mapping to allow for constant-time lookups of existing claims.
    mapping(Hash => bool) public claims;

    /// @notice A mapping of subgames rooted at a claim index to other claim indices in the subgame.
    mapping(uint256 => uint256[]) public subgames;

    /// @notice A mapping of resolved subgames rooted at a claim index.
    mapping(uint256 => bool) public resolvedSubgames;

    /// @notice A mapping of claim indices to resolution checkpoints.
    mapping(uint256 => ResolutionCheckpoint) public resolutionCheckpoints;

    /// @notice The latest finalized output root, serving as the anchor for output bisection.
    Proposal public startingOutputRoot;

    /// @notice A boolean for whether or not the game type was respected when the game was created.
    bool public wasRespectedGameTypeWhenCreated;

    /// @notice A mapping of each claimant's refund mode credit.
    mapping(address => uint256) public refundModeCredit;

    /// @notice A mapping of whether a claimant has unlocked their credit.
    mapping(address => bool) public hasUnlockedCredit;

    /// @notice The bond distribution mode of the game.
    BondDistributionMode public bondDistributionMode;

    /// @param _params Parameters for creating a new FaultDisputeGame.
    constructor(GameConstructorParams memory _params) {
        // The max game depth may not be greater than `LibPosition.MAX_POSITION_BITLEN - 1`.
        if (_params.maxGameDepth > LibPosition.MAX_POSITION_BITLEN - 1)
            revert MaxDepthTooLarge();

        // The split depth plus one cannot be greater than or equal to the max game depth. We add
        // an additional depth to the split depth to avoid a bug in trace ancestor lookup. We know
        // that the case where the split depth is the max value for uint256 is equivalent to the
        // second check though we do need to check it explicitly to avoid an overflow.
        if (
            _params.splitDepth == type(uint256).max ||
            _params.splitDepth + 1 >= _params.maxGameDepth
        ) {
            revert InvalidSplitDepth();
        }

        // The split depth cannot be 0 or 1 to stay in bounds of clock extension arithmetic.
        if (_params.splitDepth < 2) revert InvalidSplitDepth();

        // Validate clock extension bounds that don't require VM access.
        // The split depth extension is always clockExtension * 2.
        uint256 splitDepthExtension = uint256(_params.clockExtension.raw()) * 2;

        // The split depth extension must fit into a uint64.
        if (splitDepthExtension > type(uint64).max)
            revert InvalidClockExtension();

        // The split depth extension may not be greater than the maximum clock duration.
        if (uint64(splitDepthExtension) > _params.maxClockDuration.raw())
            revert InvalidClockExtension();

        // Set up initial game state.
        MAX_GAME_DEPTH = _params.maxGameDepth;
        SPLIT_DEPTH = _params.splitDepth;
        CLOCK_EXTENSION = _params.clockExtension;
        MAX_CLOCK_DURATION = _params.maxClockDuration;
    }

    /// @notice 初始化合约
    ///
    /// 这是争议游戏的创建阶段。只能调用一次。
    ///
    /// 初始化流程：
    /// 1. 从 AnchorStateRegistry 获取最新的锚定根
    /// 2. 验证根声明（root claim）的有效性
    /// 3. 创建根声明并存入保证金
    /// 4. 设置游戏创建时间戳和游戏类型状态
    ///
    /// 安全检查：
    /// - 游戏不能已被初始化
    /// - 根声明对应的区块号必须大于起始区块号
    /// - calldata 长度必须正确（防止游戏 UUID 冲突）
    ///
    /// 注意：此函数中的任何回滚都会冒泡到 DisputeGameFactory，阻止游戏创建。
    ///
    /// @dev 此函数只能调用一次
    function initialize() public payable virtual {
        // 安全说明：此函数中的任何回滚都会冒泡到 DisputeGameFactory，阻止游戏创建
        //
        // 隐式假设：
        // - `gameStatus` 状态变量默认为 0，即 `GameStatus.IN_PROGRESS`
        // - 争议游戏工厂将强制执行初始化游戏所需的保证金
        //
        // 显式检查：
        // - 游戏不能已被初始化
        // - 输出根不能在起始区块号或之前被提议

        // 不变量：游戏不能已被初始化
        if (initialized) revert AlreadyInitialized();

        // Revert if the calldata size is not the expected length.
        //
        // This is to prevent adding extra or omitting bytes from to `extraData` that result in a different game UUID
        // in the factory, but are not used by the game, which would allow for multiple dispute games for the same
        // output proposal to be created.
        if (msg.data.length != expectedInitCallDataLength())
            revert BadExtraData();

        // Grab the latest anchor root.
        (Hash root, uint256 rootBlockNumber) = ANCHOR_STATE_REGISTRY
            .getAnchorRoot();

        // 如果锚定根为零，说明这是新游戏类型且尚未设置
        if (root.raw() == bytes32(0)) revert AnchorRootNotFound();

        // 设置起始输出根提议
        startingOutputRoot = Proposal({
            l2SequenceNumber: rootBlockNumber,
            root: root
        });

        // 如果根声明对应的区块号在配置的起始区块号或之前，不允许初始化游戏
        // 这确保游戏只能挑战比锚定根更新的状态根
        if (l2BlockNumber() <= rootBlockNumber)
            revert UnexpectedRootClaim(rootClaim());
        if (l2BlockNumber() > type(uint64).max)
            revert UnexpectedRootClaim(rootClaim());

        // Validate parameters that require access to the VM.
        // The PreimageOracle challenge period must fit into uint64 so we can safely use it here.
        if (vm().oracle().challengePeriod() > type(uint64).max)
            revert InvalidChallengePeriod();

        // Determine the maximum clock extension which is either the split depth extension or the
        // maximum game depth extension depending on the configuration of these contracts.
        uint256 splitDepthExtension = uint256(CLOCK_EXTENSION.raw()) * 2;
        uint256 maxGameDepthExtension = uint256(CLOCK_EXTENSION.raw()) +
            uint64(vm().oracle().challengePeriod());
        uint256 maxClockExtension = Math.max(
            splitDepthExtension,
            maxGameDepthExtension
        );

        // The maximum clock extension must fit into a uint64.
        if (maxClockExtension > type(uint64).max)
            revert InvalidClockExtension();

        // The maximum clock extension may not be greater than the maximum clock duration.
        if (uint64(maxClockExtension) > MAX_CLOCK_DURATION.raw())
            revert InvalidClockExtension();

        // 设置根声明
        // 根声明是游戏的第一个声明，位置在 ROOT_POSITION（gindex 1）
        claimData.push(
            ClaimData({
                parentIndex: type(uint32).max, // 根声明没有父声明
                counteredBy: address(0), // 初始未被反驳
                claimant: gameCreator(), // 创建者地址
                bond: uint128(msg.value), // 保证金数量
                claim: rootClaim(), // 根声明（状态根哈希）
                position: ROOT_POSITION, // 根位置（gindex 1）
                clock: LibClock.wrap(
                    Duration.wrap(0),
                    Timestamp.wrap(uint64(block.timestamp))
                ) // 时钟初始化
            })
        );

        // 标记游戏为已初始化
        initialized = true;

        // 存入保证金到 WETH
        // 使用 refundModeCredit 记录创建者的信用（用于退款模式）
        refundModeCredit[gameCreator()] += msg.value;
        weth().deposit{value: msg.value}();

        // 设置游戏的起始时间戳
        createdAt = Timestamp.wrap(uint64(block.timestamp));

        // 设置游戏类型在游戏创建时是否被尊重
        // Respected Game Type 是当前系统认可的游戏类型
        wasRespectedGameTypeWhenCreated =
            GameType.unwrap(anchorStateRegistry().respectedGameType()) ==
            GameType.unwrap(gameType());
    }

    /// @notice Returns the expected calldata length for the initialize method
    function expectedInitCallDataLength() internal pure returns (uint256) {
        // Expected length: 6 bytes + immutable args byte count
        // - 4 bytes: selector
        // - 2 bytes: CWIA length prefix
        // - n bytes: Immutable args data
        return 6 + immutableArgsByteCount();
    }

    /// @notice Returns the byte count of the immutable args for this contract.
    function immutableArgsByteCount() internal pure virtual returns (uint256) {
        // Expected length: 244 bytes
        // - 20 bytes: creator address
        // - 32 bytes: root claim
        // - 32 bytes: l1 head
        // -  4 bytes: game type
        // - 32 bytes: extraData
        // - 32 bytes: absolutePrestate
        // - 20 bytes: vm address
        // - 20 bytes: anchorStateRegistry address
        // - 20 bytes: weth address
        // - 32 bytes: l2ChainId
        return 244;
    }

    ////////////////////////////////////////////////////////////////
    //                  `IFaultDisputeGame` impl                  //
    ////////////////////////////////////////////////////////////////

    /// @notice 通过链上故障证明处理器执行单条指令步骤
    ///
    /// 这是争议游戏的核心验证函数。在分割深度（split depth）以下，争议双方通过
    /// 单步执行来验证状态转换的正确性。
    ///
    /// 执行条件：
    /// - 游戏必须处于 IN_PROGRESS 状态
    /// - 步骤位置必须在 MAX_GAME_DEPTH + 1（即分割深度以下一层）
    /// - 声明必须未被反驳过
    ///
    /// 验证流程：
    /// 1. 确定前置状态（prestate）和后置状态（poststate）
    /// 2. 验证 _stateData 是前置状态的预映像
    /// 3. 使用 MIPS64 虚拟机执行单步
    /// 4. 验证执行结果是否与后置状态匹配
    /// 5. 如果验证通过，标记父声明为被反驳
    ///
    /// 攻击 vs 防御：
    /// - **攻击（_isAttack = true）**：挑战父声明，证明状态转换无效
    /// - **防御（_isAttack = false）**：支持父声明，证明状态转换有效
    ///
    /// @dev 此函数应指向故障证明处理器，以在链上执行故障证明程序中的步骤。
    ///      故障证明处理器合约的接口应遵循 `IBigStepper` 接口。
    ///
    /// @param _claimIndex 在 `claimData` 中被挑战的声明索引
    /// @param _isAttack   步骤是攻击还是防御
    /// @param _stateData  步骤的状态数据，是给定前置状态的声明的预映像
    ///                    - 如果是攻击，前置状态在 `_stateIndex`（或绝对前置状态）
    ///                    - 如果是防御，前置状态在 `_claimIndex`
    ///                    - 如果是对第一条指令的攻击，这是故障证明 VM 的绝对前置状态
    /// @param _proof      用于访问 VM 的 Merkle 状态树中内存节点的证明
    function step(
        uint256 _claimIndex,
        bool _isAttack,
        bytes calldata _stateData,
        bytes calldata _proof
    ) public virtual {
        // 不变量：只有在游戏进行中时才能执行步骤
        if (status != GameStatus.IN_PROGRESS) revert GameNotInProgress();

        // 获取父声明。如果不存在，调用将因越界而回滚
        ClaimData storage parent = claimData[_claimIndex];

        // 从存储中获取父位置
        Position parentPos = parent.position;

        // 确定步骤的位置（通过移动父位置）
        Position stepPos = parentPos.move(_isAttack);

        // 不变量：只有在移动位置比 `MAX_GAME_DEPTH` 深 1 层时才能执行步骤
        // 这意味着步骤必须在分割深度以下（执行跟踪二分法阶段）
        if (stepPos.depth() != MAX_GAME_DEPTH + 1) revert InvalidParent();

        // 确定步骤的预期前置状态和后置状态
        Claim preStateClaim;
        ClaimData storage postState;

        if (_isAttack) {
            // 攻击情况：
            // - 如果步骤位置在深度的索引为 0，前置状态是绝对前置状态
            // - 如果步骤是在跟踪索引 > 0 的攻击，前置状态存在于游戏状态的其他地方
            //
            // 注意：我们通过找到深度索引除以 2 ** (MAX_GAME_DEPTH - SPLIT_DEPTH) 的余数
            //       来本地化当前执行跟踪子游戏的 `indexAtDepth`，这是每个执行跟踪子游戏中的叶子数。
            //       这样我们可以确定步骤位置是否代表 `ABSOLUTE_PRESTATE`
            preStateClaim = (stepPos.indexAtDepth() %
                (1 << (MAX_GAME_DEPTH - SPLIT_DEPTH))) == 0
                ? absolutePrestate()
                : _findTraceAncestor(
                    Position.wrap(parentPos.raw() - 1),
                    parent.parentIndex,
                    false
                ).claim;

            // 对于所有攻击，后置状态是父声明
            postState = parent;
        } else {
            // 防御情况：
            // - 后置状态存在于游戏状态的其他地方
            // - 父声明是预期的前置状态
            preStateClaim = parent.claim;
            postState = _findTraceAncestor(
                Position.wrap(parentPos.raw() + 1),
                parent.parentIndex,
                false
            );
        }

        // 不变量：如果传递的 `_stateData` 不是前置状态声明哈希的预映像，前置状态总是无效的
        // 我们忽略摘要的最高位字节，因为它用于指示 VM 状态，是在摘要计算后添加的
        if (keccak256(_stateData) << 8 != preStateClaim.raw() << 8)
            revert InvalidPrestate();

        // 计算步骤的本地预映像上下文
        Hash uuid = _findLocalContext(_claimIndex);

        // INVARIANT: If a step is an attack, the poststate is valid if the step produces
        //            the same poststate hash as the parent claim's value.
        //            If a step is a defense:
        //              1. If the parent claim and the found post state agree with each other
        //                 (depth diff % 2 == 0), the step is valid if it produces the same
        //                 state hash as the post state's claim.
        //              2. If the parent claim and the found post state disagree with each other
        //                 (depth diff % 2 != 0), the parent cannot be countered unless the step
        //                 produces the same state hash as `postState.claim`.
        // SAFETY:    While the `attack` path does not need an extra check for the post
        //            state's depth in relation to the parent, we don't need another
        //            branch because (n - n) % 2 == 0.
        bool validStep = VM.step(_stateData, _proof, uuid.raw()) ==
            postState.claim.raw();
        bool parentPostAgree = (parentPos.depth() -
            postState.position.depth()) %
            2 ==
            0;

        // 如果父后置同意且步骤有效，或父后置不同意且步骤无效，则步骤验证失败
        if (parentPostAgree == validStep) revert ValidStep();

        // 不变量：不能对声明执行第二次步骤
        if (parent.counteredBy != address(0)) revert DuplicateStep();

        // 将父声明标记为被反驳
        // 我们不需要在游戏中追加新声明；相反，我们可以只将现有父声明标记为被反驳
        parent.counteredBy = msg.sender;
    }

    /// @notice 通用移动函数，用于 `attack` 和 `defend` 移动
    ///
    /// 这是交互式争议的核心函数。争议双方通过攻击和防御移动逐步缩小争议范围。
    ///
    /// 移动流程：
    /// 1. 验证游戏状态和父声明
    /// 2. 计算下一个位置（攻击向左，防御向右）
    /// 3. 验证移动的有效性（不能防御根声明、不能超过最大深度等）
    /// 4. 验证保证金数量
    /// 5. 计算时钟（超时机制）
    /// 6. 创建新声明并存入保证金
    /// 7. 更新子游戏结构
    ///
    /// 时钟机制：
    /// - 每个移动都有时间限制（MAX_CLOCK_DURATION）
    /// - 时钟扩展机制：在关键位置（如分割深度）自动扩展时钟
    /// - 防止一方通过拖延时间获胜
    ///
    /// @param _disputed      有争议的声明
    /// @param _challengeIndex 正在移动的声明索引
    /// @param _claim         游戏中下一个逻辑位置的声明
    /// @param _isAttack      移动是攻击还是防御
    function move(
        Claim _disputed,
        uint256 _challengeIndex,
        Claim _claim,
        bool _isAttack
    ) public payable virtual {
        // 不变量：只有在游戏进行中时才能移动
        if (status != GameStatus.IN_PROGRESS) revert GameNotInProgress();

        // 获取父声明。如果不存在，调用将因越界而回滚
        ClaimData memory parent = claimData[_challengeIndex];

        // 不变量：`_challengeIndex` 处的声明必须是有争议的声明
        if (Claim.unwrap(parent.claim) != Claim.unwrap(_disputed))
            revert InvalidDisputedClaimIndex();

        // 计算声明承诺的位置
        // 因为父位置已知，我们可以通过向左或向右移动来计算下一个位置，
        // 取决于移动是攻击还是防御
        Position parentPos = parent.position;
        Position nextPosition = parentPos.move(_isAttack); // 攻击向左，防御向右
        uint256 nextPositionDepth = nextPosition.depth();

        // 不变量：永远不能对输出根游戏或任何执行跟踪二分法子游戏的根声明进行防御
        // 这是因为根声明承诺整个状态。因此，如果同意，唯一有效的防御是什么都不做
        if (
            (_challengeIndex == 0 || nextPositionDepth == SPLIT_DEPTH + 2) &&
            !_isAttack
        ) {
            revert CannotDefendRootClaim();
        }

        // 不变量：在通过 `challengeRootL2Block` 挑战根声明后，不能再对根声明进行移动
        if (l2BlockNumberChallenged && _challengeIndex == 0)
            revert L2BlockNumberChallenged();

        // 不变量：移动永远不能超过 `MAX_GAME_DEPTH`
        // 在此深度反驳声明的唯一选择是通过 `step` 函数在链上执行单条指令步骤，
        // 以证明状态转换产生了意外的后置状态
        if (nextPositionDepth > MAX_GAME_DEPTH) revert GameDepthExceeded();

        // 当下一个位置超过分割深度时（即它是执行跟踪二分法子游戏的根声明），
        // 我们需要执行一些额外的验证步骤
        if (nextPositionDepth == SPLIT_DEPTH + 1) {
            _verifyExecBisectionRoot(
                _claim,
                _challengeIndex,
                parentPos,
                _isAttack
            );
        }

        // 不变量：`msg.value` 必须完全等于所需的保证金
        if (getRequiredBond(nextPosition) != msg.value)
            revert IncorrectBondAmount();

        // 计算下一个时钟的持续时间
        // 这是通过将祖父声明的持续时间加上当前区块时间戳与父声明的时钟时间戳之间的差值来完成的
        Duration nextDuration = getChallengerDuration(_challengeIndex);

        // 不变量：一旦时钟超过 `MAX_CLOCK_DURATION` 秒，就不能再进行移动
        if (nextDuration.raw() == MAX_CLOCK_DURATION.raw())
            revert ClockTimeExceeded();

        // 时钟扩展机制：
        // 当玩家在反驳"搭便车"声明时被迫继承另一方的时钟，如果剩余时间少于时钟扩展时间，
        // 时钟扩展机制会自动为潜在的孙子声明扩展时钟。
        // 时钟扩展的确切数量取决于我们在游戏中的确切位置
        uint64 actualExtension;
        if (nextPositionDepth == MAX_GAME_DEPTH - 1) {
            // If the next position is `MAX_GAME_DEPTH - 1` then we're about to execute a step. Our
            // clock extension must therefore account for the LPP challenge period in addition to
            // the standard clock extension.
            actualExtension =
                CLOCK_EXTENSION.raw() +
                uint64(VM.oracle().challengePeriod());
        } else if (nextPositionDepth == SPLIT_DEPTH - 1) {
            // 如果下一个位置是 `SPLIT_DEPTH - 1`，那么我们将要开始执行跟踪二分法
            // 我们需要给链下挑战代理额外的时间，以便能够在原生 FPVM 上生成初始指令跟踪
            actualExtension = CLOCK_EXTENSION.raw() * 2;
        } else {
            // 否则，我们只使用标准时钟扩展
            actualExtension = CLOCK_EXTENSION.raw();
        }

        // 检查是否需要应用时钟扩展
        if (nextDuration.raw() > MAX_CLOCK_DURATION.raw() - actualExtension) {
            nextDuration = Duration.wrap(
                MAX_CLOCK_DURATION.raw() - actualExtension
            );
        }

        // 使用新持续时间和当前区块时间戳构造下一个时钟
        Clock nextClock = LibClock.wrap(
            nextDuration,
            Timestamp.wrap(uint64(block.timestamp))
        );

        // 不变量：不能有多个相同移动在相同 challengeIndex 上的相同声明
        // 同一位置的多个声明可能争议相同的 challengeIndex，但它们必须有不同的值
        Hash claimHash = _claim.hashClaimPos(nextPosition, _challengeIndex);
        if (claims[claimHash]) revert ClaimAlreadyExists();
        claims[claimHash] = true;

        // 创建新声明
        claimData.push(
            ClaimData({
                parentIndex: uint32(_challengeIndex), // 父声明索引
                counteredBy: address(0), // 在子游戏解决期间更新
                claimant: msg.sender, // 声明者地址
                bond: uint128(msg.value), // 保证金数量
                claim: _claim, // 声明（状态哈希）
                position: nextPosition, // 位置
                clock: nextClock // 时钟
            })
        );

        // 更新以父声明为根的子游戏
        subgames[_challengeIndex].push(claimData.length - 1);

        // 存入保证金到 WETH
        // 使用 refundModeCredit 记录发送者的信用（用于退款模式）
        refundModeCredit[msg.sender] += msg.value;
        weth().deposit{value: msg.value}();

        // 发出攻击或防御的相应事件
        emit Move(_challengeIndex, _claim, msg.sender);
    }

    /// @notice 攻击一个不同意的声明（Claim）
    ///
    /// 这是交互式争议中的攻击移动。挑战者通过提出一个更具体的声明来挑战父声明，
    /// 逐步缩小争议范围。
    ///
    /// 攻击移动：
    /// - 在游戏树中向左移动（更具体的位置）
    /// - 提出一个新的声明，挑战父声明的有效性
    /// - 需要存入保证金
    /// - 更新时钟和子游戏结构
    ///
    /// @param _disputed   正在被攻击的声明
    /// @param _parentIndex 在 `claimData` 数组中要攻击的声明索引，必须与 `_disputed` 匹配
    /// @param _claim      在相对攻击位置的声明
    function attack(
        Claim _disputed,
        uint256 _parentIndex,
        Claim _claim
    ) external payable {
        // 调用通用移动函数，_isAttack = true 表示这是攻击
        move(_disputed, _parentIndex, _claim, true);
    }

    /// @notice 防御一个同意的声明（Claim）
    ///
    /// 这是交互式争议中的防御移动。防御者通过提出一个更具体的声明来支持父声明，
    /// 证明父声明的有效性。
    ///
    /// 防御移动：
    /// - 在游戏树中向右移动（更具体的位置）
    /// - 提出一个新的声明，支持父声明的有效性
    /// - 需要存入保证金
    /// - 更新时钟和子游戏结构
    ///
    /// 注意：不能对根声明进行防御（根声明只能被攻击）
    ///
    /// @param _disputed   正在被防御的声明
    /// @param _parentIndex 在 `claimData` 数组中要防御的声明索引，必须与 `_disputed` 匹配
    /// @param _claim      在相对防御位置的声明
    function defend(
        Claim _disputed,
        uint256 _parentIndex,
        Claim _claim
    ) external payable {
        // 调用通用移动函数，_isAttack = false 表示这是防御
        move(_disputed, _parentIndex, _claim, false);
    }

    /// @notice Posts the requested local data to the VM's `PreimageOralce`.
    /// @param _ident The local identifier of the data to post.
    /// @param _execLeafIdx The index of the leaf claim in an execution subgame that requires the local data for a step.
    /// @param _partOffset The offset of the data to post.
    function addLocalData(
        uint256 _ident,
        uint256 _execLeafIdx,
        uint256 _partOffset
    ) external {
        // INVARIANT: Local data can only be added if the game is currently in progress.
        if (status != GameStatus.IN_PROGRESS) revert GameNotInProgress();

        (
            Claim starting,
            Position startingPos,
            Claim disputed,
            Position disputedPos
        ) = _findStartingAndDisputedOutputs(_execLeafIdx);
        Hash uuid = _computeLocalContext(
            starting,
            startingPos,
            disputed,
            disputedPos
        );

        IPreimageOracle oracle = vm().oracle();
        if (_ident == LocalPreimageKey.L1_HEAD_HASH) {
            // Load the L1 head hash
            oracle.loadLocalData(
                _ident,
                uuid.raw(),
                l1Head().raw(),
                32,
                _partOffset
            );
        } else if (_ident == LocalPreimageKey.STARTING_OUTPUT_ROOT) {
            // Load the starting proposal's output root.
            oracle.loadLocalData(
                _ident,
                uuid.raw(),
                starting.raw(),
                32,
                _partOffset
            );
        } else if (_ident == LocalPreimageKey.DISPUTED_OUTPUT_ROOT) {
            // Load the disputed proposal's output root
            oracle.loadLocalData(
                _ident,
                uuid.raw(),
                disputed.raw(),
                32,
                _partOffset
            );
        } else if (_ident == LocalPreimageKey.DISPUTED_L2_BLOCK_NUMBER) {
            // Load the disputed proposal's L2 block number as a big-endian uint64 in the
            // high order 8 bytes of the word.

            // We add the index at depth + 1 to the starting block number to get the disputed L2
            // block number.
            uint256 l2Number = startingOutputRoot.l2SequenceNumber +
                disputedPos.traceIndex(SPLIT_DEPTH) +
                1;

            // Choose the minimum between the `l2BlockNumber` claim and the bisected-to L2 block number.
            l2Number = l2Number < l2BlockNumber() ? l2Number : l2BlockNumber();

            oracle.loadLocalData(
                _ident,
                uuid.raw(),
                bytes32(l2Number << 0xC0),
                8,
                _partOffset
            );
        } else if (_ident == LocalPreimageKey.CHAIN_ID) {
            // Load the chain ID as a big-endian uint64 in the high order 8 bytes of the word.
            oracle.loadLocalData(
                _ident,
                uuid.raw(),
                bytes32(l2ChainId() << 0xC0),
                8,
                _partOffset
            );
        } else {
            revert InvalidLocalIdent();
        }
    }

    /// @notice Returns the number of children that still need to be resolved in order to fully resolve a subgame rooted
    ///         at `_claimIndex`.
    /// @param _claimIndex The subgame root claim's index within `claimData`.
    /// @return numRemainingChildren_ The number of children that still need to be checked to resolve the subgame.
    function getNumToResolve(
        uint256 _claimIndex
    ) public view returns (uint256 numRemainingChildren_) {
        ResolutionCheckpoint storage checkpoint = resolutionCheckpoints[
            _claimIndex
        ];
        uint256[] storage challengeIndices = subgames[_claimIndex];
        uint256 challengeIndicesLen = challengeIndices.length;

        numRemainingChildren_ = challengeIndicesLen - checkpoint.subgameIndex;
    }

    /// @notice The l2BlockNumber of the disputed output root in the `L2OutputOracle`.
    function l2BlockNumber() public pure returns (uint256 l2BlockNumber_) {
        l2BlockNumber_ = _getArgUint256(88);
    }

    /// @notice The l2SequenceNumber of the disputed output root in the `L2OutputOracle` (in this case - block number).
    function l2SequenceNumber()
        public
        pure
        returns (uint256 l2SequenceNumber_)
    {
        l2SequenceNumber_ = l2BlockNumber();
    }

    /// @notice Only the starting block number of the game.
    function startingBlockNumber()
        external
        view
        returns (uint256 startingBlockNumber_)
    {
        startingBlockNumber_ = startingOutputRoot.l2SequenceNumber;
    }

    /// @notice Starting output root and block number of the game.
    function startingRootHash() external view returns (Hash startingRootHash_) {
        startingRootHash_ = startingOutputRoot.root;
    }

    /// @notice Challenges the root L2 block number by providing the preimage of the output root and the L2 block header
    ///         and showing that the committed L2 block number is incorrect relative to the claimed L2 block number.
    /// @param _outputRootProof The output root proof.
    /// @param _headerRLP The RLP-encoded L2 block header.
    function challengeRootL2Block(
        Types.OutputRootProof calldata _outputRootProof,
        bytes calldata _headerRLP
    ) external {
        // INVARIANT: Moves cannot be made unless the game is currently in progress.
        if (status != GameStatus.IN_PROGRESS) revert GameNotInProgress();

        // The root L2 block claim can only be challenged once.
        if (l2BlockNumberChallenged) revert L2BlockNumberChallenged();

        // Verify the output root preimage.
        if (Hashing.hashOutputRootProof(_outputRootProof) != rootClaim().raw())
            revert InvalidOutputRootProof();

        // Verify the block hash preimage.
        if (keccak256(_headerRLP) != _outputRootProof.latestBlockhash)
            revert InvalidHeaderRLP();

        // Decode the header RLP to find the number of the block. In the consensus encoding, the timestamp
        // is the 9th element in the list that represents the block header.
        RLPReader.RLPItem[] memory headerContents = RLPReader.readList(
            RLPReader.toRLPItem(_headerRLP)
        );
        bytes memory rawBlockNumber = RLPReader.readBytes(
            headerContents[HEADER_BLOCK_NUMBER_INDEX]
        );

        // Sanity check the block number string length.
        if (rawBlockNumber.length > 32) revert InvalidHeaderRLP();

        // Convert the raw, left-aligned block number to a uint256 by aligning it as a big-endian
        // number in the low-order bytes of a 32-byte word.
        //
        // SAFETY: The length of `rawBlockNumber` is checked above to ensure it is at most 32 bytes.
        uint256 blockNumber;
        assembly {
            blockNumber := shr(
                shl(0x03, sub(0x20, mload(rawBlockNumber))),
                mload(add(rawBlockNumber, 0x20))
            )
        }

        // Ensure the block number does not match the block number claimed in the dispute game.
        if (blockNumber == l2BlockNumber()) revert BlockNumberMatches();

        // Issue a special counter to the root claim. This counter will always win the root claim subgame, and receive
        // the bond from the root claimant.
        l2BlockNumberChallenger = msg.sender;
        l2BlockNumberChallenged = true;
    }

    ////////////////////////////////////////////////////////////////
    //                    `IDisputeGame` impl                     //
    ////////////////////////////////////////////////////////////////

    /// @notice 如果已收集所有必要信息，此函数应将游戏状态标记为 `CHALLENGER_WINS` 或 `DEFENDER_WINS`
    ///
    /// 这是争议游戏的最终阶段。在解决所有子游戏后，可以调用此函数来确定最终获胜者。
    ///
    /// 解决逻辑：
    /// 1. 检查游戏处于 IN_PROGRESS 状态
    /// 2. 检查根子游戏已被解决
    /// 3. 根据根声明是否被反驳确定获胜者：
    ///    - 如果根声明未被反驳（counteredBy == address(0)）：防御者获胜（状态根有效）
    ///    - 如果根声明被反驳：挑战者获胜（状态根无效）
    /// 4. 更新游戏状态和时间戳
    /// 5. 发出解决事件
    ///
    /// 保证金分配：
    /// - 获胜方获得失败方的保证金
    /// - 保证金分配在 resolveClaim 函数中处理
    ///
    /// @dev 只能在 `status` 为 `IN_PROGRESS` 时调用
    /// @return status_ 解决后的游戏状态
    function resolve() external returns (GameStatus status_) {
        // 不变量：只有在游戏进行中时才能解决
        if (status != GameStatus.IN_PROGRESS) revert GameNotInProgress();

        // 不变量：只有在绝对根子游戏已被解决时才能解决
        // 这确保我们自底向上解决游戏树
        if (!resolvedSubgames[0]) revert OutOfOrderResolution();

        // 更新全局游戏状态；争议已结束
        // 如果根声明未被反驳，防御者获胜；否则挑战者获胜
        status_ = claimData[0].counteredBy == address(0)
            ? GameStatus.DEFENDER_WINS
            : GameStatus.CHALLENGER_WINS;
        resolvedAt = Timestamp.wrap(uint64(block.timestamp));

        // 更新状态并发出解决事件
        // 注意：这里我们执行赋值操作
        emit Resolved(status = status_);
    }

    /// @notice Resolves the subgame rooted at the given claim index. `_numToResolve` specifies how many children of
    ///         the subgame will be checked in this call. If `_numToResolve` is less than the number of children, an
    ///         internal cursor will be updated and this function may be called again to complete resolution of the
    ///         subgame.
    /// @dev This function must be called bottom-up in the DAG
    ///      A subgame is a tree of claims that has a maximum depth of 1.
    ///      A subgame root claims is valid if, and only if, all of its child claims are invalid.
    ///      At the deepest level in the DAG, a claim is invalid if there's a successful step against it.
    /// @param _claimIndex The index of the subgame root claim to resolve.
    /// @param _numToResolve The number of subgames to resolve in this call. If the input is `0`, and this is the first
    ///                      page, this function will attempt to check all of the subgame's children at once.
    function resolveClaim(uint256 _claimIndex, uint256 _numToResolve) external {
        // INVARIANT: Resolution cannot occur unless the game is currently in progress.
        if (status != GameStatus.IN_PROGRESS) revert GameNotInProgress();

        ClaimData storage subgameRootClaim = claimData[_claimIndex];
        Duration challengeClockDuration = getChallengerDuration(_claimIndex);

        // INVARIANT: Cannot resolve a subgame unless the clock of its would-be counter has expired
        // INVARIANT: Assuming ordered subgame resolution, challengeClockDuration is always >= MAX_CLOCK_DURATION if all
        // descendant subgames are resolved
        if (challengeClockDuration.raw() < MAX_CLOCK_DURATION.raw())
            revert ClockNotExpired();

        // INVARIANT: Cannot resolve a subgame twice.
        if (resolvedSubgames[_claimIndex]) revert ClaimAlreadyResolved();

        uint256[] storage challengeIndices = subgames[_claimIndex];
        uint256 challengeIndicesLen = challengeIndices.length;

        // Uncontested claims are resolved implicitly unless they are the root claim. Pay out the bond to the claimant
        // and return early.
        if (challengeIndicesLen == 0 && _claimIndex != 0) {
            // In the event that the parent claim is at the max depth, there will always be 0 subgames. If the
            // `counteredBy` field is set and there are no subgames, this implies that the parent claim was successfully
            // stepped against. In this case, we pay out the bond to the party that stepped against the parent claim.
            // Otherwise, the parent claim is uncontested, and the bond is returned to the claimant.
            address counteredBy = subgameRootClaim.counteredBy;
            address recipient = counteredBy == address(0)
                ? subgameRootClaim.claimant
                : counteredBy;
            _distributeBond(recipient, subgameRootClaim);
            resolvedSubgames[_claimIndex] = true;
            return;
        }

        // Fetch the resolution checkpoint from storage.
        ResolutionCheckpoint memory checkpoint = resolutionCheckpoints[
            _claimIndex
        ];

        // If the checkpoint does not currently exist, initialize the current left most position as max u128.
        if (!checkpoint.initialCheckpointComplete) {
            checkpoint.leftmostPosition = Position.wrap(type(uint128).max);
            checkpoint.initialCheckpointComplete = true;

            // If `_numToResolve == 0`, assume that we can check all child subgames in this one callframe.
            if (_numToResolve == 0) _numToResolve = challengeIndicesLen;
        }

        // Assume parent is honest until proven otherwise
        uint256 lastToResolve = checkpoint.subgameIndex + _numToResolve;
        uint256 finalCursor = lastToResolve > challengeIndicesLen
            ? challengeIndicesLen
            : lastToResolve;
        for (uint256 i = checkpoint.subgameIndex; i < finalCursor; i++) {
            uint256 challengeIndex = challengeIndices[i];

            // INVARIANT: Cannot resolve a subgame containing an unresolved claim
            if (!resolvedSubgames[challengeIndex])
                revert OutOfOrderResolution();

            ClaimData storage claim = claimData[challengeIndex];

            // If the child subgame is uncountered and further left than the current left-most counter,
            // update the parent subgame's `countered` address and the current `leftmostCounter`.
            // The left-most correct counter is preferred in bond payouts in order to discourage attackers
            // from countering invalid subgame roots via an invalid defense position. As such positions
            // cannot be correctly countered.
            // Note that correctly positioned defense, but invalid claimes can still be successfully countered.
            if (
                claim.counteredBy == address(0) &&
                checkpoint.leftmostPosition.raw() > claim.position.raw()
            ) {
                checkpoint.counteredBy = claim.claimant;
                checkpoint.leftmostPosition = claim.position;
            }
        }

        // Increase the checkpoint's cursor position by the number of children that were checked.
        checkpoint.subgameIndex = uint32(finalCursor);

        // Persist the checkpoint and allow for continuing in a separate transaction, if resolution is not already
        // complete.
        resolutionCheckpoints[_claimIndex] = checkpoint;

        // If all children have been traversed in the above loop, the subgame may be resolved. Otherwise, persist the
        // checkpoint and allow for continuation in a separate transaction.
        if (checkpoint.subgameIndex == challengeIndicesLen) {
            address countered = checkpoint.counteredBy;

            // Mark the subgame as resolved.
            resolvedSubgames[_claimIndex] = true;

            // Distribute the bond to the appropriate party.
            if (_claimIndex == 0 && l2BlockNumberChallenged) {
                // Special case: If the root claim has been challenged with the `challengeRootL2Block` function,
                // the bond is always paid out to the issuer of that challenge.
                address challenger = l2BlockNumberChallenger;
                _distributeBond(challenger, subgameRootClaim);
                subgameRootClaim.counteredBy = challenger;
            } else {
                // If the parent was not successfully countered, pay out the parent's bond to the claimant.
                // If the parent was successfully countered, pay out the parent's bond to the challenger.
                _distributeBond(
                    countered == address(0)
                        ? subgameRootClaim.claimant
                        : countered,
                    subgameRootClaim
                );

                // Once a subgame is resolved, we percolate the result up the DAG so subsequent calls to
                // resolveClaim will not need to traverse this subgame.
                subgameRootClaim.counteredBy = countered;
            }
        }
    }

    /// @notice Getter for the creator of the dispute game.
    /// @dev `clones-with-immutable-args` argument #1
    /// @return creator_ The creator of the dispute game.
    function gameCreator() public pure returns (address creator_) {
        creator_ = _getArgAddress(0);
    }

    /// @notice Getter for the root claim.
    /// @dev `clones-with-immutable-args` argument #2
    /// @return rootClaim_ The root claim of the DisputeGame.
    function rootClaim() public pure returns (Claim rootClaim_) {
        rootClaim_ = Claim.wrap(_getArgBytes32(20));
    }

    /// @notice Getter for the root claim for a given L2 chain ID.
    /// @param _chainId The L2 chain ID to get the root claim for.
    /// @return rootClaim_ The root claim of the DisputeGame.
    function rootClaimByChainId(
        uint256 _chainId
    ) public pure returns (Claim rootClaim_) {
        if (_chainId != l2ChainId()) revert UnknownChainId();
        rootClaim_ = rootClaim();
    }

    /// @notice Getter for the parent hash of the L1 block when the dispute game was created.
    /// @dev `clones-with-immutable-args` argument #3
    /// @return l1Head_ The parent hash of the L1 block when the dispute game was created.
    function l1Head() public pure returns (Hash l1Head_) {
        l1Head_ = Hash.wrap(_getArgBytes32(52));
    }

    /// @notice Getter for the game type.
    /// @dev `clones-with-immutable-args` argument #4
    /// @return gameType_ The type of proof system being used.
    function gameType() public pure returns (GameType gameType_) {
        gameType_ = GameType.wrap(_getArgUint32(84));
    }

    /// @notice Getter for the extra data.
    /// @dev `clones-with-immutable-args` argument #5
    /// @return extraData_ Any extra data supplied to the dispute game contract by the creator.
    function extraData() public pure returns (bytes memory extraData_) {
        // The extra data starts at the second word within the cwia calldata and
        // is 32 bytes long.
        extraData_ = _getArgBytes(88, 32);
    }

    /// @notice Getter for the absolute prestate of the instruction trace.
    /// @dev `clones-with-immutable-args` argument #6
    /// @return absolutePrestate_ The absolute prestate of the instruction trace.
    function absolutePrestate() public pure returns (Claim absolutePrestate_) {
        absolutePrestate_ = Claim.wrap(_getArgBytes32(120));
    }

    /// @notice Getter for the VM implementation.
    /// @dev `clones-with-immutable-args` argument #7
    /// @return vm_ The onchain VM implementation address.
    function vm() public pure returns (IBigStepper vm_) {
        vm_ = IBigStepper(_getArgAddress(152));
    }

    /// @notice Getter for the anchor state registry.
    /// @dev `clones-with-immutable-args` argument #8
    /// @return registry_ The anchor state registry contract address.
    function anchorStateRegistry()
        public
        pure
        returns (IAnchorStateRegistry registry_)
    {
        registry_ = IAnchorStateRegistry(_getArgAddress(172));
    }

    /// @notice Getter for the WETH contract.
    /// @dev `clones-with-immutable-args` argument #9
    /// @return weth_ The WETH contract for holding ETH.
    function weth() public pure returns (IDelayedWETH weth_) {
        weth_ = IDelayedWETH(payable(_getArgAddress(192)));
    }

    /// @notice Getter for the L2 chain ID.
    /// @dev `clones-with-immutable-args` argument #10
    /// @return l2ChainId_ The L2 chain ID.
    function l2ChainId() public pure returns (uint256 l2ChainId_) {
        l2ChainId_ = _getArgUint256(212);
    }

    /// @notice A compliant implementation of this interface should return the components of the
    ///         game UUID's preimage provided in the cwia payload. The preimage of the UUID is
    ///         constructed as `keccak256(gameType . rootClaim . extraData)` where `.` denotes
    ///         concatenation.
    /// @return gameType_ The type of proof system being used.
    /// @return rootClaim_ The root claim of the DisputeGame.
    /// @return extraData_ Any extra data supplied to the dispute game contract by the creator.
    function gameData()
        external
        pure
        returns (GameType gameType_, Claim rootClaim_, bytes memory extraData_)
    {
        gameType_ = gameType();
        rootClaim_ = rootClaim();
        extraData_ = extraData();
    }

    ////////////////////////////////////////////////////////////////
    //                       MISC EXTERNAL                        //
    ////////////////////////////////////////////////////////////////

    /// @notice Returns the required bond for a given move kind.
    /// @param _position The position of the bonded interaction.
    /// @return requiredBond_ The required ETH bond for the given move, in wei.
    function getRequiredBond(
        Position _position
    ) public view returns (uint256 requiredBond_) {
        uint256 depth = uint256(_position.depth());
        if (depth > MAX_GAME_DEPTH) revert GameDepthExceeded();

        // Values taken from Big Bonds v1.5 (TM) spec.
        uint256 assumedBaseFee = 200 gwei;
        uint256 baseGasCharged = 400_000;
        uint256 highGasCharged = 300_000_000;

        // Goal here is to compute the fixed multiplier that will be applied to the base gas
        // charged to get the required gas amount for the given depth. We apply this multiplier
        // some `n` times where `n` is the depth of the position. We are looking for some number
        // that, when multiplied by itself `MAX_GAME_DEPTH` times and then multiplied by the base
        // gas charged, will give us the maximum gas that we want to charge.
        // We want to solve for (highGasCharged/baseGasCharged) ** (1/MAX_GAME_DEPTH).
        // We know that a ** (b/c) is equal to e ** (ln(a) * (b/c)).
        // We can compute e ** (ln(a) * (b/c)) quite easily with FixedPointMathLib.

        // Set up a, b, and c.
        uint256 a = highGasCharged / baseGasCharged;
        uint256 b = FixedPointMathLib.WAD;
        uint256 c = MAX_GAME_DEPTH * FixedPointMathLib.WAD;

        // Compute ln(a).
        // slither-disable-next-line divide-before-multiply
        uint256 lnA = uint256(
            FixedPointMathLib.lnWad(int256(a * FixedPointMathLib.WAD))
        );

        // Computes (b / c) with full precision using WAD = 1e18.
        uint256 bOverC = FixedPointMathLib.divWad(b, c);

        // Compute e ** (ln(a) * (b/c))
        // sMulWad can be used here since WAD = 1e18 maintains the same precision.
        uint256 numerator = FixedPointMathLib.mulWad(lnA, bOverC);
        int256 base = FixedPointMathLib.expWad(int256(numerator));

        // Compute the required gas amount.
        int256 rawGas = FixedPointMathLib.powWad(
            base,
            int256(depth * FixedPointMathLib.WAD)
        );
        uint256 requiredGas = FixedPointMathLib.mulWad(
            baseGasCharged,
            uint256(rawGas)
        );

        // Compute the required bond.
        requiredBond_ = assumedBaseFee * requiredGas;
    }

    /// @notice Claim the credit belonging to the recipient address. Reverts if the game isn't
    ///         finalized, if the recipient has no credit to claim, or if the bond transfer
    ///         fails. If the game is finalized but no bond has been paid out yet, this method
    ///         will determine the bond distribution mode and also try to update anchor game.
    /// @param _recipient The owner and recipient of the credit.
    function claimCredit(address _recipient) external {
        // Close out the game and determine the bond distribution mode if not already set.
        // We call this as part of claim credit to reduce the number of additional calls that a
        // Challenger needs to make to this contract.
        closeGame();

        // Fetch the recipient's credit balance based on the bond distribution mode.
        uint256 recipientCredit;
        if (bondDistributionMode == BondDistributionMode.REFUND) {
            recipientCredit = refundModeCredit[_recipient];
        } else if (bondDistributionMode == BondDistributionMode.NORMAL) {
            recipientCredit = normalModeCredit[_recipient];
        } else {
            // We shouldn't get here, but sanity check just in case.
            revert InvalidBondDistributionMode();
        }

        // If the game is in refund mode, and the recipient has not unlocked their refund mode
        // credit, we unlock it and return early.
        if (!hasUnlockedCredit[_recipient]) {
            hasUnlockedCredit[_recipient] = true;
            weth().unlock(_recipient, recipientCredit);
            return;
        }

        // Revert if the recipient has no credit to claim.
        if (recipientCredit == 0) revert NoCreditToClaim();

        // Set the recipient's credit balances to 0.
        refundModeCredit[_recipient] = 0;
        normalModeCredit[_recipient] = 0;

        // Try to withdraw the WETH amount so it can be used here.
        weth().withdraw(_recipient, recipientCredit);

        // Transfer the credit to the recipient.
        (bool success, ) = _recipient.call{value: recipientCredit}(hex"");
        if (!success) revert BondTransferFailed();
    }

    /// @notice Closes out the game, determines the bond distribution mode, attempts to register
    ///         the game as the anchor game, and emits an event.
    function closeGame() public {
        // If the bond distribution mode has already been determined, we can return early.
        if (
            bondDistributionMode == BondDistributionMode.REFUND ||
            bondDistributionMode == BondDistributionMode.NORMAL
        ) {
            // We can't revert or we'd break claimCredit().
            return;
        } else if (bondDistributionMode != BondDistributionMode.UNDECIDED) {
            // We shouldn't get here, but sanity check just in case.
            revert InvalidBondDistributionMode();
        }

        // We won't close the game if the system is currently paused. Paused games are temporarily
        // invalid which would cause the game to go into refund mode and potentially cause some
        // confusion for honest challengers. By blocking the game from being closed while the
        // system is paused, the game will only go into refund mode if it ends up being explicitly
        // invalidated in the AnchorStateRegistry. If the game has already been closed and a refund
        // mode has been selected, we'll already have returned and we won't hit this revert.
        if (anchorStateRegistry().paused()) {
            revert GamePaused();
        }

        // Make sure that the game is resolved.
        // AnchorStateRegistry should be checking this but we're being defensive here.
        if (resolvedAt.raw() == 0) {
            revert GameNotResolved();
        }

        // Game must be finalized according to the AnchorStateRegistry.
        bool finalized = anchorStateRegistry().isGameFinalized(
            IDisputeGame(address(this))
        );
        if (!finalized) {
            revert GameNotFinalized();
        }

        // Try to update the anchor game first. Won't always succeed because delays can lead
        // to situations in which this game might not be eligible to be a new anchor game.
        // eip150-safe
        try
            anchorStateRegistry().setAnchorState(IDisputeGame(address(this)))
        {} catch {}
        // Check if the game is a proper game, which will determine the bond distribution mode.
        bool properGame = anchorStateRegistry().isGameProper(
            IDisputeGame(address(this))
        );

        // If the game is a proper game, the bonds should be distributed normally. Otherwise, go
        // into refund mode and distribute bonds back to their original depositors.
        if (properGame) {
            bondDistributionMode = BondDistributionMode.NORMAL;
        } else {
            bondDistributionMode = BondDistributionMode.REFUND;
        }

        // Emit an event to signal that the game has been closed.
        emit GameClosed(bondDistributionMode);
    }

    /// @notice Returns the amount of time elapsed on the potential challenger to `_claimIndex`'s chess clock. Maxes
    ///         out at `MAX_CLOCK_DURATION`.
    /// @param _claimIndex The index of the subgame root claim.
    /// @return duration_ The time elapsed on the potential challenger to `_claimIndex`'s chess clock.
    function getChallengerDuration(
        uint256 _claimIndex
    ) public view returns (Duration duration_) {
        // INVARIANT: The game must be in progress to query the remaining time to respond to a given claim.
        if (status != GameStatus.IN_PROGRESS) {
            revert GameNotInProgress();
        }

        // Fetch the subgame root claim.
        ClaimData storage subgameRootClaim = claimData[_claimIndex];

        // Fetch the parent of the subgame root's clock, if it exists.
        Clock parentClock;
        if (subgameRootClaim.parentIndex != type(uint32).max) {
            parentClock = claimData[subgameRootClaim.parentIndex].clock;
        }

        // Compute the duration elapsed of the potential challenger's clock.
        uint64 challengeDuration = uint64(
            parentClock.duration().raw() +
                (block.timestamp - subgameRootClaim.clock.timestamp().raw())
        );
        duration_ = challengeDuration > MAX_CLOCK_DURATION.raw()
            ? MAX_CLOCK_DURATION
            : Duration.wrap(challengeDuration);
    }

    /// @notice Returns the length of the `claimData` array.
    function claimDataLen() external view returns (uint256 len_) {
        len_ = claimData.length;
    }

    /// @notice Returns the credit balance of a given recipient.
    /// @param _recipient The recipient of the credit.
    /// @return credit_ The credit balance of the recipient.
    function credit(
        address _recipient
    ) external view returns (uint256 credit_) {
        if (bondDistributionMode == BondDistributionMode.REFUND) {
            credit_ = refundModeCredit[_recipient];
        } else {
            // Always return normal credit balance by default unless we're in refund mode.
            credit_ = normalModeCredit[_recipient];
        }
    }

    ////////////////////////////////////////////////////////////////
    //                     IMMUTABLE GETTERS                      //
    ////////////////////////////////////////////////////////////////

    /// @notice Returns the max game depth.
    function maxGameDepth() external view returns (uint256 maxGameDepth_) {
        maxGameDepth_ = MAX_GAME_DEPTH;
    }

    /// @notice Returns the split depth.
    function splitDepth() external view returns (uint256 splitDepth_) {
        splitDepth_ = SPLIT_DEPTH;
    }

    /// @notice Returns the max clock duration.
    function maxClockDuration()
        external
        view
        returns (Duration maxClockDuration_)
    {
        maxClockDuration_ = MAX_CLOCK_DURATION;
    }

    /// @notice Returns the clock extension constant.
    function clockExtension() external view returns (Duration clockExtension_) {
        clockExtension_ = CLOCK_EXTENSION;
    }

    ////////////////////////////////////////////////////////////////
    //                          HELPERS                           //
    ////////////////////////////////////////////////////////////////

    /// @notice Pays out the bond of a claim to a given recipient.
    /// @param _recipient The recipient of the bond.
    /// @param _bonded The claim to pay out the bond of.
    function _distributeBond(
        address _recipient,
        ClaimData storage _bonded
    ) internal {
        normalModeCredit[_recipient] += _bonded.bond;
    }

    /// @notice Verifies the integrity of an execution bisection subgame's root claim. Reverts if the claim
    ///         is invalid.
    /// @param _rootClaim The root claim of the execution bisection subgame.
    function _verifyExecBisectionRoot(
        Claim _rootClaim,
        uint256 _parentIdx,
        Position _parentPos,
        bool _isAttack
    ) internal view {
        // The root claim of an execution trace bisection sub-game must:
        // 1. Signal that the VM panicked or resulted in an invalid transition if the disputed output root
        //    was made by the opposing party.
        // 2. Signal that the VM resulted in a valid transition if the disputed output root was made by the same party.

        // If the move is a defense, the disputed output could have been made by either party. In this case, we
        // need to search for the parent output to determine what the expected status byte should be.
        Position disputedLeafPos = Position.wrap(_parentPos.raw() + 1);
        ClaimData storage disputed = _findTraceAncestor({
            _pos: disputedLeafPos,
            _start: _parentIdx,
            _global: true
        });
        uint8 vmStatus = uint8(_rootClaim.raw()[0]);

        if (_isAttack || disputed.position.depth() % 2 == SPLIT_DEPTH % 2) {
            // If the move is an attack, the parent output is always deemed to be disputed. In this case, we only need
            // to check that the root claim signals that the VM panicked or resulted in an invalid transition.
            // If the move is a defense, and the disputed output and creator of the execution trace subgame disagree,
            // the root claim should also signal that the VM panicked or resulted in an invalid transition.
            if (
                !(vmStatus == VMStatuses.INVALID.raw() ||
                    vmStatus == VMStatuses.PANIC.raw())
            ) {
                revert UnexpectedRootClaim(_rootClaim);
            }
        } else if (vmStatus != VMStatuses.VALID.raw()) {
            // The disputed output and the creator of the execution trace subgame agree. The status byte should
            // have signaled that the VM succeeded.
            revert UnexpectedRootClaim(_rootClaim);
        }
    }

    /// @notice Finds the trace ancestor of a given position within the DAG.
    /// @param _pos The position to find the trace ancestor claim of.
    /// @param _start The index to start searching from.
    /// @param _global Whether or not to search the entire dag or just within an execution trace subgame. If set to
    ///                `true`, and `_pos` is at or above the split depth, this function will revert.
    /// @return ancestor_ The ancestor claim that commits to the same trace index as `_pos`.
    function _findTraceAncestor(
        Position _pos,
        uint256 _start,
        bool _global
    ) internal view returns (ClaimData storage ancestor_) {
        // Grab the trace ancestor's expected position.
        Position traceAncestorPos = _global
            ? _pos.traceAncestor()
            : _pos.traceAncestorBounded(SPLIT_DEPTH);

        // Walk up the DAG to find a claim that commits to the same trace index as `_pos`. It is
        // guaranteed that such a claim exists.
        ancestor_ = claimData[_start];
        while (ancestor_.position.raw() != traceAncestorPos.raw()) {
            ancestor_ = claimData[ancestor_.parentIndex];
        }
    }

    /// @notice Finds the starting and disputed output root for a given `ClaimData` within the DAG. This
    ///         `ClaimData` must be below the `SPLIT_DEPTH`.
    /// @param _start The index within `claimData` of the claim to start searching from.
    /// @return startingClaim_ The starting output root claim.
    /// @return startingPos_ The starting output root position.
    /// @return disputedClaim_ The disputed output root claim.
    /// @return disputedPos_ The disputed output root position.
    function _findStartingAndDisputedOutputs(
        uint256 _start
    )
        internal
        view
        returns (
            Claim startingClaim_,
            Position startingPos_,
            Claim disputedClaim_,
            Position disputedPos_
        )
    {
        // Fatch the starting claim.
        uint256 claimIdx = _start;
        ClaimData storage claim = claimData[claimIdx];

        // If the starting claim's depth is less than or equal to the split depth, we revert as this is UB.
        if (claim.position.depth() <= SPLIT_DEPTH) revert ClaimAboveSplit();

        // We want to:
        // 1. Find the first claim at the split depth.
        // 2. Determine whether it was the starting or disputed output for the exec game.
        // 3. Find the complimentary claim depending on the info from #2 (pre or post).

        // Walk up the DAG until the ancestor's depth is equal to the split depth.
        uint256 currentDepth;
        ClaimData storage execRootClaim = claim;
        while ((currentDepth = claim.position.depth()) > SPLIT_DEPTH) {
            uint256 parentIndex = claim.parentIndex;

            // If we're currently at the split depth + 1, we're at the root of the execution sub-game.
            // We need to keep track of the root claim here to determine whether the execution sub-game was
            // started with an attack or defense against the output leaf claim.
            if (currentDepth == SPLIT_DEPTH + 1) execRootClaim = claim;

            claim = claimData[parentIndex];
            claimIdx = parentIndex;
        }

        // Determine whether the start of the execution sub-game was an attack or defense to the output root
        // above. This is important because it determines which claim is the starting output root and which
        // is the disputed output root.
        (Position execRootPos, Position outputPos) = (
            execRootClaim.position,
            claim.position
        );
        bool wasAttack = execRootPos.parent().raw() == outputPos.raw();

        // Determine the starting and disputed output root indices.
        // 1. If it was an attack, the disputed output root is `claim`, and the starting output root is
        //    elsewhere in the DAG (it must commit to the block # index at depth of `outputPos - 1`).
        // 2. If it was a defense, the starting output root is `claim`, and the disputed output root is
        //    elsewhere in the DAG (it must commit to the block # index at depth of `outputPos + 1`).
        if (wasAttack) {
            // If this is an attack on the first output root (the block directly after the starting
            // block number), the starting claim nor position exists in the tree. We leave these as
            // 0, which can be easily identified due to 0 being an invalid Gindex.
            if (outputPos.indexAtDepth() > 0) {
                ClaimData storage starting = _findTraceAncestor(
                    Position.wrap(outputPos.raw() - 1),
                    claimIdx,
                    true
                );
                (startingClaim_, startingPos_) = (
                    starting.claim,
                    starting.position
                );
            } else {
                startingClaim_ = Claim.wrap(startingOutputRoot.root.raw());
            }
            (disputedClaim_, disputedPos_) = (claim.claim, claim.position);
        } else {
            ClaimData storage disputed = _findTraceAncestor(
                Position.wrap(outputPos.raw() + 1),
                claimIdx,
                true
            );
            (startingClaim_, startingPos_) = (claim.claim, claim.position);
            (disputedClaim_, disputedPos_) = (
                disputed.claim,
                disputed.position
            );
        }
    }

    /// @notice Finds the local context hash for a given claim index that is present in an execution trace subgame.
    /// @param _claimIndex The index of the claim to find the local context hash for.
    /// @return uuid_ The local context hash.
    function _findLocalContext(
        uint256 _claimIndex
    ) internal view returns (Hash uuid_) {
        (
            Claim starting,
            Position startingPos,
            Claim disputed,
            Position disputedPos
        ) = _findStartingAndDisputedOutputs(_claimIndex);
        uuid_ = _computeLocalContext(
            starting,
            startingPos,
            disputed,
            disputedPos
        );
    }

    /// @notice Computes the local context hash for a set of starting/disputed claim values and positions.
    /// @param _starting The starting claim.
    /// @param _startingPos The starting claim's position.
    /// @param _disputed The disputed claim.
    /// @param _disputedPos The disputed claim's position.
    /// @return uuid_ The local context hash.
    function _computeLocalContext(
        Claim _starting,
        Position _startingPos,
        Claim _disputed,
        Position _disputedPos
    ) internal pure returns (Hash uuid_) {
        // A position of 0 indicates that the starting claim is the absolute prestate. In this special case,
        // we do not include the starting claim within the local context hash.
        uuid_ = _startingPos.raw() == 0
            ? Hash.wrap(keccak256(abi.encode(_disputed, _disputedPos)))
            : Hash.wrap(
                keccak256(
                    abi.encode(_starting, _startingPos, _disputed, _disputedPos)
                )
            );
    }
}
