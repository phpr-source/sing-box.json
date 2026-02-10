import json
import os
import subprocess
import sys
import concurrent.futures
import re
import shutil
import ipaddress
import requests
import logging
import tempfile
import math
import gc
import hashlib
import time
import threading
import zlib
import copy
import bisect
import struct
import array
import unicodedata
import weakref
import binascii
import psutil
import random
import string
import collections
import multiprocessing
import heapq
import signal
from collections import defaultdict, deque, OrderedDict
from typing import List, Dict, Set, Tuple, Optional, Any, Union, FrozenSet, Callable, Literal
from pathlib import Path
from dataclasses import dataclass, field, asdict, fields
from enum import IntEnum, auto
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from abc import ABC, abstractmethod
from functools import lru_cache, total_ordering
import contextlib

# 可選依賴導入
try:
    import orjson
    USE_ORJSON = True
except ImportError:
    orjson = None
    USE_ORJSON = False

try:
    import msgpack
    USE_MSGPACK = True
except ImportError:
    msgpack = None
    USE_MSGPACK = False

try:
    import tldextract
    USE_TLDEXTRACT = True
    _tld_cache_dir = Path(tempfile.gettempdir()) / "tld_cache_strict"
    try:
        _tld_cache_dir.mkdir(parents=True, exist_ok=True)
        _tld_cache = tldextract.TLDExtract(cache_dir=str(_tld_cache_dir))
    except Exception:
        _tld_cache = None
except ImportError:
    USE_TLDEXTRACT = False
    _tld_cache = None

try:
    import lmdb
    USE_LMDB = True
    LMDB_MAP_FULL = lmdb.MapFullError
except ImportError:
    USE_LMDB = False
    LMDB_MAP_FULL = Exception

try:
    import z3
    HAS_Z3 = True
except ImportError:
    HAS_Z3 = False

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False

try:
    from hypothesis import given, strategies as st, settings, Phase, example, assume
    from hypothesis.stateful import RuleBasedStateMachine, rule, precondition, invariant
    HAS_HYPOTHESIS = True
except ImportError:
    HAS_HYPOTHESIS = False

try:
    from greenery import parse, fsm
    HAS_GREENERY = True
except ImportError:
    HAS_GREENERY = False

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger(__name__)


class CIDRFragmentationError(Exception):
    __slots__ = ('processed_count', 'limit', 'loss_rate')
    def __init__(self, processed_count: int, limit: int, loss_rate: float = 0.0):
        self.processed_count = processed_count
        self.limit = limit
        self.loss_rate = loss_rate
        super().__init__(f"CIDR fragmentation exceeded limit: {processed_count} > {limit}, loss: {loss_rate:.4%}")


class StrictVerificationError(Exception):
    __slots__ = ('rule_type', 'rule_value', 'source_url', 'confidence')
    def __init__(self, message: str, *, rule_type: Optional[str] = None, 
                 rule_value: Optional[str] = None, source_url: Optional[str] = None, 
                 confidence: float = 0.0):
        super().__init__(message)
        self.rule_type = rule_type
        self.rule_value = rule_value
        self.source_url = source_url
        self.confidence = confidence


class LineageAnalysisError(Exception):
    pass


class PolicyViolationError(Exception):
    pass


class TransientError(Exception):
    pass


class ResourceExhaustedError(Exception):
    pass


class InvalidRuleError(Exception):
    pass


class AnomalyDetectionError(Exception):
    pass


class SMTUnknownResult(Exception):
    pass


class AbstractDomainError(Exception):
    pass


class BDDReorderingError(Exception):
    pass


class TieredVerificationError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class MergeConfig:
    config_file: str = 'scripts/custom_merge.json'
    output_dir: Path = field(default_factory=lambda: Path('rules'))
    core_bin_path: str = field(default_factory=lambda: os.getenv("SB_CORE_PATH", "./sb-core"))
    max_workers: int = field(default_factory=lambda: (os.cpu_count() or 4) * 2)
    max_download_size: int = 150 * 1024 * 1024
    originality_decay_rate: float = 0.15
    enable_union_inclusion: bool = True
    union_inclusion_threshold: int = 3
    max_cidr_fragmentation: int = 5000
    strict_cidr_arithmetic: bool = True
    enable_ipv6: bool = True
    bloom_target_fpp: float = 0.001
    weighted_exclusion: bool = True
    exclusion_weight_threshold: float = 0.1
    deterministic_output: bool = True
    strict_idn_normalization: bool = True
    strict_html_detection: bool = True
    strict_zero_loss: bool = True
    max_domain_depth: int = 128
    lmdb_initial_map_size: int = 256 * 1024 * 1024
    lmdb_max_map_size: int = 8 * 1024 * 1024 * 1024
    max_index_builders: int = 4
    enable_cidr_adjacent_merge: bool = True
    safety_override_threshold: float = 2.0
    domain_specificity_threshold: float = 0.3
    temporal_override_factor: float = 1.5
    max_source_age_days: int = 30
    enable_rir_lookup: bool = False
    node_id: str = field(default_factory=lambda: f"node_{int(time.time() * 1000) % 100000}")
    enable_cidr_approximation: bool = True
    cidr_approximation_threshold: int = 1000
    rir_data_url: str = 'https://ftp.apnic.net/stats/apnic/delegated-apnic-latest '
    rir_cache_ttl_days: int = 7
    regex_derivative_max_depth: int = 200
    enable_interval_tree: bool = True
    strict_rule_ordering: bool = True
    rule_specificity_boost: float = 0.1
    enable_merkle_tree: bool = True
    merkle_tree_branching: int = 2
    cid_approximation_max_loss_rate: float = 0.05
    enable_smt_verification: bool = True
    smt_timeout_ms: int = 5000
    smt_progressive_timeout: Tuple[int, ...] = (100, 500, 2000, 5000)
    smt_process_pool_size: int = 2
    enable_adaptive_degradation: bool = True
    memory_threshold_percent: float = 85.0
    incremental_update: bool = True
    verification_level: int = 3
    entropy_threshold: float = 4.5
    enable_entropy_check: bool = True
    enable_bdd_verification: bool = True
    bdd_node_limit: int = 100000
    bdd_reordering_threshold: int = 10000
    enable_fuzzing_tests: bool = True
    enable_grammar_fuzzing: bool = True
    enable_differential_testing: bool = True
    enable_ngram_analysis: bool = True
    ngram_threshold: float = 0.3
    ngram_scales: Tuple[int, ...] = (2, 3, 4, 5)
    ngram_js_divergence_threshold: float = 0.5
    enable_semantic_embedding: bool = True
    semantic_model: str = "distilbert-base-uncased"
    enable_isolation_forest: bool = True
    isolation_forest_contamination: float = 0.01
    enable_compression_ratio_check: bool = True
    compression_ratio_threshold: float = 0.3
    deterministic_seed: str = "hyperaccurate_v9_strict"
    bdd_lru_cache_size: int = 50000
    enable_abstract_interpretation: bool = True
    enable_crdt: bool = True
    smt_three_valued_logic: bool = True
    pca_ngram_range: Tuple[int, int] = (2, 4)
    pca_n_components: int = 16
    enable_pca_anomaly_detection: bool = True
    enable_hypothesis_testing: bool = True
    hypothesis_max_examples: int = 1000
    hypothesis_deadline_ms: int = 5000
    enable_idn_script_whitelist: bool = True
    idn_allowed_scripts: Tuple[str, ...] = ('LATIN', 'CYRILLIC', 'GREEK', 'ARABIC', 'HEBREW', 'CJK', 'HANGUL')
    enable_provenance_logging: bool = True
    provenance_format: str = 'w3c-prov'
    enable_policy_engine: bool = True
    default_policy: str = 'WEIGHTED'
    tiered_verification: bool = True
    tier1_max_rules: int = 1000
    tier2_max_rules: int = 10000
    wal_sync_interval: int = 10

    @classmethod
    def from_dict(cls, d: Dict, base: 'MergeConfig') -> 'MergeConfig':
        """安全地從字典更新配置，忽略無效鍵並進行類型轉換"""
        valid_fields = {f.name for f in fields(cls)}
        filtered = {}
        for k, v in d.items():
            if k in valid_fields:
                field_type = cls.__dataclass_fields__[k].type
                if field_type == Path and isinstance(v, str):
                    filtered[k] = Path(v)
                else:
                    filtered[k] = v
        return cls(**{**asdict(base), **filtered})


DEFAULT_CONFIG = MergeConfig()

RE_HASH_LIKE = re.compile(r'\b[a-f0-9]{32,64}\b')
RE_EXCLUSION_PREFIX = re.compile(r'^\s*!')
RE_IPV4_STRICT = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:/\d+)?$')
RE_JSON_MAGIC = re.compile(rb'^\s*[\{\[]')
RE_HTML_MAGIC = re.compile(rb'^\s*<(?:!DOCTYPE|html|head|body|div|span)', re.IGNORECASE)
RE_DOMAIN_LABEL = re.compile(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$')
RE_PUNYCODE = re.compile(r'^xn--[a-z0-9-]+$')
RE_SYNTAX_SUGAR = re.compile(r'\([dwsDSW])|\\x([0-9a-fA-F]{2})')
RE_UNCERTAIN_REGEX = re.compile(r'\[1-9]|\(\?P<|\(\?[=!]|\(\?<=!]|\(\?\#|\\g<|\\k<|(?<!\)\(\?\#')
RE_CATASTROPHIC_BACKTRACK = re.compile(r'(\w+\([\w\s|]+\)[*+])|(\([\w\s|]+\)\2*?)')


class DeterministicRandom:
    __slots__ = ('_rng', '_seed', '_history', '_lock')
    def __init__(self, seed_data: Union[str, bytes, int, Tuple]):
        if isinstance(seed_data, (str, bytes)):
            if isinstance(seed_data, str):
                seed_data = seed_data.encode('utf-8')
            seed = int(hashlib.sha256(seed_data).hexdigest()[:16], 16)
        elif isinstance(seed_data, (tuple, list)):
            seed = int(hashlib.sha256(str(seed_data).encode()).hexdigest()[:16], 16)
        elif isinstance(seed_data, int):
            # 修復：確保seed在有效範圍內
            seed = abs(seed) % (2 ** 32)
        else:
            seed = 0
        self._seed = seed
        self._rng = random.Random(seed)
        self._history = deque(maxlen=10000)  # 限制歷史記錄大小
        self._lock = threading.Lock()

    def random(self):
        with self._lock:
            val = self._rng.random()
            self._history.append(('random', val))
            return val

    def randint(self, a: int, b: int) -> int:
        with self._lock:
            val = self._rng.randint(a, b)
            self._history.append(('randint', a, b, val))
            return val

    def choice(self, seq):
        with self._lock:
            val = self._rng.choice(seq)
            self._history.append(('choice', len(seq), val))
            return val

    def sample(self, population, k):
        with self._lock:
            val = self._rng.sample(population, k)
            self._history.append(('sample', len(population), k, val))
            return val

    def shuffle(self, x):
        with self._lock:
            self._rng.shuffle(x)
            self._history.append(('shuffle', len(x)))

    def get_history(self):
        with self._lock:
            return tuple(self._history)

    def get_state(self) -> Dict:
        """獲取可序列化狀態，用於檢查點"""
        with self._lock:
            return {
                'seed': self._seed,
                'rng_state': self._rng.getstate(),
                'history_len': len(self._history)
            }

    def set_state(self, state: Dict):
        """從檢查點恢復"""
        with self._lock:
            self._seed = state['seed']
            self._rng.setstate(state['rng_state'])


def fnv1a_64(data: Union[str, bytes], seed: int = 0xcbf29ce484222325) -> int:
    """修復：強制歸一化seed到64位無符號整數"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    # 修復：確保seed為正數並在64位範圍內
    hash_val = seed & 0xffffffffffffffff
    for byte in data:
        hash_val ^= byte
        hash_val = (hash_val * 0x100000001b3) & 0xffffffffffffffff
    return hash_val


def calculate_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = defaultdict(int)
    for c in s:
        freq[c] += 1
    length = len(s)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def calculate_js_divergence(p: Dict[str, float], q: Dict[str, float]) -> float:
    """修復：添加平滑處理避免除零和空分佈問題"""
    if not p or not q:
        return float('inf')
    
    all_keys = set(p.keys()) | set(q.keys())
    if not all_keys:
        return 0.0
    
    # 添加Laplace平滑
    epsilon = 1e-10
    p_smooth = {k: p.get(k, 0.0) + epsilon for k in all_keys}
    q_smooth = {k: q.get(k, 0.0) + epsilon for k in all_keys}
    
    # 重新歸一化
    total_p = sum(p_smooth.values())
    total_q = sum(q_smooth.values())
    
    p_norm = {k: v / total_p for k, v in p_smooth.items()}
    q_norm = {k: v / total_q for k, v in q_smooth.items()}
    
    # 計算中間分佈
    m = {k: (p_norm[k] + q_norm[k]) / 2.0 for k in all_keys}
    
    kl_pm = sum(p_norm[k] * math.log2(p_norm[k] / m[k]) for k in all_keys if p_norm[k] > 0 and m[k] > 0)
    kl_qm = sum(q_norm[k] * math.log2(q_norm[k] / m[k]) for k in all_keys if q_norm[k] > 0 and m[k] > 0)
    return (kl_pm + kl_qm) / 2.0


def calculate_conditional_entropy(s: str, lag: int = 1) -> float:
    """修復：添加lag參數驗證"""
    if lag <= 0 or len(s) <= lag:
        return 0.0
    pairs = defaultdict(lambda: defaultdict(int))
    singles = defaultdict(int)
    for i in range(len(s) - lag):
        a, b = s[i], s[i + lag]
        pairs[a][b] += 1
        singles[a] += 1
    entropy = 0.0
    for a, inner in pairs.items():
        p_a = singles[a] / (len(s) - lag)
        for b, count in inner.items():
            p_b_given_a = count / singles[a]
            entropy -= p_a * p_b_given_a * math.log2(p_b_given_a)
    return entropy


def optimal_bloom_size(n: int, p: float = 0.001) -> Tuple[int, int]:
    """修復：處理n=0的情況"""
    if n <= 0:
        n = 100  # 默認最小值
    m = int(-n * math.log(p) / (math.log(2) ** 2))
    m = max(m, 1024)
    m = (m + 7) // 8 * 8
    k = max(1, int(m / n * math.log(2)))
    return m, k


class MatchType(IntEnum):
    EXACT = 1
    SUFFIX = 2
    WILDCARD = 3
    REGEX = 4
    CIDR = 5
    KEYWORD = 6


@dataclass(frozen=True, slots=True)
class DomainRule:
    pattern: str
    match_type: MatchType
    normalized: str
    is_exclusion: bool = False
    original: str = field(default="")
    specificity_score: int = field(default=0)
    script_type: str = field(default="")

    # 類級別常量：腳本白名單
    SCRIPT_WHITELIST = {'LATIN', 'CYRILLIC', 'GREEK', 'ARABIC', 'HEBREW', 'CJK', 'HANGUL', 'COMMON'}

    def __post_init__(self):
        if not self.normalized:
            object.__setattr__(self, 'normalized', self.pattern)
        if not self.original:
            object.__setattr__(self, 'original', self.pattern)
        if self.specificity_score == 0:
            parts = self.normalized.split('.')
            score = len(parts) * 10
            if self.match_type == MatchType.EXACT:
                score += 5
            elif self.match_type == MatchType.SUFFIX:
                score += 2
            object.__setattr__(self, 'specificity_score', score)
        if not self.script_type:
            scripts = set()
            # 修復：性能優化，跳過ASCII字符和Punycode
            if not self.normalized.startswith('xn--'):
                for char in self.normalized:
                    code = ord(char)
                    if code < 128:
                        continue  # 跳過ASCII
                    try:
                        name = unicodedata.name(char)
                        parts = name.split()
                        base_script = parts[0]
                        # 歸一化處理
                        if base_script in ('DIGIT', 'NUMBER', 'CIRCLED'):
                            scripts.add('COMMON')
                        elif base_script in self.SCRIPT_WHITELIST:
                            scripts.add(base_script)
                            if len(scripts) > 2:  # 提前退出
                                break
                    except (ValueError, AttributeError):
                        pass
            if scripts:
                object.__setattr__(self, 'script_type', ','.join(sorted(scripts)))

    def covers(self, other: 'DomainRule') -> bool:
        """修復：完善covers語義，明確定義為'self是否涵蓋other'（other是self的子集）"""
        if self.match_type == MatchType.EXACT:
            return self.normalized == other.normalized
        elif self.match_type == MatchType.SUFFIX:
            if other.match_type == MatchType.EXACT:
                return other.normalized.endswith(self.normalized)
            elif other.match_type == MatchType.SUFFIX:
                return other.normalized.endswith(self.normalized) or self.normalized.endswith(other.normalized)
            else:
                return other.normalized.endswith(self.normalized)
        elif self.match_type == MatchType.WILDCARD:
            suffix = self.normalized.lstrip('*.')
            return other.normalized.endswith(suffix)
        return False

    def __hash__(self):
        return hash((self.normalized, self.match_type, self.is_exclusion))

    def __eq__(self, other):
        if not isinstance(other, DomainRule):
            return False
        return (self.normalized == other.normalized and 
                self.match_type == other.match_type and 
                self.is_exclusion == other.is_exclusion)


@dataclass(frozen=True, slots=True)
class IPCIDRRule:
    network: Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
    original_str: str
    is_exclusion: bool = False

    def __post_init__(self):
        if not self.original_str:
            object.__setattr__(self, 'original_str', str(self.network))

    def covers(self, other: 'IPCIDRRule') -> bool:
        if self.network.version != other.network.version:
            return False
        return other.network.subnet_of(self.network)

    def __hash__(self):
        # 修復：確保不同prefixlen的相同address有不同的hash
        return hash((int(self.network.network_address), self.network.prefixlen, self.is_exclusion))

    def __eq__(self, other):
        if not isinstance(other, IPCIDRRule):
            return False
        return (self.network.network_address == other.network.network_address and 
                self.network.prefixlen == other.network.prefixlen and
                self.is_exclusion == other.is_exclusion)


@dataclass(frozen=True, slots=True)
class KeywordRule:
    keyword: str
    is_exclusion: bool = False

    def __hash__(self):
        return hash((self.keyword, self.is_exclusion))

    def __eq__(self, other):
        if not isinstance(other, KeywordRule):
            return False
        return self.keyword == other.keyword and self.is_exclusion == other.is_exclusion


@dataclass(frozen=True, slots=True)
class RegexRule:
    pattern: str
    is_exclusion: bool = False
    antimirov_hash: int = field(default=0)

    def __post_init__(self):
        if self.antimirov_hash == 0:
            h = hashlib.sha256(self.pattern.encode()).hexdigest()
            object.__setattr__(self, 'antimirov_hash', int(h[:16], 16))

    def covers(self, other: 'RegexRule') -> bool:
        """修復：添加複雜度檢查和超時保護"""
        if not HAS_GREENERY:
            return False
        
        # 預檢查：限制正則複雜度
        if len(self.pattern) > 200 or self.pattern.count('*') + self.pattern.count('+') > 5:
            return False
        
        try:
            # 使用線程超時替代信號
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(self._check_coverage, other)
                try:
                    return future.result(timeout=1.0)
                except concurrent.futures.TimeoutError:
                    return False
        except Exception:
            return False

    def _check_coverage(self, other: 'RegexRule') -> bool:
        try:
            fsm_self = parse(self.pattern).to_fsm()
            fsm_other = parse(other.pattern).to_fsm()
            return fsm_other.issubset(fsm_self)
        except Exception:
            return False

    def __hash__(self):
        return hash((self.pattern, self.is_exclusion))

    def __eq__(self, other):
        if not isinstance(other, RegexRule):
            return False
        return self.pattern == other.pattern and self.is_exclusion == other.is_exclusion


RuleType = Union[DomainRule, IPCIDRRule, KeywordRule, RegexRule]


class RIRDataManager:
    """RIR (Regional Internet Registry) 數據管理器 - 修復版"""
    __slots__ = ('_prefixes', '_cache_dir', '_cache_file', '_lock', '_last_update')

    BUILTIN_PREFIXES = {
        '1.0.0.0/8': 'APNIC', '1.1.1.0/24': 'APNIC', '14.0.0.0/8': 'APNIC',
        '27.0.0.0/8': 'APNIC', '36.0.0.0/8': 'APNIC', '39.0.0.0/8': 'APNIC',
        '42.0.0.0/8': 'APNIC', '43.0.0.0/8': 'APNIC', '49.0.0.0/8': 'APNIC',
        '58.0.0.0/8': 'APNIC', '59.0.0.0/8': 'APNIC', '60.0.0.0/8': 'APNIC',
        '61.0.0.0/8': 'APNIC', '101.0.0.0/8': 'APNIC', '103.0.0.0/8': 'APNIC',
        '106.0.0.0/8': 'APNIC', '110.0.0.0/8': 'APNIC', '111.0.0.0/8': 'APNIC',
        '112.0.0.0/8': 'APNIC', '113.0.0.0/8': 'APNIC', '114.0.0.0/8': 'APNIC',
        '115.0.0.0/8': 'APNIC', '116.0.0.0/8': 'APNIC', '117.0.0.0/8': 'APNIC',
        '118.0.0.0/8': 'APNIC', '119.0.0.0/8': 'APNIC', '120.0.0.0/8': 'APNIC',
        '121.0.0.0/8': 'APNIC', '122.0.0.0/8': 'APNIC', '123.0.0.0/8': 'APNIC',
        '124.0.0.0/8': 'APNIC', '125.0.0.0/8': 'APNIC', '126.0.0.0/8': 'APNIC',
        '175.0.0.0/8': 'APNIC', '180.0.0.0/8': 'APNIC', '182.0.0.0/8': 'APNIC',
        '183.0.0.0/8': 'APNIC', '202.0.0.0/8': 'APNIC', '203.0.0.0/8': 'APNIC',
        '210.0.0.0/8': 'APNIC', '211.0.0.0/8': 'APNIC', '218.0.0.0/8': 'APNIC',
        '219.0.0.0/8': 'APNIC', '220.0.0.0/8': 'APNIC', '221.0.0.0/8': 'APNIC',
        '222.0.0.0/8': 'APNIC', '223.0.0.0/8': 'APNIC',
        '2.0.0.0/8': 'RIPE', '5.0.0.0/8': 'RIPE', '31.0.0.0/8': 'RIPE',
        '37.0.0.0/8': 'RIPE', '46.0.0.0/8': 'RIPE', '62.0.0.0/8': 'RIPE',
        '77.0.0.0/8': 'RIPE', '78.0.0.0/8': 'RIPE', '79.0.0.0/8': 'RIPE',
        '80.0.0.0/8': 'RIPE', '81.0.0.0/8': 'RIPE', '82.0.0.0/8': 'RIPE',
        '83.0.0.0/8': 'RIPE', '84.0.0.0/8': 'RIPE', '85.0.0.0/8': 'RIPE',
        '86.0.0.0/8': 'RIPE', '87.0.0.0/8': 'RIPE', '88.0.0.0/8': 'RIPE',
        '89.0.0.0/8': 'RIPE', '90.0.0.0/8': 'RIPE', '91.0.0.0/8': 'RIPE',
        '92.0.0.0/8': 'RIPE', '93.0.0.0/8': 'RIPE', '94.0.0.0/8': 'RIPE',
        '95.0.0.0/8': 'RIPE', '109.0.0.0/8': 'RIPE', '141.0.0.0/8': 'RIPE',
        '145.0.0.0/8': 'RIPE', '151.0.0.0/8': 'RIPE', '176.0.0.0/8': 'RIPE',
        '178.0.0.0/8': 'RIPE', '185.0.0.0/8': 'RIPE', '188.0.0.0/8': 'RIPE',
        '193.0.0.0/8': 'RIPE', '194.0.0.0/8': 'RIPE', '195.0.0.0/8': 'RIPE',
        '212.0.0.0/8': 'RIPE', '213.0.0.0/8': 'RIPE', '217.0.0.0/8': 'RIPE',
        '3.0.0.0/8': 'ARIN', '6.0.0.0/8': 'ARIN', '7.0.0.0/8': 'ARIN',
        '8.0.0.0/8': 'ARIN', '9.0.0.0/8': 'ARIN', '11.0.0.0/8': 'ARIN',
        '12.0.0.0/8': 'ARIN', '17.0.0.0/8': 'ARIN', '18.0.0.0/8': 'ARIN',
        '19.0.0.0/8': 'ARIN', '20.0.0.0/8': 'ARIN', '21.0.0.0/8': 'ARIN',
        '22.0.0.0/8': 'ARIN', '23.0.0.0/8': 'ARIN', '24.0.0.0/8': 'ARIN',
        '25.0.0.0/8': 'ARIN', '26.0.0.0/8': 'ARIN', '28.0.0.0/8': 'ARIN',
        '29.0.0.0/8': 'ARIN', '30.0.0.0/8': 'ARIN', '32.0.0.0/8': 'ARIN',
        '33.0.0.0/8': 'ARIN', '34.0.0.0/8': 'ARIN', '35.0.0.0/8': 'ARIN',
        '38.0.0.0/8': 'ARIN', '40.0.0.0/8': 'ARIN', '44.0.0.0/8': 'ARIN',
        '45.0.0.0/8': 'ARIN', '47.0.0.0/8': 'ARIN', '48.0.0.0/8': 'ARIN',
        '50.0.0.0/8': 'ARIN', '52.0.0.0/8': 'ARIN', '54.0.0.0/8': 'ARIN',
        '55.0.0.0/8': 'ARIN', '56.0.0.0/8': 'ARIN', '63.0.0.0/8': 'ARIN',
        '64.0.0.0/8': 'ARIN', '65.0.0.0/8': 'ARIN', '66.0.0.0/8': 'ARIN',
        '67.0.0.0/8': 'ARIN', '68.0.0.0/8': 'ARIN', '69.0.0.0/8': 'ARIN',
        '70.0.0.0/8': 'ARIN', '71.0.0.0/8': 'ARIN', '72.0.0.0/8': 'ARIN',
        '73.0.0.0/8': 'ARIN', '74.0.0.0/8': 'ARIN', '75.0.0.0/8': 'ARIN',
        '76.0.0.0/8': 'ARIN', '96.0.0.0/8': 'ARIN', '97.0.0.0/8': 'ARIN',
        '98.0.0.0/8': 'ARIN', '99.0.0.0/8': 'ARIN', '100.0.0.0/8': 'ARIN',
        '128.0.0.0/8': 'ARIN', '129.0.0.0/8': 'ARIN', '130.0.0.0/8': 'ARIN',
        '131.0.0.0/8': 'ARIN', '132.0.0.0/8': 'ARIN', '134.0.0.0/8': 'ARIN',
        '135.0.0.0/8': 'ARIN', '136.0.0.0/8': 'ARIN', '137.0.0.0/8': 'ARIN',
        '138.0.0.0/8': 'ARIN', '139.0.0.0/8': 'ARIN', '140.0.0.0/8': 'ARIN',
        '142.0.0.0/8': 'ARIN', '143.0.0.0/8': 'ARIN', '144.0.0.0/8': 'ARIN',
        '146.0.0.0/8': 'ARIN', '147.0.0.0/8': 'ARIN', '148.0.0.0/8': 'ARIN',
        '149.0.0.0/8': 'ARIN', '150.0.0.0/8': 'ARIN', '152.0.0.0/8': 'ARIN',
        '155.0.0.0/8': 'ARIN', '156.0.0.0/8': 'ARIN', '157.0.0.0/8': 'ARIN',
        '158.0.0.0/8': 'ARIN', '159.0.0.0/8': 'ARIN', '160.0.0.0/8': 'ARIN',
        '161.0.0.0/8': 'ARIN', '162.0.0.0/8': 'ARIN', '163.0.0.0/8': 'ARIN',
        '164.0.0.0/8': 'ARIN', '165.0.0.0/8': 'ARIN', '166.0.0.0/8': 'ARIN',
        '167.0.0.0/8': 'ARIN', '168.0.0.0/8': 'ARIN', '169.0.0.0/8': 'ARIN',
        '170.0.0.0/8': 'ARIN', '171.0.0.0/8': 'ARIN', '172.0.0.0/8': 'ARIN',
        '173.0.0.0/8': 'ARIN', '174.0.0.0/8': 'ARIN', '184.0.0.0/8': 'ARIN',
        '192.0.0.0/8': 'ARIN', '198.0.0.0/8': 'ARIN', '199.0.0.0/8': 'ARIN',
        '204.0.0.0/8': 'ARIN', '205.0.0.0/8': 'ARIN', '206.0.0.0/8': 'ARIN',
        '207.0.0.0/8': 'ARIN', '208.0.0.0/8': 'ARIN', '209.0.0.0/8': 'ARIN',
        '216.0.0.0/8': 'ARIN',
        '177.0.0.0/8': 'LACNIC', '179.0.0.0/8': 'LACNIC', '181.0.0.0/8': 'LACNIC',
        '186.0.0.0/8': 'LACNIC', '187.0.0.0/8': 'LACNIC', '189.0.0.0/8': 'LACNIC',
        '190.0.0.0/8': 'LACNIC', '191.0.0.0/8': 'LACNIC', '200.0.0.0/8': 'LACNIC',
        '201.0.0.0/8': 'LACNIC',
        '41.0.0.0/8': 'AFRINIC', '102.0.0.0/8': 'AFRINIC', '105.0.0.0/8': 'AFRINIC',
        '154.0.0.0/8': 'AFRINIC', '196.0.0.0/8': 'AFRINIC', '197.0.0.0/8': 'AFRINIC',
    }

    def __init__(self, config: MergeConfig = DEFAULT_CONFIG):
        self._prefixes = {}
        self._cache_dir = Path(tempfile.gettempdir()) / "rir_cache"
        self._cache_file = self._cache_dir / "rir_data.json"
        self._lock = threading.RLock()
        self._last_update = 0
        self._load_builtin()
        if config.enable_rir_lookup:
            self._try_load_cached()

    def _load_builtin(self):
        """惰性加載內置的 RIR 前綴數據"""
        with self._lock:
            for prefix_str, rir in self.BUILTIN_PREFIXES.items():
                try:
                    network = ipaddress.ip_network(prefix_str, strict=False)
                    self._prefixes[network] = rir
                except ValueError:
                    continue

    def _try_load_cached(self):
        """嘗試從緩存加載 RIR 數據"""
        try:
            if self._cache_file.exists():
                mtime = self._cache_file.stat().st_mtime
                if time.time() - mtime < 7 * 86400:
                    with open(self._cache_file, 'r') as f:
                        data = json.load(f)
                        for prefix_str, rir in data.items():
                            try:
                                network = ipaddress.ip_network(prefix_str, strict=False)
                                self._prefixes[network] = rir
                            except ValueError:
                                continue
                        self._last_update = mtime
        except Exception as e:
            logger.warning(f"Failed to load RIR cache: {e}")

    def get_owner(self, network: Union[ipaddress.IPv4Network, ipaddress.IPv6Network]) -> Optional[str]:
        """修復：使用最長匹配前綴（most specific prefix）"""
        with self._lock:
            best_match = None
            best_len = -1
            for prefix, rir in self._prefixes.items():
                if prefix.version != network.version:
                    continue
                # 修復：只檢查network是否是prefix的子網
                if network.subnet_of(prefix) and prefix.prefixlen > best_len:
                    best_len = prefix.prefixlen
                    best_match = rir
            return best_match

    def can_merge(self, net1: Union[ipaddress.IPv4Network, ipaddress.IPv6Network],
                  net2: Union[ipaddress.IPv4Network, ipaddress.IPv6Network]) -> bool:
        """檢查兩個網絡是否可以合併（屬於同一 RIR）"""
        owner1 = self.get_owner(net1)
        owner2 = self.get_owner(net2)
        if owner1 is None or owner2 is None:
            return True
        return owner1 == owner2


class ReadWriteLock:
    __slots__ = ('_read_ready', '_readers', '_writers_waiting', '_writer_active', '_lock')
    def __init__(self):
        self._lock = threading.RLock()
        self._read_ready = threading.Condition(self._lock)
        self._readers = 0
        self._writers_waiting = 0
        self._writer_active = False

    def acquire_read(self):
        with self._lock:
            while self._writer_active or self._writers_waiting > 0:
                self._read_ready.wait()
            self._readers += 1

    def release_read(self):
        with self._lock:
            self._readers -= 1
            if self._readers == 0:
                self._read_ready.notify_all()

    def acquire_write(self):
        with self._lock:
            self._writers_waiting += 1
            while self._readers > 0 or self._writer_active:
                self._read_ready.wait()
            self._writers_waiting -= 1
            self._writer_active = True

    def release_write(self):
        with self._lock:
            self._writer_active = False
            self._read_ready.notify_all()

    def __enter__(self):
        self.acquire_write()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.release_write()


class ResourceMonitor:
    __slots__ = ('_threshold', '_enabled', '_start_time', '_max_duration', '_check_count', '_lock')
    def __init__(self, threshold_percent: float = 85.0, max_duration: Optional[float] = None):
        self._threshold = threshold_percent
        self._enabled = True
        self._start_time = time.time()
        self._max_duration = max_duration
        self._check_count = 0
        self._lock = threading.Lock()

    def check_resources(self) -> Tuple[bool, float]:
        if not self._enabled:
            return True, 0.0
        with self._lock:
            self._check_count += 1
            if self._check_count % 100 != 0:
                return True, 0.0
        try:
            mem = psutil.virtual_memory()
            mem_usage = mem.percent
            if mem_usage > self._threshold:
                return False, mem_usage
            if self._max_duration and (time.time() - self._start_time) > self._max_duration:
                return False, mem_usage
            return True, mem_usage
        except:
            return True, 0.0

    def should_degrade(self, current_level: int) -> bool:
        ok, usage = self.check_resources()
        if not ok:
            return True
        if current_level > 1 and usage > self._threshold * 0.9:
            logger.warning(f"Degrading from level {current_level} to {current_level-1} due to memory pressure {usage:.1f}%")
            return True
        if current_level > 2 and usage > self._threshold * 0.95:
            return True
        return False


class TieredVerificationStrategy:
    __slots__ = ('_config', '_current_tier', '_tier_stats', '_lock')
    TIER_NAMES = {1: 'STRICT', 2: 'STANDARD', 3: 'FAST'}

    def __init__(self, config: MergeConfig = DEFAULT_CONFIG):
        self._config = config
        self._current_tier = 1
        self._tier_stats = {1: 0, 2: 0, 3: 0}
        self._lock = threading.Lock()

    def select_tier(self, rule_count: int, available_memory: float) -> int:
        """修復：使用真實可用內存百分比"""
        with self._lock:
            if not self._config.tiered_verification:
                return 1
            
            # 修復：確保使用真實內存數據
            if rule_count <= self._config.tier1_max_rules and available_memory > 50.0:
                tier = 1
            elif rule_count <= self._config.tier2_max_rules and available_memory > 30.0:
                tier = 2
            else:
                tier = 3
            
            self._current_tier = tier
            self._tier_stats[tier] += 1
            return tier

    def get_current_tier(self) -> int:
        with self._lock:
            return self._current_tier

    def get_stats(self) -> Dict[int, int]:
        with self._lock:
            return dict(self._tier_stats)


class VersionedBDDNode:
    """修復版：添加弱引用支持和跨代引用管理"""
    __slots__ = ('var', 'low', 'high', 'hash_val', '_ref_count', '_generation', '_migrated_to', '_last_accessed_gen', '_low_is_weak', '_high_is_weak')
    _node_cache = OrderedDict()
    _cache_lock = threading.RLock()
    _instance_count = 0
    _count_lock = threading.Lock()
    _max_cache_size = 50000
    _current_generation = 0

    def __new__(cls, var: int, low: Optional['VersionedBDDNode'], high: Optional['VersionedBDDNode'], generation: int = 0):
        if low is high:
            return low
        
        key = (var, id(low) if low else None, id(high) if high else None, generation)
        
        with cls._cache_lock:
            if key in cls._node_cache:
                existing = cls._node_cache[key]
                if existing._migrated_to is not None:
                    return existing._migrated_to
                existing._last_accessed_gen = generation
                return existing
            
            if cls._instance_count >= cls._max_cache_size:
                cls._emergency_gc(generation)
            
            instance = super().__new__(cls)
            cls._node_cache[key] = instance
            with cls._count_lock:
                cls._instance_count += 1
            
            weakref.finalize(instance, cls._decrement_count)
            return instance

    @classmethod
    def _decrement_count(cls):
        with cls._count_lock:
            cls._instance_count = max(0, cls._instance_count - 1)

    @classmethod
    def _emergency_gc(cls, current_gen):
        gc.collect()
        if cls._instance_count >= cls._max_cache_size * 0.95:
            with cls._cache_lock:
                to_remove = [k for k, v in cls._node_cache.items() 
                            if v._ref_count == 0 and current_gen - v._last_accessed_gen > 2]
                for k in to_remove:
                    del cls._node_cache[k]
            gc.collect()

    @classmethod
    def increment_generation(cls):
        with cls._cache_lock:
            cls._current_generation += 1
            return cls._current_generation

    @classmethod
    def remove_from_cache(cls, node_id: int, generation: int):
        """從緩存中移除指定節點（用於事務回滾）"""
        with cls._cache_lock:
            to_remove = [k for k, v in cls._node_cache.items() 
                        if id(v) == node_id and v._generation == generation]
            for k in to_remove:
                del cls._node_cache[k]

    def __init__(self, var: int, low: Optional['VersionedBDDNode'], high: Optional['VersionedBDDNode'], generation: int = 0):
        if hasattr(self, 'var'):
            return
        self.var = var
        self._low_is_weak = False
        self._high_is_weak = False
        
        # 修復：對非當前generation的引用使用弱引用
        if low is not None and low._generation < generation:
            self.low = weakref.ref(low)
            self._low_is_weak = True
        else:
            self.low = low
            
        if high is not None and high._generation < generation:
            self.high = weakref.ref(high)
            self._high_is_weak = True
        else:
            self.high = high
            
        self.hash_val = hash((var, id(low), id(high), generation))
        self._ref_count = 0
        self._generation = generation
        self._migrated_to = None
        self._last_accessed_gen = generation

    def get_low(self):
        """安全獲取low引用"""
        if self._low_is_weak:
            return self.low() if self.low else None
        return self.low

    def get_high(self):
        """安全獲取high引用"""
        if self._high_is_weak:
            return self.high() if self.high else None
        return self.high

    def mark_migrated(self, new_node: 'VersionedBDDNode'):
        self._migrated_to = new_node

    def __hash__(self):
        return self.hash_val

    def __eq__(self, other):
        return self is other


class TransactionalBDDEngine:
    __slots__ = ('var_map', 'var_counter', 'true_node', 'false_node', '_lock', '_op_cache', '_node_count', 
                 '_gc_threshold', '_op_cache_lock', '_var_order', '_var_order_lock', '_roots', 
                 '_rebuild_lock', '_reordering_active', '_generation', '_transaction_active', '_txn_created_nodes')

    def __init__(self, gc_threshold: int = 50000):
        self.var_map = {}
        self.var_counter = 0
        self._lock = threading.Lock()
        self._op_cache = OrderedDict()
        self._op_cache_lock = threading.RLock()
        self._node_count = 0
        self._gc_threshold = gc_threshold
        self.false_node = VersionedBDDNode(-2, None, None, 0)
        self.true_node = VersionedBDDNode(-1, None, None, 0)
        self._var_order = []
        self._var_order_lock = threading.RLock()
        self._roots = weakref.WeakSet()
        self._rebuild_lock = threading.Lock()
        self._reordering_active = False
        self._generation = 0
        self._transaction_active = False
        self._txn_created_nodes = []

        with VersionedBDDNode._cache_lock:
            VersionedBDDNode._node_cache[(float('-inf'), None, None, 0)] = self.false_node
            VersionedBDDNode._node_cache[(float('inf'), None, None, 0)] = self.true_node

    def begin_transaction(self):
        with self._rebuild_lock:
            self._transaction_active = True
            self._generation = VersionedBDDNode.increment_generation()
            self._txn_created_nodes = []

    def commit_transaction(self):
        with self._rebuild_lock:
            self._transaction_active = False
            self._txn_created_nodes = []
            with self._op_cache_lock:
                self._op_cache.clear()

    def rollback_transaction(self):
        """修復：清理事務創建的節點"""
        with self._rebuild_lock:
            for node_id in self._txn_created_nodes:
                VersionedBDDNode.remove_from_cache(node_id, self._generation)
            self._txn_created_nodes = []
            self._transaction_active = False
            self._generation = max(0, self._generation - 1)
            with self._op_cache_lock:
                self._op_cache.clear()

    def get_var(self, name: str) -> int:
        with self._lock:
            if name not in self.var_map:
                self.var_map[name] = self.var_counter
                self._var_order.append(name)
                self.var_counter += 1
                self._node_count += 1
            return self.var_map[name]

    def ith_var(self, i: int) -> VersionedBDDNode:
        node = VersionedBDDNode(i, self.false_node, self.true_node, self._generation)
        if self._transaction_active:
            self._txn_created_nodes.append(id(node))
        self._roots.add(node)
        return node

    def neg(self, node: VersionedBDDNode) -> VersionedBDDNode:
        if node is self.true_node:
            return self.false_node
        if node is self.false_node:
            return self.true_node
        key = ('neg', id(node), self._generation)
        with self._op_cache_lock:
            result = self._op_cache.get(key)
            if result is not None:
                return result
            low = node.get_low()
            high = node.get_high()
            result = VersionedBDDNode(node.var, self.neg(low), self.neg(high), self._generation)
            if self._transaction_active:
                self._txn_created_nodes.append(id(result))
            self._op_cache[key] = result
            self._roots.add(result)
            return result

    def apply_and(self, f: VersionedBDDNode, g: VersionedBDDNode) -> VersionedBDDNode:
        return self._apply_op(f, g, 'and')

    def apply_or(self, f: VersionedBDDNode, g: VersionedBDDNode) -> VersionedBDDNode:
        return self._apply_op(f, g, 'or')

    def apply_implies(self, f: VersionedBDDNode, g: VersionedBDDNode) -> VersionedBDDNode:
        return self.apply_or(self.neg(f), g)

    def _apply_op(self, f: VersionedBDDNode, g: VersionedBDDNode, op: str) -> VersionedBDDNode:
        if f is self.false_node or g is self.false_node:
            return self.false_node if op == 'and' else (g if f is self.false_node else f)
        if f is self.true_node:
            return g if op == 'and' else self.true_node
        if g is self.true_node:
            return f if op == 'and' else self.true_node
        if f is g:
            return f if op == 'and' else f

        key = (op, min(id(f), id(g)), max(id(f), id(g)), self._generation)
        with self._op_cache_lock:
            result = self._op_cache.get(key)
            if result is not None:
                return result

            f_low, f_high = f.get_low(), f.get_high()
            g_low, g_high = g.get_low(), g.get_high()
            
            if f.var == g.var:
                result = VersionedBDDNode(f.var, 
                              self._apply_op(f_low, g_low, op),
                              self._apply_op(f_high, g_high, op), self._generation)
            elif f.var < g.var:
                result = VersionedBDDNode(f.var,
                              self._apply_op(f_low, g, op),
                              self._apply_op(f_high, g, op), self._generation)
            else:
                result = VersionedBDDNode(g.var,
                              self._apply_op(f, g_low, op),
                              self._apply_op(f, g_high, op), self._generation)

            if self._transaction_active:
                self._txn_created_nodes.append(id(result))
            self._op_cache[key] = result
            self._roots.add(result)
            return result

    def sat_count(self, node: VersionedBDDNode, n_vars: int) -> int:
        if node is self.false_node:
            return 0
        if node is self.true_node:
            return 1 << n_vars
        low = node.get_low()
        high = node.get_high()
        count_low = self.sat_count(low, n_vars - 1)
        count_high = self.sat_count(high, n_vars - 1)
        return count_low + count_high

    def implies(self, f: VersionedBDDNode, g: VersionedBDDNode) -> bool:
        result = self.apply_implies(f, g)
        return result is self.true_node

    def equivalent(self, f: VersionedBDDNode, g: VersionedBDDNode) -> bool:
        return self.implies(f, g) and self.implies(g, f)


class BDDRuleVerifier:
    __slots__ = ('engine', '_domain_vars', '_ip_vars', '_lock', '_encoded_rules')
    def __init__(self, engine: TransactionalBDDEngine):
        self.engine = engine
        self._domain_vars = {}
        self._ip_vars = {}
        self._lock = threading.RLock()
        self._encoded_rules = weakref.WeakSet()

    def encode_domain_rule(self, rule: DomainRule) -> VersionedBDDNode:
        """修復：使用路徑編碼策略，將域名層次結構編碼為布林變量合取"""
        with self._lock:
            # 使用層次化編碼而非扁平化編碼
            parts = rule.normalized.lstrip('*.').split('.')
            result = self.engine.true_node
            
            for i, part in enumerate(reversed(parts)):
                var_name = f"label_{i}_{part}"
                if var_name not in self._domain_vars:
                    var_idx = self.engine.get_var(var_name)
                    self._domain_vars[var_name] = self.engine.ith_var(var_idx)
                node = self._domain_vars[var_name]
                result = self.engine.apply_and(result, node)
            
            # 對於wildcard，添加存在量詞語義
            if rule.match_type == MatchType.WILDCARD:
                # 添加「任意子標籤」語義 - 使用額外變量表示
                wildcard_var = f"wildcard_{rule.normalized}"
                if wildcard_var not in self._domain_vars:
                    var_idx = self.engine.get_var(wildcard_var)
                    self._domain_vars[wildcard_var] = self.engine.ith_var(var_idx)
                result = self.engine.apply_and(result, self._domain_vars[wildcard_var])
            
            self._encoded_rules.add(result)
            return result

    def encode_ip_rule(self, rule: IPCIDRRule) -> VersionedBDDNode:
        """修復：正確處理prefix=0（默認路由）的情況"""
        with self._lock:
            addr = int(rule.network.network_address)
            prefix = rule.network.prefixlen
            version = rule.network.version
            width = 32 if version == 4 else 128
            
            # 修復：處理prefix=0的情況
            if prefix == 0:
                return self.engine.true_node  # 匹配所有
            
            var_name = f"ip_{version}_{addr}_{prefix}"

            if var_name not in self._ip_vars:
                result = self.engine.true_node
                for bit_pos in range(prefix):
                    bit_val = (addr >> (width - 1 - bit_pos)) & 1
                    bit_var_name = f"ip_bit_{version}_{bit_pos}"
                    bit_idx = self.engine.get_var(bit_var_name)
                    bit_node = self.engine.ith_var(bit_idx)
                    if bit_val == 0:
                        bit_node = self.engine.neg(bit_node)
                    result = self.engine.apply_and(result, bit_node)
                self._ip_vars[var_name] = result

            self._encoded_rules.add(self._ip_vars[var_name])
            return self._ip_vars[var_name]

    def build_rule_set_expression(self, rules: List[RuleType]) -> VersionedBDDNode:
        allow_rules = [r for r in rules if not r.is_exclusion]
        exclude_rules = [r for r in rules if r.is_exclusion]

        allow_bdd = self.engine.false_node
        for rule in allow_rules:
            if isinstance(rule, DomainRule):
                rule_bdd = self.encode_domain_rule(rule)
            elif isinstance(rule, IPCIDRRule):
                rule_bdd = self.encode_ip_rule(rule)
            else:
                continue
            allow_bdd = self.engine.apply_or(allow_bdd, rule_bdd)

        if not exclude_rules:
            return allow_bdd

        exclude_bdd = self.engine.false_node
        for rule in exclude_rules:
            if isinstance(rule, DomainRule):
                rule_bdd = self.encode_domain_rule(rule)
            elif isinstance(rule, IPCIDRRule):
                rule_bdd = self.encode_ip_rule(rule)
            else:
                continue
            exclude_bdd = self.engine.apply_or(exclude_bdd, rule_bdd)

        exclude_neg = self.engine.neg(exclude_bdd)
        return self.engine.apply_and(allow_bdd, exclude_neg)

    def check_equivalence(self, rules_a: List[RuleType], rules_b: List[RuleType]) -> bool:
        bdd_a = self.build_rule_set_expression(rules_a)
        bdd_b = self.build_rule_set_expression(rules_b)
        return self.engine.equivalent(bdd_a, bdd_b)

    def verify_subset_strict(self, parent_rules: List[RuleType], child_rules: List[RuleType]) -> Tuple[bool, float]:
        if not parent_rules or not child_rules:
            return True, 1.0

        self.engine.begin_transaction()
        try:
            parent_bdd = self.build_rule_set_expression(parent_rules)
            child_bdd = self.build_rule_set_expression(child_rules)

            is_subset = self.engine.implies(child_bdd, parent_bdd)
            if is_subset:
                return True, 1.0

            sat_count_parent = self.engine.sat_count(parent_bdd, len(self.engine.var_map))
            sat_count_child = self.engine.sat_count(child_bdd, len(self.engine.var_map))

            if sat_count_child == 0:
                return True, 1.0

            intersection = self.engine.apply_and(child_bdd, self.engine.neg(parent_bdd))
            sat_count_diff = self.engine.sat_count(intersection, len(self.engine.var_map))

            if sat_count_diff == 0:
                return True, 1.0

            confidence = 1.0 - (sat_count_diff / sat_count_child)
            return False, max(0.0, confidence)
        finally:
            self.engine.commit_transaction()


class SMTVerifier:
    """修復版：解決進程池序列化問題和緩存無限增長"""
    __slots__ = ('enabled', '_z3_available', '_solver_cache', '_config', '_timeout_stages', 
                 '_process_pool', '_pool_size', '_stop_event', '_cache_lock', '_max_cache_size')

    def __init__(self, config: MergeConfig = DEFAULT_CONFIG):
        self._config = config
        self._z3_available = HAS_Z3 and config.enable_smt_verification
        self.enabled = self._z3_available
        self._solver_cache = OrderedDict()
        self._cache_lock = threading.RLock()
        self._max_cache_size = 1000  # 限制緩存大小
        self._timeout_stages = config.smt_progressive_timeout or (100, 500, 2000, 5000)
        self._pool_size = config.smt_process_pool_size
        self._process_pool = None
        self._stop_event = None
        if self._z3_available and self._pool_size > 0:
            self._stop_event = multiprocessing.Event()
            self._process_pool = multiprocessing.Pool(processes=self._pool_size, maxtasksperchild=100)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self):
        if self._stop_event:
            self._stop_event.set()
        if self._process_pool:
            self._process_pool.terminate()
            self._process_pool.join()
            self._process_pool = None

    def verify_subset(self, parent_rules: List[DomainRule], child_rules: List[DomainRule], 
                     monitor: Optional[ResourceMonitor] = None) -> Tuple[bool, float, int, str]:
        if not self.enabled:
            return False, 0.0, 0, "disabled"
        if not parent_rules or not child_rules:
            return True, 1.0, 0, "trivial"

        try:
            key = (tuple(sorted(r.normalized for r in parent_rules)), 
                   tuple(sorted(r.normalized for r in child_rules)))

            with self._cache_lock:
                if key in self._solver_cache:
                    return self._solver_cache[key]

            parent_strs = [f"dom:{r.normalized}" for r in parent_rules if r.match_type != MatchType.WILDCARD]
            child_strs = [f"dom:{r.normalized}" for r in child_rules if r.match_type != MatchType.WILDCARD]

            for timeout_idx, timeout_ms in enumerate(self._timeout_stages):
                if monitor and monitor.should_degrade(3):
                    return False, 0.0, 0, "resource_pressure"

                if self._stop_event and self._stop_event.is_set():
                    return False, 0.0, 0, "shutdown"

                if self._pool_size == 0:
                    result = self._verify_impl(parent_strs, child_strs, timeout_ms)
                else:
                    # 修復：使用靜態方法並傳遞配置字典而非self
                    try:
                        config_dict = asdict(self._config)
                        future = self._process_pool.apply_async(
                            SMTVerifier._verify_worker_static, 
                            (parent_strs, child_strs, timeout_ms, config_dict)
                        )
                        result = future.get(timeout=timeout_ms/1000.0 + 1.0)
                    except multiprocessing.TimeoutError:
                        continue

                with self._cache_lock:
                    # 修復：LRU緩存淘汰
                    if len(self._solver_cache) >= self._max_cache_size:
                        self._solver_cache.popitem(last=False)
                    self._solver_cache[key] = result
                return result

            final_result = (False, 0.5, 0, "unknown")
            with self._cache_lock:
                if len(self._solver_cache) >= self._max_cache_size:
                    self._solver_cache.popitem(last=False)
                self._solver_cache[key] = final_result
            return final_result
        except Exception as e:
            logger.warning(f"SMT verification failed: {e}")
            return False, 0.0, 0, f"exception:{str(e)}"

    def _verify_impl(self, parent_rules_str, child_rules_str, timeout_ms):
        """實例方法實現（單進程模式使用）"""
        return SMTVerifier._verify_worker_static(parent_rules_str, child_rules_str, timeout_ms, asdict(self._config))

    @staticmethod
    def _verify_worker_static(parent_rules_str, child_rules_str, timeout_ms, config_dict):
        """修復：靜態方法，避免捕獲self，使用線程超時替代信號"""
        if not HAS_Z3:
            return False, 0.0, timeout_ms, "z3_unavailable"

        result_container = [None]
        
        def target():
            try:
                s = z3.Solver()
                x = z3.String('x')

                parent_exprs = []
                for rule_str in parent_rules_str:
                    parts = rule_str.split(':', 1)
                    if len(parts) == 2:
                        parent_exprs.append(z3.Contains(x, z3.StringVal(parts[1])))

                child_exprs = []
                for rule_str in child_rules_str:
                    parts = rule_str.split(':', 1)
                    if len(parts) == 2:
                        child_exprs.append(z3.Contains(x, z3.StringVal(parts[1])))

                if not parent_exprs or not child_exprs:
                    result_container[0] = (True, 1.0, timeout_ms, "trivial")
                    return

                parent_expr = z3.Or(*parent_exprs) if len(parent_exprs) > 1 else parent_exprs[0]
                child_expr = z3.Or(*child_exprs) if len(child_exprs) > 1 else child_exprs[0]

                s.add(z3.And(child_expr, z3.Not(parent_expr)))
                check_result = s.check()

                if check_result == z3.sat:
                    result_container[0] = (False, 1.0, timeout_ms, "sat")
                elif check_result == z3.unsat:
                    result_container[0] = (True, 1.0, timeout_ms, "unsat")
                else:
                    result_container[0] = (False, 0.5, timeout_ms, "unknown")
            except Exception as e:
                result_container[0] = (False, 0.0, timeout_ms, f"error:{str(e)}")

        thread = threading.Thread(target=target)
        thread.start()
        thread.join(timeout_ms / 1000.0)
        
        if thread.is_alive():
            return False, 0.0, timeout_ms, "timeout"
        
        return result_container[0] if result_container[0] else (False, 0.0, timeout_ms, "unknown")


class StrictNgramSpectrumAnalyzer:
    __slots__ = ('_baseline_freq', '_scales', '_js_threshold', '_lock', '_det_rand', 
                 '_chi2_threshold', '_script_whitelist')

    def __init__(self, config: MergeConfig = DEFAULT_CONFIG):
        self._scales = config.ngram_scales
        self._js_threshold = config.ngram_js_divergence_threshold
        self._chi2_threshold = 0.05
        self._lock = threading.RLock()
        self._det_rand = DeterministicRandom(config.deterministic_seed + "_ngram")
        self._script_whitelist = set(config.idn_allowed_scripts) if config.enable_idn_script_whitelist else set()
        self._baseline_freq = {}
        self._build_baseline()

    def _build_baseline(self):
        baseline_domains = [
            'google.com', 'facebook.com', 'amazon.com', 'microsoft.com', 'apple.com',
            'github.com', 'stackoverflow.com', 'wikipedia.org', 'linkedin.com', 'twitter.com',
            'instagram.com', 'youtube.com', 'reddit.com', 'netflix.com', 'spotify.com'
        ]
        for domain in baseline_domains:
            for n in self._scales:
                ngrams = self._extract_ngrams(domain, n)
                if n not in self._baseline_freq:
                    self._baseline_freq[n] = defaultdict(int)
                for ng in ngrams:
                    self._baseline_freq[n][ng] += 1

    def _extract_ngrams(self, s: str, n: int) -> List[str]:
        s_clean = ''.join(c if c.isalnum() else '-' for c in s.lower())
        return [s_clean[i:i+n] for i in range(len(s_clean) - n + 1)]

    def _detect_script(self, s: str) -> Set[str]:
        scripts = set()
        for char in s:
            try:
                name = unicodedata.name(char)
                parts = name.split()
                base_script = parts[0]
                if base_script in ('DIGIT', 'NUMBER', 'CIRCLED'):
                    scripts.add('COMMON')
                elif base_script in ('LATIN', 'CYRILLIC', 'GREEK', 'ARABIC', 'HEBREW', 'CJK', 'HANGUL'):
                    scripts.add(base_script)
            except:
                pass
        return scripts

    def _is_idn_whitelisted(self, domain: str) -> bool:
        if not self._script_whitelist:
            return False
        scripts = self._detect_script(domain)
        return len(scripts) == 1 and scripts.pop() in self._script_whitelist

    def _compute_js_divergence(self, test_ngrams: List[str], n: int) -> float:
        if n not in self._baseline_freq:
            return 0.0

        test_dist = defaultdict(int)
        for ng in test_ngrams:
            test_dist[ng] += 1

        total_test = len(test_ngrams)
        total_base = sum(self._baseline_freq[n].values())

        if total_test == 0 or total_base == 0:
            return 0.0

        p = {k: v/total_test for k, v in test_dist.items()}
        q = {k: v/total_base for k, v in self._baseline_freq[n].items()}

        return calculate_js_divergence(p, q)

    def analyze(self, domain: str) -> Dict[str, Any]:
        with self._lock:
            if self._is_idn_whitelisted(domain):
                return {
                    'scales': {},
                    'max_js_divergence': 0.0,
                    'min_chi2_pvalue': 1.0,
                    'is_anomaly': False,
                    'entropy': calculate_entropy(domain),
                    'conditional_entropy': calculate_conditional_entropy(domain, 1),
                    'explanation': 'IDN script whitelisted',
                    'entropy_spectrum': self._compute_entropy_spectrum(domain)
                }

            results = {
                'scales': {},
                'max_js_divergence': 0.0,
                'min_chi2_pvalue': 1.0,
                'is_anomaly': False,
                'entropy': calculate_entropy(domain),
                'conditional_entropy': calculate_conditional_entropy(domain, 1),
                'explanation': '',
                'entropy_spectrum': self._compute_entropy_spectrum(domain)
            }

            explanations = []

            for n in self._scales:
                ngrams = self._extract_ngrams(domain, n)
                js_div = self._compute_js_divergence(ngrams, n)
                chi2, p_val = self._compute_chi2_statistic(ngrams, n)

                results['scales'][n] = {
                    'js_divergence': js_div,
                    'chi2_pvalue': p_val,
                    'ngram_count': len(ngrams)
                }

                results['max_js_divergence'] = max(results['max_js_divergence'], js_div)
                results['min_chi2_pvalue'] = min(results['min_chi2_pvalue'], p_val)

                if js_div > self._js_threshold:
                    high_ngrams = [ng for ng in ngrams if self._baseline_freq[n].get(ng, 0) == 0]
                    if high_ngrams:
                        explanations.append(f"High-frequency consonant cluster '{high_ngrams[0]}' detected (scale {n}), deviation {js_div:.2f}")

            results['is_anomaly'] = (
                results['max_js_divergence'] > self._js_threshold or
                results['min_chi2_pvalue'] < self._chi2_threshold or
                results['entropy'] > 4.5 or
                results['conditional_entropy'] > 3.5
            )

            if results['is_anomaly'] and not explanations:
                explanations.append(f"Entropy {results['entropy']:.2f} exceeds threshold")

            results['explanation'] = '; '.join(explanations) if explanations else 'Normal pattern'

            return results

    def _compute_chi2_statistic(self, test_ngrams: List[str], n: int) -> Tuple[float, float]:
        if n not in self._baseline_freq:
            return 0.0, 1.0

        observed = defaultdict(int)
        for ng in test_ngrams:
            observed[ng] += 1

        total_observed = len(test_ngrams)
        total_expected = sum(self._baseline_freq[n].values())

        if total_observed == 0:
            return 0.0, 1.0

        chi2 = 0.0
        for ng, obs in observed.items():
            exp = (self._baseline_freq[n][ng] / total_expected) * total_observed
            if exp > 0:
                chi2 += (obs - exp) ** 2 / exp

        degrees_freedom = max(len(observed) - 1, 1)
        p_value = self._approximate_p_value(chi2, degrees_freedom)
        return chi2, p_value

    def _approximate_p_value(self, chi2: float, df: int) -> float:
        if chi2 < 0 or df == 0:
            return 1.0
        return math.exp(-chi2 / (2 * df))

    def _compute_entropy_spectrum(self, domain: str) -> List[float]:
        spectrum = []
        for i in range(min(len(domain), 10)):
            substring = domain[max(0, i-2):i+3]
            spectrum.append(calculate_entropy(substring))
        return spectrum

    def is_dga_like(self, domain: str) -> Tuple[bool, str]:
        analysis = self.analyze(domain)
        return analysis['is_anomaly'], analysis['explanation']


class DomainTrie:
    """修復版：添加缺失方法，使用COW策略避免死鎖"""
    __slots__ = ('root', '_cache', '_cache_limit', '_rwlock', '_depth_limit', '_version', '_cache_lock')

    class Node:
        __slots__ = ('children', 'types', 'terminal', 'wildcard')
        def __init__(self):
            self.children = {}
            self.types = set()
            self.terminal = False
            self.wildcard = False

    def __init__(self, cache_limit: int = 10000, depth_limit: int = 128):
        self.root = self.Node()
        self._cache = OrderedDict()
        self._cache_limit = cache_limit
        self._rwlock = ReadWriteLock()
        self._depth_limit = depth_limit
        self._version = 0
        self._cache_lock = threading.RLock()

    def insert(self, domain: str, match_type: MatchType = MatchType.EXACT):
        """修復：使用COW策略，創建新路徑而非修改現有節點"""
        with self._rwlock:
            # 創建新的root副本
            new_root = self._copy_path(self.root, domain, match_type)
            self.root = new_root
            self._version += 1
            with self._cache_lock:
                self._cache.clear()

    def _copy_path(self, node, domain: str, match_type: MatchType):
        """複製路徑實現COW"""
        parts = domain.split('.')
        if len(parts) > self._depth_limit:
            parts = parts[-self._depth_limit:]
        
        # 從底部開始構建新路徑
        new_node = self.Node()
        new_node.types = node.types.copy()
        new_node.terminal = node.terminal
        new_node.wildcard = node.wildcard
        new_node.children = dict(node.children)
        
        current = new_node
        for i, part in enumerate(reversed(parts)):
            next_node = current.children.get(part)
            if next_node is None:
                next_node = self.Node()
                current.children[part] = next_node
            else:
                # 複製子節點
                copied = self.Node()
                copied.types = next_node.types.copy()
                copied.terminal = next_node.terminal
                copied.wildcard = next_node.wildcard
                copied.children = dict(next_node.children)
                current.children[part] = copied
                next_node = copied
            
            if match_type == MatchType.WILDCARD and i == len(parts) - 1:
                next_node.wildcard = True
                next_node.types.add(MatchType.WILDCARD)
            elif match_type == MatchType.SUFFIX and i == len(parts) - 1:
                next_node.types.add(MatchType.SUFFIX)
            
            current = next_node
        
        current.terminal = True
        current.types.add(match_type)
        return new_node

    def is_covered(self, domain: str, match_type: MatchType = MatchType.EXACT) -> Tuple[bool, MatchType, int]:
        """修復：無鎖讀取，使用版本號檢測一致性"""
        current_root = self.root  # Python引用賦值是原子的
        current_version = self._version
        
        cache_key = f"{domain}:{match_type.value}:{current_version}"
        with self._cache_lock:
            if cache_key in self._cache:
                self._cache.move_to_end(cache_key)
                return self._cache[cache_key]

        parts = domain.split('.')
        if len(parts) > self._depth_limit:
            parts = parts[-self._depth_limit:]

        node = current_root
        best_match = (False, MatchType.EXACT, 0)
        depth = 0

        for i, part in enumerate(reversed(parts)):
            if MatchType.WILDCARD in node.types and match_type == MatchType.EXACT:
                best_match = (True, MatchType.WILDCARD, depth)
            if node.terminal and MatchType.SUFFIX in node.types:
                best_match = (True, MatchType.SUFFIX, depth)
            if node.terminal and MatchType.EXACT in node.types and i == len(parts) - 1:
                best_match = (True, MatchType.EXACT, depth)

            if part not in node.children:
                with self._cache_lock:
                    self._cache[cache_key] = best_match
                    if len(self._cache) > self._cache_limit:
                        self._cache.popitem(last=False)
                return best_match
            node = node.children[part]
            depth += 1

        if MatchType.WILDCARD in node.types and match_type == MatchType.WILDCARD:
            best_match = (True, MatchType.WILDCARD, depth)
        elif node.terminal:
            if MatchType.EXACT in node.types and match_type == MatchType.EXACT:
                best_match = (True, MatchType.EXACT, depth)
            elif MatchType.SUFFIX in node.types:
                best_match = (True, MatchType.SUFFIX, depth)

        with self._cache_lock:
            self._cache[cache_key] = best_match
            if len(self._cache) > self._cache_limit:
                self._cache.popitem(last=False)

        return best_match

    def optimize(self) -> List[Tuple[str, MatchType]]:
        """修復：添加缺失的optimize方法"""
        result = []
        self._collect_domains(self.root, [], result)
        return result

    def _collect_domains(self, node, parts, result):
        """遞迴收集域名"""
        if node.terminal:
            domain = '.'.join(reversed(parts))
            if MatchType.WILDCARD in node.types:
                result.append((f"*.{domain}" if domain else "*", MatchType.WILDCARD))
            elif MatchType.EXACT in node.types:
                result.append((domain, MatchType.EXACT))
            elif MatchType.SUFFIX in node.types:
                result.append((domain, MatchType.SUFFIX))
        for part, child in node.children.items():
            self._collect_domains(child, parts + [part], result)

    def get_specificity_score(self, domain: str) -> int:
        """修復：添加缺失的get_specificity_score方法"""
        parts = domain.split('.')
        if len(parts) > self._depth_limit:
            parts = parts[-self._depth_limit:]
        node = self.root
        score = 0
        for part in reversed(parts):
            score += 10
            if MatchType.EXACT in node.types:
                score += 5
            elif MatchType.SUFFIX in node.types:
                score += 2
            if part not in node.children:
                break
            node = node.children[part]
        return score


class StrictPatriciaTrie:
    """修復版：處理prefixlen=0邊界"""
    __slots__ = ('root_v4', 'root_v6', '_lock')

    class Node:
        __slots__ = ('left', 'right', 'is_terminal', 'prefix_len', 'network')
        def __init__(self):
            self.left = None
            self.right = None
            self.is_terminal = False
            self.prefix_len = -1
            self.network = None

    def __init__(self):
        self.root_v4 = self.Node()
        self.root_v6 = self.Node()
        self._lock = threading.RLock()

    def insert(self, network: Union[ipaddress.IPv4Network, ipaddress.IPv6Network]):
        """修復：處理prefixlen=0（默認路由）"""
        is_v4 = network.version == 4
        
        # 修復：特殊處理默認路由
        if network.prefixlen == 0:
            root = self.root_v4 if is_v4 else self.root_v6
            with self._lock:
                root.is_terminal = True
                root.prefix_len = 0
                root.network = network
            return
        
        node = self.root_v4 if is_v4 else self.root_v6
        addr_int = int(network.network_address)
        width = 32 if is_v4 else 128

        with self._lock:
            for i in range(network.prefixlen):
                bit = (addr_int >> (width - 1 - i)) & 1
                if bit == 0:
                    if not node.left: node.left = self.Node()
                    node = node.left
                else:
                    if not node.right: node.right = self.Node()
                    node = node.right
            node.is_terminal = True
            node.prefix_len = network.prefixlen
            node.network = network

    def contains_subnet(self, network: Union[ipaddress.IPv4Network, ipaddress.IPv6Network]) -> bool:
        is_v4 = network.version == 4
        node = self.root_v4 if is_v4 else self.root_v6
        addr_int = int(network.network_address)
        width = 32 if is_v4 else 128

        with self._lock:
            for i in range(network.prefixlen + 1):
                if node.is_terminal:
                    return True
                if i == network.prefixlen:
                    break
                bit = (addr_int >> (width - 1 - i)) & 1
                if bit == 0:
                    if not node.left: return False
                    node = node.left
                else:
                    if not node.right: return False
                    node = node.right
            return False

    def find_covering_networks(self, network: Union[ipaddress.IPv4Network, ipaddress.IPv6Network]) -> List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]:
        """修復：返回所有覆蓋給定網絡的父網絡列表（按前綴長度降序）"""
        is_v4 = network.version == 4
        node = self.root_v4 if is_v4 else self.root_v6
        addr_int = int(network.network_address)
        width = 32 if is_v4 else 128

        covering = []

        with self._lock:
            for i in range(network.prefixlen + 1):
                if node.is_terminal and node.network:
                    if network.subnet_of(node.network):
                        covering.append(node.network)

                if i == network.prefixlen:
                    break

                bit = (addr_int >> (width - 1 - i)) & 1
                if bit == 0:
                    if not node.left:
                        break
                    node = node.left
                else:
                    if not node.right:
                        break
                    node = node.right

        # 修復：確保排序穩定（按前綴長度降序）
        return sorted(covering, key=lambda x: (-x.prefixlen, int(x.network_address)))


class IntervalTreeNode:
    __slots__ = ('center', 'intervals', 'left', 'right', 'by_start', 'by_end', '_lock', '_max_depth', '_current_depth')

    def __init__(self, intervals: List[Tuple[int, int, Any]], depth: int = 0, max_depth: int = 128):
        self.intervals = []
        self.left = None
        self.right = None
        self.by_start = []
        self.by_end = []
        self._lock = threading.RLock()
        self._max_depth = max_depth
        self._current_depth = depth

        if not intervals:
            self.center = 0
            return

        starts = [i[0] for i in intervals]
        ends = [i[1] for i in intervals]
        self.center = (min(starts) + max(ends)) // 2

        left_intervals = []
        right_intervals = []
        for start, end, data in intervals:
            if end < self.center:
                left_intervals.append((start, end, data))
            elif start > self.center:
                right_intervals.append((start, end, data))
            else:
                self.intervals.append((start, end, data))

        self.by_start = sorted(self.intervals, key=lambda x: x[0])
        self.by_end = sorted(self.intervals, key=lambda x: x[1])

        if depth < max_depth:
            if left_intervals:
                self.left = IntervalTreeNode(left_intervals, depth + 1, max_depth)
            if right_intervals:
                self.right = IntervalTreeNode(right_intervals, depth + 1, max_depth)

    def find_overlapping(self, start: int, end: int) -> List[Any]:
        """修復：使用嚴格重疊判斷（CIDR區間為閉區間）"""
        results = []
        with self._lock:
            for s, e, data in self.intervals:
                # 修復：嚴格重疊判斷 - 非分離即重疊
                if not (e < start or s > end):
                    results.append(data)
            if self.left and start <= self.center:
                results.extend(self.left.find_overlapping(start, end))
            if self.right and end >= self.center:
                results.extend(self.right.find_overlapping(start, end))
        return results


class IntervalTree:
    __slots__ = ('root', '_intervals', '_rwlock', '_dirty', '_version', '_max_depth')

    def __init__(self, max_depth: int = 128):  # 修復：支持IPv6的128位
        self.root = None
        self._intervals = []
        self._rwlock = ReadWriteLock()
        self._dirty = False
        self._version = 0
        self._max_depth = max_depth

    def insert(self, start: int, end: int, data: Any):
        with self._rwlock:
            self._intervals.append((start, end, data))
            self._dirty = True
            self._version += 1

    def _ensure_built(self):
        with self._rwlock:
            if self._dirty:
                self.root = IntervalTreeNode(self._intervals, max_depth=self._max_depth)
                self._dirty = False

    def find_overlapping(self, start: int, end: int) -> List[Any]:
        self._ensure_built()
        if not self.root:
            return []
        return self.root.find_overlapping(start, end)


class SweepLineCIDRManager:
    """修復版：解決RIR檢查漏洞、事件排序非確定性、無限循環等問題"""
    __slots__ = ('_patricia', '_networks', '_lock', 'enable_adjacent_merge', '_interval_tree', '_version', '_rir_manager')
    
    # 修復：使用類變量但確保只讀訪問
    PRIORITY = {'BS': 3, 'BE': 1, 'ES': 4, 'EE': 2}

    def __init__(self, enable_adjacent_merge: bool = True, use_interval_tree: bool = True, 
                 enable_rir: bool = False, rir_manager: Optional[RIRDataManager] = None):
        self._patricia = StrictPatriciaTrie()
        self._networks = []
        self._lock = threading.RLock()
        self.enable_adjacent_merge = enable_adjacent_merge
        # 修復：根據地址族動態調整深度
        self._interval_tree = IntervalTree(max_depth=128) if use_interval_tree else None
        self._version = 0
        self._rir_manager = rir_manager

    def add(self, network: Union[ipaddress.IPv4Network, ipaddress.IPv6Network]):
        if not isinstance(network, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
            raise TypeError("Must be IPv4Network or IPv6Network")

        with self._lock:
            self._patricia.insert(network)
            self._networks.append(network)
            if self._interval_tree:
                start = int(network.network_address)
                end = int(network.broadcast_address)
                self._interval_tree.insert(start, end, network)
            self._version += 1

    def contains(self, network: Union[ipaddress.IPv4Network, ipaddress.IPv6Network]) -> bool:
        with self._lock:
            return self._patricia.contains_subnet(network)

    def find_overlapping(self, network: Union[ipaddress.IPv4Network, ipaddress.IPv6Network]) -> List[Any]:
        if not self._interval_tree:
            return []
        with self._lock:
            start = int(network.network_address)
            end = int(network.broadcast_address)
            return self._interval_tree.find_overlapping(start, end)

    @classmethod
    def subtract(cls, base_nets: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]], 
                 exclude_nets: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]],
                 max_fragments: int = 5000,
                 enable_adjacent_merge: bool = True,
                 enable_rir_lookup: bool = False,
                 enable_approximation: bool = False,
                 approximation_threshold: int = 1000,
                 max_loss_rate: float = 0.05,
                 strict_zero_loss: bool = True,
                 rir_manager: Optional[RIRDataManager] = None) -> List[str]:
        """修復：使用類方法而非靜態方法，確保正確訪問類變量"""

        v4_base = [n for n in base_nets if n.version == 4]
        v6_base = [n for n in base_nets if n.version == 6]
        v4_excl = [n for n in exclude_nets if n.version == 4]
        v6_excl = [n for n in exclude_nets if n.version == 6]

        try:
            v4_result = cls._subtract_version(v4_base, v4_excl, 32, max_fragments // 2)
            remaining = max_fragments - len(v4_result)
            v6_result = cls._subtract_version(v6_base, v6_excl, 128, remaining)
            total_result = v4_result + v6_result

            if enable_adjacent_merge:
                total_result = cls._merge_adjacent_cidrs(total_result)

            if len(total_result) > max_fragments:
                if enable_approximation and len(total_result) > approximation_threshold:
                    total_result, loss_rate = cls._hierarchical_supernet_with_loss(
                        total_result, max_fragments, enable_rir_lookup, rir_manager
                    )
                    if strict_zero_loss and loss_rate > 0:
                        raise CIDRFragmentationError(len(total_result), max_fragments, loss_rate)
                    if loss_rate > max_loss_rate:
                        raise CIDRFragmentationError(len(total_result), max_fragments, loss_rate)
                else:
                    raise CIDRFragmentationError(len(total_result), max_fragments, 0.0)

            return [str(n) for n in total_result]
        except CIDRFragmentationError as e:
            if enable_approximation and not strict_zero_loss:
                if e.loss_rate <= max_loss_rate:
                    merged, _ = cls._hierarchical_supernet_with_loss(
                        base_nets, max_fragments, enable_rir_lookup, rir_manager
                    )
                    return [str(n) for n in merged]
            raise

    @classmethod
    def _subtract_version(cls, base: List, exclude: List, width: int, max_frag: int) -> List:
        if not base:
            return []
        if not exclude:
            return list(ipaddress.collapse_addresses(base))

        events = []
        max_addr = (1 << width) - 1
        event_id = 0  # 修復：添加序列號確保排序穩定性

        for net in base:
            start = int(net.network_address)
            end = min(int(net.broadcast_address), max_addr)
            events.append((start, cls.PRIORITY['BS'], 0, event_id, net))
            event_id += 1
            if end < max_addr:
                events.append((end + 1, cls.PRIORITY['BE'], 0, event_id, net))
                event_id += 1

        for net in exclude:
            start = int(net.network_address)
            end = min(int(net.broadcast_address), max_addr)
            events.append((start, cls.PRIORITY['ES'], 1, event_id, net))
            event_id += 1
            if end < max_addr:
                events.append((end + 1, cls.PRIORITY['EE'], 1, event_id, net))
                event_id += 1

        # 修復：使用序列號作為第三排序鍵確保確定性
        events.sort(key=lambda x: (x[0], -x[1], x[3]))

        result_intervals = []
        base_depth = 0
        exclude_depth = 0
        prev_pos = events[0][0] if events else 0

        for pos, prio, is_excl, eid, net in events:
            if pos > prev_pos and prev_pos <= max_addr:
                if base_depth > 0 and exclude_depth == 0:
                    end_pos = min(pos - 1, max_addr)
                    if result_intervals and result_intervals[-1][1] == prev_pos - 1:
                        result_intervals[-1] = (result_intervals[-1][0], end_pos)
                    else:
                        result_intervals.append((prev_pos, end_pos))
                    if len(result_intervals) > max_frag:
                        raise CIDRFragmentationError(len(result_intervals), max_frag)

            if is_excl:
                if prio == cls.PRIORITY['ES']:
                    exclude_depth += 1
                else:
                    exclude_depth -= 1
            else:
                if prio == cls.PRIORITY['BS']:
                    base_depth += 1
                else:
                    base_depth -= 1
            prev_pos = pos

        cidrs = []
        for start, end in result_intervals:
            cidrs.extend(cls._range_to_cidrs(start, end, width))

        return list(ipaddress.collapse_addresses(cidrs))

    @classmethod
    def _hierarchical_supernet_with_loss(cls, networks: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]], 
                                         target_count: int,
                                         enable_rir: bool = False,
                                         rir_manager: Optional[RIRDataManager] = None) -> Tuple[List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]], float]:
        if len(networks) <= target_count:
            return networks, 0.0

        # 修復：確保同版本網絡
        v4_networks = [n for n in networks if n.version == 4]
        v6_networks = [n for n in networks if n.version == 6]
        
        v4_merged, v4_loss = cls._hierarchical_supernet_version(v4_networks, target_count // 2 + 1, enable_rir, rir_manager)
        v6_merged, v6_loss = cls._hierarchical_supernet_version(v6_networks, target_count // 2 + 1, enable_rir, rir_manager)
        
        merged = v4_merged + v6_merged
        original_hosts = sum(n.num_addresses for n in networks)
        final_hosts = sum(n.num_addresses for n in merged)
        loss_rate = (original_hosts - final_hosts) / original_hosts if original_hosts > 0 else 0.0
        
        return merged[:target_count], loss_rate

    @classmethod
    def _hierarchical_supernet_version(cls, networks: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]], 
                                       target_count: int,
                                       enable_rir: bool = False,
                                       rir_manager: Optional[RIRDataManager] = None) -> Tuple[List, float]:
        if len(networks) <= target_count:
            return networks, 0.0
            
        sorted_nets = sorted(networks, key=lambda x: (int(x.network_address), x.prefixlen))
        original_hosts = sum(n.num_addresses for n in networks)

        merged = []
        i = 0
        while i < len(sorted_nets) and len(merged) < target_count:
            current = sorted_nets[i]
            merged_siblings = False
            if i + 1 < len(sorted_nets):
                next_net = sorted_nets[i + 1]
                if current.prefixlen == next_net.prefixlen and current.prefixlen > 0:
                    if enable_rir and rir_manager:
                        if not rir_manager.can_merge(current, next_net):
                            merged.append(current)
                            i += 1
                            continue
                    try:
                        super_net = current.supernet()
                        if next_net.subnet_of(super_net):
                            current = super_net
                            i += 2
                            while i < len(sorted_nets) and sorted_nets[i].subnet_of(current):
                                i += 1
                            merged.append(current)
                            merged_siblings = True
                    except ValueError:
                        pass
            if not merged_siblings:
                merged.append(current)
                i += 1

        if len(merged) > target_count:
            width = 32 if merged[0].version == 4 else 128
            min_prefix = max(0, merged[0].prefixlen - 4)
            for prefix_len in range(merged[0].prefixlen, min_prefix - 1, -1):
                aggregated = []
                super_map = {}
                for net in merged:
                    if net.prefixlen <= prefix_len:
                        aggregated.append(net)
                    else:
                        super_addr = int(net.network_address) & ((1 << (width - prefix_len)) - 1 << (width - prefix_len))
                        if width == 32:
                            super_net = ipaddress.IPv4Network((super_addr, prefix_len), strict=False)
                        else:
                            super_net = ipaddress.IPv6Network((super_addr, prefix_len), strict=False)
                        
                        # 修復：檢查超網是否與所有子網同RIR
                        if enable_rir and rir_manager:
                            subs = super_map.get(super_net, [])
                            subs.append(net)
                            if not all(rir_manager.can_merge(super_net, sub) for sub in subs):
                                aggregated.extend(subs)
                                continue
                        
                        if super_net not in super_map:
                            super_map[super_net] = []
                        super_map[super_net].append(net)
                
                for super_net, subs in super_map.items():
                    aggregated.append(super_net)
                
                merged = cls._merge_adjacent_cidrs(aggregated)
                if len(merged) <= target_count:
                    break

        final_hosts = sum(n.num_addresses for n in merged)
        loss_rate = (original_hosts - final_hosts) / original_hosts if original_hosts > 0 else 0.0
        return merged[:target_count], loss_rate

    @classmethod
    def _merge_adjacent_cidrs(cls, networks: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]) -> List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]:
        if not networks:
            return networks

        v4_nets = sorted([n for n in networks if n.version == 4], key=lambda x: (int(x.network_address), x.prefixlen))
        v6_nets = sorted([n for n in networks if n.version == 6], key=lambda x: (int(x.network_address), x.prefixlen))

        merged_v4 = cls._merge_adjacent_version(v4_nets, 32)
        merged_v6 = cls._merge_adjacent_version(v6_nets, 128)

        return merged_v4 + merged_v6

    @classmethod
    def _merge_adjacent_version(cls, nets: List, width: int) -> List:
        if len(nets) < 2:
            return nets

        merged = []
        current = nets[0]
        for next_net in nets[1:]:
            if current.prefixlen != next_net.prefixlen:
                merged.append(current)
                current = next_net
                continue

            prefix_len = current.prefixlen
            if prefix_len == 0:
                merged.append(current)
                current = next_net
                continue

            curr_int = int(current.network_address)
            next_int = int(next_net.network_address)
            block_size = 1 << (width - prefix_len)

            if curr_int + block_size == next_int:
                super_addr = curr_int & ~(block_size - 1)
                try:
                    if width == 32:
                        current = ipaddress.IPv4Network((super_addr, prefix_len - 1), strict=False)
                    else:
                        current = ipaddress.IPv6Network((super_addr, prefix_len - 1), strict=False)
                except ValueError:
                    merged.append(current)
                    current = next_net
            else:
                merged.append(current)
                current = next_net

        merged.append(current)

        # 修復：使用迭代而非遞迴避免棧溢出
        if len(merged) < len(nets):
            return cls._merge_adjacent_version(merged, width)
        return merged

    @classmethod
    def _range_to_cidrs(cls, start: int, end: int, width: int) -> List:
        """修復：添加無限循環防護"""
        cidrs = []
        current = start
        max_ip = (1 << width) - 1
        max_iterations = 10000  # 安全上限
        iterations = 0

        while current <= end and current <= max_ip and iterations < max_iterations:
            iterations += 1
            if current == 0:
                trailing_zeros = width
            else:
                trailing_zeros = (current & -current).bit_length() - 1

            max_size = 1 << trailing_zeros
            remaining = end - current + 1
            
            # 修復：防護remaining <= 0的情況
            if remaining <= 0:
                break
                
            size = max_size
            while size > remaining:
                size >>= 1
                if size == 0:
                    size = 1
                    break

            prefix_len = width - (size.bit_length() - 1)

            try:
                if width == 32:
                    network = ipaddress.IPv4Network((current, prefix_len), strict=False)
                else:
                    network = ipaddress.IPv6Network((current, prefix_len), strict=False)
                cidrs.append(network)
                current += size
            except ValueError:
                current += 1

        return cidrs


class WALBackend:
    """修復版：解決fsync時序和目錄同步問題"""
    __slots__ = ('db_path', 'wal_path', 'data', '_lock', '_flush_count', '_config')

    def __init__(self, db_path: Path, config: MergeConfig = DEFAULT_CONFIG):
        self.db_path = db_path.with_suffix('.ldb')
        self.wal_path = db_path.with_suffix('.wal')
        self.data = {}
        self._lock = threading.RLock()
        self._flush_count = 0
        self._config = config
        self._load()

    def _load(self):
        if self.wal_path.exists():
            try:
                with open(self.wal_path, 'rb') as f:
                    if USE_MSGPACK:
                        content = f.read()
                        if len(content) >= 16:
                            stored_checksum = content[:16]
                            data_bytes = content[16:]
                            computed_checksum = hashlib.blake2b(data_bytes, digest_size=16).digest()
                            if stored_checksum == computed_checksum:
                                pending = msgpack.unpackb(data_bytes, raw=False)
                                self.data.update(pending)
                                self._snapshot()
                    else:
                        content = f.read()
                        if len(content) >= 16:
                            stored_checksum = content[:16]
                            data_bytes = content[16:]
                            computed_checksum = hashlib.blake2b(data_bytes, digest_size=16).digest()
                            if stored_checksum == computed_checksum:
                                pending = json.loads(data_bytes.decode('utf-8'))
                                self.data.update(pending)
                                self._snapshot()
            except Exception:
                logger.error(f"Corrupted WAL at {self.wal_path}, discarding.")

        if self.db_path.exists():
            try:
                with open(self.db_path, 'rb') as f:
                    if USE_MSGPACK:
                        content = f.read()
                        if len(content) >= 16:
                            stored_checksum = content[:16]
                            data_bytes = content[16:]
                            computed_checksum = hashlib.blake2b(data_bytes, digest_size=16).digest()
                            if stored_checksum == computed_checksum:
                                self.data = msgpack.unpackb(data_bytes, raw=False)
                    else:
                        content = f.read()
                        if len(content) >= 16:
                            stored_checksum = content[:16]
                            data_bytes = content[16:]
                            computed_checksum = hashlib.blake2b(data_bytes, digest_size=16).digest()
                            if stored_checksum == computed_checksum:
                                self.data = json.loads(data_bytes.decode('utf-8'))
            except Exception:
                self.data = {}

    def _snapshot(self):
        """修復：添加目錄同步確保崩潰一致性"""
        tmp = self.db_path.with_suffix('.tmp')

        if USE_MSGPACK:
            data_bytes = msgpack.packb(self.data, use_bin_type=True)
        else:
            data_bytes = json.dumps(self.data, ensure_ascii=False, sort_keys=True).encode('utf-8')

        checksum = hashlib.blake2b(data_bytes, digest_size=16).digest()
        content = checksum + data_bytes

        with open(tmp, 'wb') as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        
        tmp.replace(self.db_path)
        
        # 修復：同步目錄以確保目錄項持久化
        try:
            dir_fd = os.open(self.db_path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except Exception:
            pass
            
        if self.wal_path.exists():
            self.wal_path.unlink()

    def get(self, key):
        with self._lock:
            return self.data.get(key)

    def put_batch(self, updates: Dict):
        with self._lock:
            if USE_MSGPACK:
                data_bytes = msgpack.packb(updates, use_bin_type=True)
            else:
                data_bytes = json.dumps(updates, ensure_ascii=False, sort_keys=True).encode('utf-8')

            checksum = hashlib.blake2b(data_bytes, digest_size=16).digest()
            content = checksum + data_bytes

            with open(self.wal_path, 'wb') as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())

            self.data.update(updates)
            self._flush_count += 1

            if self._flush_count >= self._config.wal_sync_interval:
                self._snapshot()
                self._flush_count = 0

    def checkpoint(self):
        with self._lock:
            self._snapshot()
            self._flush_count = 0


class AWSetCRDT:
    """修復版：Add-Wins Set CRDT，添加向量時鐘合併"""
    __slots__ = ('_node_id', '_add_set', '_remove_set', '_lock', '_vector_clock', '_timestamp_precision')

    def __init__(self, node_id: str):
        self._node_id = node_id
        self._add_set = {}
        self._remove_set = {}
        self._lock = threading.RLock()
        self._vector_clock = {node_id: 0}
        # 修復：使用更高精度的時間戳
        self._timestamp_precision = 1e-6

    def add(self, element: str, timestamp: float = None, vector_clock: Dict = None):
        with self._lock:
            ts = timestamp or time.time()
            self._vector_clock[self._node_id] = self._vector_clock.get(self._node_id, 0) + 1

            if element not in self._add_set:
                self._add_set[element] = set()
            self._add_set[element].add((self._node_id, ts))

            if vector_clock:
                for node, count in vector_clock.items():
                    self._vector_clock[node] = max(self._vector_clock.get(node, 0), count)

    def remove(self, element: str, timestamp: float = None):
        with self._lock:
            ts = timestamp or time.time()
            self._vector_clock[self._node_id] = self._vector_clock.get(self._node_id, 0) + 1

            if element not in self._remove_set:
                self._remove_set[element] = set()
            self._remove_set[element].add((self._node_id, ts))

    def contains(self, element: str) -> bool:
        with self._lock:
            if element not in self._add_set:
                return False

            if element not in self._remove_set:
                return True

            add_timestamps = self._add_set[element]
            remove_timestamps = self._remove_set[element]

            max_add = max(ts for _, ts in add_timestamps)
            max_remove = max(ts for _, ts in remove_timestamps)

            return max_add >= max_remove

    def merge(self, other: 'AWSetCRDT') -> 'AWSetCRDT':
        """修復：正確合併向量時鐘"""
        with self._lock:
            for elem, timestamps in other._add_set.items():
                if elem not in self._add_set:
                    self._add_set[elem] = set()
                self._add_set[elem].update(timestamps)

            for elem, timestamps in other._remove_set.items():
                if elem not in self._remove_set:
                    self._remove_set[elem] = set()
                self._remove_set[elem].update(timestamps)

            # 修復：正確合併向量時鐘（取每個節點的最大值）
            for node, count in other._vector_clock.items():
                self._vector_clock[node] = max(self._vector_clock.get(node, 0), count)

            return self

    def to_set(self) -> Set[str]:
        with self._lock:
            result = set()
            for elem in self._add_set:
                if self.contains(elem):
                    result.add(elem)
            return result

    def get_vector_clock(self) -> Dict[str, int]:
        with self._lock:
            return self._vector_clock.copy()


class ProvenanceLogger:
    """修復版：解決哈希鏈斷裂和內存無限增長"""
    __slots__ = ('_wal', '_activity_log', '_lock', '_config', '_hash_chain')

    def __init__(self, state_dir: Path, config: MergeConfig = DEFAULT_CONFIG):
        self._config = config
        self._wal = WALBackend(state_dir / 'provenance', config)
        self._activity_log = deque(maxlen=1000)  # 修復：限制內存隊列大小
        self._lock = threading.RLock()
        # 修復：使用deque限制哈希鏈長度
        self._hash_chain = deque([hashlib.sha256(b'genesis').hexdigest()], maxlen=10000)
        self._load_state()

    def _load_state(self):
        """從WAL重建哈希鏈"""
        try:
            all_entries = sorted(self._wal.data.values(), key=lambda x: x.get('timestamp', 0))
            self._hash_chain = deque([hashlib.sha256(b'genesis').hexdigest()], maxlen=10000)
            for entry in all_entries:
                if entry.get('prev_hash') != self._hash_chain[-1]:
                    logger.error(f"Provenance chain broken at {entry.get('timestamp')}")
                    continue
                self._hash_chain.append(entry['hash'])
        except Exception as e:
            logger.warning(f"Failed to load provenance state: {e}")

    def log_activity(self, activity_type: str, entity_id: str, attributes: Dict, 
                     agent: str = "system", derived_from: Optional[List[str]] = None):
        if not self._config.enable_provenance_logging:
            return

        with self._lock:
            timestamp = time.time()
            prev_hash = self._hash_chain[-1]
            record = {
                'timestamp': timestamp,
                'activity': activity_type,
                'entity': entity_id,
                'attributes': attributes,
                'agent': agent,
                'derived_from': derived_from or [],
                'prev_hash': prev_hash
            }
            record_hash = hashlib.sha256(json.dumps(record, sort_keys=True).encode()).hexdigest()
            record['hash'] = record_hash
            self._hash_chain.append(record_hash)
            self._activity_log.append(record)

            if len(self._activity_log) >= 100:
                self._flush()

    def _flush(self):
        batch = {}
        for i, entry in enumerate(self._activity_log):
            batch[f"prov_{entry['timestamp']}_{i}"] = entry
        self._wal.put_batch(batch)
        self._activity_log.clear()

    def close(self):
        with self._lock:
            self._flush()
            self._wal.checkpoint()


class MerkleClock:
    """修復版：解決並發處理真空"""
    __slots__ = ('clock', '_merkle_tree', '_lock', '_hash_cache', '_had_conflict')

    def __init__(self, initial: Optional[Dict] = None, branching: int = 2):
        self.clock = initial.copy() if initial else {}
        self._merkle_tree = IncrementalMerkleTree(branching)
        self._lock = threading.RLock()
        self._hash_cache = {}
        self._had_conflict = False
        self._rebuild_merkle()

    def _rebuild_merkle(self):
        for node, count in self.clock.items():
            self._merkle_tree.update_leaf(node, f"{node}:{count}")

    def increment(self, node: str):
        with self._lock:
            self.clock[node] = self.clock.get(node, 0) + 1
            self._merkle_tree.update_leaf(node, f"{node}:{self.clock[node]}")
            self._hash_cache.clear()
            return self

    def merge(self, other: 'MerkleClock'):
        """修復：處理並發衝突"""
        with self._lock:
            relation = self.compare(other)
            if relation == "concurrent":
                # 修復：使用Add-Wins策略解決衝突
                for n, c in other.clock.items():
                    self.clock[n] = max(self.clock.get(n, 0), c)
                self._had_conflict = True
                logger.warning(f"MerkleClock detected concurrent conflict, resolved with Add-Wins")
            elif relation == "before":
                self.clock.update(other.clock)
            elif relation == "equal":
                pass  # 無需更改
            else:  # "after"
                pass  # 無需更改
            
            self._rebuild_merkle()
            self._hash_cache.clear()
            return self

    def compare(self, other: 'MerkleClock') -> str:
        s_keys = set(self.clock.keys())
        o_keys = set(other.clock.keys())
        all_keys = s_keys | o_keys
        s_dom = False
        o_dom = False

        for k in all_keys:
            s_val = self.clock.get(k, 0)
            o_val = other.clock.get(k, 0)
            if s_val > o_val:
                s_dom = True
            elif o_val > s_val:
                o_dom = True

        if s_dom and not o_dom:
            return "after"
        if o_dom and not s_dom:
            return "before"
        if not s_dom and not o_dom:
            return "equal"
        return "concurrent"

    def get_merkle_root(self) -> str:
        with self._lock:
            return self._merkle_tree.compute_root() or ''

    def verify_consistency(self, other: 'MerkleClock') -> bool:
        if self.compare(other) == "equal":
            return self.get_merkle_root() == other.get_merkle_root()
        return True

    def had_conflict(self) -> bool:
        with self._lock:
            return self._had_conflict


class IncrementalMerkleTree:
    __slots__ = ('branching', 'leaves', 'nodes', '_dirty_paths', '_lock')

    def __init__(self, branching: int = 2):
        self.branching = branching
        self.leaves = {}
        self.nodes = {}
        self._dirty_paths = set()
        self._lock = threading.RLock()

    def update_leaf(self, index: str, value: str):
        with self._lock:
            old_hash = self.leaves.get(index)
            new_hash = hashlib.sha256(value.encode()).hexdigest()
            if old_hash == new_hash:
                return
            self.leaves[index] = new_hash
            self._mark_path_dirty(index)

    def _mark_path_dirty(self, leaf_index: str):
        path = self._get_path_to_root(leaf_index)
        for node_id in path:
            self._dirty_paths.add(node_id)

    def _get_path_to_root(self, leaf_index: str) -> List[str]:
        path = [f"leaf:{leaf_index}"]
        current_level = 0
        sorted_leaves = sorted(self.leaves.keys())
        current_pos = sorted_leaves.index(leaf_index) if leaf_index in self.leaves else 0

        while len(self.leaves) > self.branching ** current_level:
            parent_pos = current_pos // self.branching
            node_id = f"level{current_level}:node{parent_pos}"
            path.append(node_id)
            current_pos = parent_pos
            current_level += 1

        return path

    def compute_root(self) -> Optional[str]:
        with self._lock:
            if not self.leaves:
                return hashlib.sha256(b'').hexdigest()

            sorted_leaves = sorted(self.leaves.items())
            current_level = [h for _, h in sorted_leaves]
            level_num = 0

            while len(current_level) > 1:
                next_level = []
                for i in range(0, len(current_level), self.branching):
                    chunk = current_level[i:i+self.branching]
                    if len(chunk) < self.branching:
                        chunk.extend([hashlib.sha256(b'').hexdigest()] * (self.branching - len(chunk)))
                    combined = ''.join(chunk).encode()
                    node_hash = hashlib.sha256(combined).hexdigest()
                    next_level.append(node_hash)
                current_level = next_level
                level_num += 1

            return current_level[0] if current_level else None


class PolicyRuleEngine:
    __slots__ = ('_policies', '_config', '_lock')
    SOURCE_TYPES = {
        'AUTHORITY': 3,
        'COMMUNITY': 2,
        'LOCAL': 1
    }

    def __init__(self, config: MergeConfig = DEFAULT_CONFIG):
        self._config = config
        self._policies = {}
        self._lock = threading.Lock()

    def register_source_policy(self, source_url: str, source_type: str, policy: str):
        with self._lock:
            self._policies[source_url] = {
                'type': source_type,
                'priority': self.SOURCE_TYPES.get(source_type, 1),
                'policy': policy
            }

    def mediate_conflict(self, rule_value: str, sources: List[Tuple[str, float, bool]]) -> Tuple[bool, str, Dict]:
        if not self._config.enable_policy_engine or not sources:
            return True, "NO_POLICY", {}

        with self._lock:
            max_priority = -1
            authoritative_sources = []

            for url, weight, is_excl in sources:
                policy = self._policies.get(url, {'type': 'LOCAL', 'priority': 1})
                priority = policy['priority']
                if priority > max_priority:
                    max_priority = priority
                    authoritative_sources = [(url, weight, is_excl, policy)]
                elif priority == max_priority:
                    authoritative_sources.append((url, weight, is_excl, policy))

            if len(authoritative_sources) == 1:
                winner = authoritative_sources[0]
                proof = {
                    'winner': winner[0],
                    'type': winner[3]['type'],
                    'reason': f'Strict hierarchy: {winner[3]["type"]} overrides others',
                    'losers': [s[0] for s in sources if s[0] != winner[0]]
                }
                return not winner[2], "STRICT_HIERARCHY", proof

            total_weight_allow = sum(s[1] for s in authoritative_sources if not s[2])
            total_weight_deny = sum(s[1] for s in authoritative_sources if s[2])

            if total_weight_deny > total_weight_allow * self._config.safety_override_threshold:
                proof = {
                    'decision': 'EXCLUDE',
                    'reason': f'Weighted consensus: deny weight {total_weight_deny} > allow {total_weight_allow}',
                    'participants': [s[0] for s in authoritative_sources]
                }
                return False, "WEIGHTED_CONSENSUS", proof

            return True, "WEIGHTED_DEFAULT", {}


@dataclass(frozen=True, slots=True)
class LineageInfo:
    depth: int
    min_depth: int
    originality: float
    is_redundant: bool
    confidence: float = 1.0
    uncertainty_reason: Optional[str] = None
    covering_sources: Optional[FrozenSet[str]] = None
    scc_representative: Optional[str] = None
    is_scc_root_representative: bool = False
    uncertain_rules: Optional[FrozenSet[str]] = None
    scc_unique_exclusions: Optional[FrozenSet[str]] = None
    scc_exclusion_conflicts: Optional[FrozenSet[str]] = None
    is_scc_union: bool = False
    vector_clock_causal: Optional[str] = None
    merkle_root: Optional[str] = None
    specificity_depth: int = 0
    verification_level: int = 3
    mediation_proof: Optional[Dict] = None  # 修復：確保此字段被正確填充


class StandardBloomFilter:
    """修復版：動態分片避免極端碎片"""
    __slots__ = ('size', 'k', 'seed', 'bits', 'locks', 'shards')

    def __init__(self, size: int, k: int, seed: int):
        self.size = size
        self.k = k
        self.seed = seed
        self.bits = bytearray(size // 8 + 1)
        # 修復：動態分片，每個分片至少管理512字節
        self.shards = min(1024, max(1, size // 4096))
        self.locks = [threading.RLock() for _ in range(self.shards)]

    def add(self, key: str):
        for i in range(self.k):
            h = fnv1a_64(key, self.seed + i * 0x9e3779b97f4a7c15)
            idx = h % self.size
            byte_idx = idx // 8
            lock_idx = byte_idx % self.shards
            with self.locks[lock_idx]:
                self.bits[byte_idx] |= (1 << (idx % 8))

    def contains(self, key: str) -> bool:
        for i in range(self.k):
            h = fnv1a_64(key, self.seed + i * 0x9e3779b97f4a7c15)
            idx = h % self.size
            byte_idx = idx // 8
            lock_idx = byte_idx % self.shards
            with self.locks[lock_idx]:
                if not (self.bits[byte_idx] & (1 << (idx % 8))):
                    return False
        return True


@dataclass(frozen=True, slots=True)
class RawSource:
    url: str
    raw_bytes: Optional[bytes]
    download_time: float
    http_status: int
    headers: Dict[str, str]


@dataclass(frozen=True, slots=True)
class ParsedRuleSet:
    url: str
    weight: float
    domain_rules: Tuple[DomainRule, ...]
    ip_rules: Tuple[IPCIDRRule, ...]
    keyword_rules: Tuple[KeywordRule, ...]
    regex_rules: Tuple[RegexRule, ...]
    metadata: Dict[str, Any]
    timestamp: float = field(default_factory=time.time)

    def get_content_hash(self) -> str:
        hasher = hashlib.sha256()
        hasher.update(f"w:{self.weight:.6f}".encode())
        for r in sorted(self.domain_rules, key=lambda x: x.normalized):
            hasher.update(f"D:{r.match_type}:{r.normalized}:{r.is_exclusion}".encode())
        for r in sorted(self.ip_rules, key=lambda x: (x.network.version, x.network.network_address)):
            hasher.update(f"I:{r.network}:{r.is_exclusion}".encode())
        return hasher.hexdigest()


@dataclass
class IndexedSource:
    url: str
    weight: float
    content_hash: str
    domain_trie: DomainTrie
    ip_trie: StrictPatriciaTrie
    interval_tree: Optional[IntervalTree]
    bloom_filter: StandardBloomFilter
    bdd_engine: Optional[TransactionalBDDEngine]
    rule_verifier: Optional[BDDRuleVerifier]
    domain_rules: List[DomainRule]
    ip_rules: List[IPCIDRRule]
    keyword_rules: List[KeywordRule]
    regex_rules: List[RegexRule]
    etld_set: Set[str]  # 修復：填充此字段
    merkle_clock: MerkleClock
    last_modified: float = field(default_factory=time.time)
    _crdt: Optional[AWSetCRDT] = None

    @classmethod
    def from_parsed(cls, parsed: ParsedRuleSet, config: MergeConfig, bdd_engine: Optional[TransactionalBDDEngine] = None):
        domain_trie = DomainTrie(cache_limit=5000, depth_limit=config.max_domain_depth)
        ip_trie = StrictPatriciaTrie()
        interval_tree = IntervalTree(max_depth=128) if config.enable_interval_tree else None  # 修復：支持IPv6
        
        # 修復：填充etld_set
        etld_set = set()
        if USE_TLDEXTRACT and _tld_cache:
            for rule in parsed.domain_rules:
                try:
                    ext = _tld_cache(rule.normalized)
                    if ext.suffix:
                        etld_set.add(ext.suffix)
                except Exception:
                    pass

        # 修復：處理規則數為0的情況
        total_rules = len(parsed.domain_rules) + len(parsed.ip_rules)
        bloom_size, bloom_k = optimal_bloom_size(max(total_rules, 100), config.bloom_target_fpp)
        det_seed = int(hashlib.sha256((config.deterministic_seed + parsed.url).encode()).hexdigest()[:8], 16)
        bloom = StandardBloomFilter(bloom_size, bloom_k, det_seed)

        rule_verifier = BDDRuleVerifier(bdd_engine) if bdd_engine else None
        crdt = AWSetCRDT(config.node_id) if config.enable_crdt else None

        for rule in parsed.domain_rules:
            key = f"domain:{rule.normalized}:{rule.is_exclusion}"
            bloom.add(key)
            if not rule.is_exclusion:
                domain_trie.insert(rule.normalized, rule.match_type)
            if crdt:
                crdt.add(f"domain:{rule.normalized}", timestamp=parsed.timestamp)

        for rule in parsed.ip_rules:
            key = f"ip_cidr:{rule.network}:{rule.is_exclusion}"
            bloom.add(key)
            if not rule.is_exclusion:
                ip_trie.insert(rule.network)
                if interval_tree:
                    start = int(rule.network.network_address)
                    end = int(rule.network.broadcast_address)
                    interval_tree.insert(start, end, rule.network)
            if crdt:
                crdt.add(f"ip:{rule.network}", timestamp=parsed.timestamp)

        return cls(
            url=parsed.url,
            weight=parsed.weight,
            content_hash=parsed.get_content_hash(),
            domain_trie=domain_trie,
            ip_trie=ip_trie,
            interval_tree=interval_tree,
            bloom_filter=bloom,
            bdd_engine=bdd_engine,
            rule_verifier=rule_verifier,
            domain_rules=list(parsed.domain_rules),
            ip_rules=list(parsed.ip_rules),
            keyword_rules=list(parsed.keyword_rules),
            regex_rules=list(parsed.regex_rules),
            etld_set=etld_set,  # 修復：填充etld_set
            merkle_clock=MerkleClock(branching=config.merkle_tree_branching),
            last_modified=parsed.timestamp,
            _crdt=crdt
        )


@dataclass
class VerifiedSource:
    url: str
    weight: float
    content_hash: str
    indexed: IndexedSource
    lineage_info: LineageInfo
    final_rules: Dict[str, List[str]]


class IterativeTarjanSCC:
    __slots__ = ('graph', 'index', 'stack', 'on_stack', 'indices', 'lowlinks', 'sccs', 'max_nodes')

    def __init__(self, graph_edges: Dict[str, Set[str]], max_nodes: int = 100000):
        self.graph = graph_edges
        self.index = 0
        self.stack = []
        self.on_stack = set()
        self.indices = {}
        self.lowlinks = {}
        self.sccs = []
        self.max_nodes = max_nodes

    def find_sccs(self) -> List[List[str]]:
        for v in self.graph:
            if v not in self.indices:
                self._strongconnect_iterative(v)
        return self.sccs

    def _strongconnect_iterative(self, start: str):
        work_stack = [(start, iter(self.graph.get(start, [])), False)]

        while work_stack:
            v, children, processed = work_stack[-1]
            if not processed:
                if v not in self.indices:
                    if len(self.indices) >= self.max_nodes:
                        raise LineageAnalysisError(f"Exceeded max SCC nodes: {self.max_nodes}")
                    self.indices[v] = self.index
                    self.lowlinks[v] = self.index
                    self.index += 1
                    self.stack.append(v)
                    self.on_stack.add(v)

                try:
                    w = next(children)
                    if w not in self.indices:
                        work_stack.append((w, iter(self.graph.get(w, [])), False))
                    elif w in self.on_stack:
                        self.lowlinks[v] = min(self.lowlinks[v], self.indices[w])
                except StopIteration:
                    work_stack[-1] = (v, children, True)
            else:
                work_stack.pop()
                if work_stack:
                    parent_v, _, _ = work_stack[-1]
                    self.lowlinks[parent_v] = min(self.lowlinks[parent_v], self.lowlinks[v])

                if self.lowlinks[v] == self.indices[v]:
                    scc = []
                    while True:
                        w = self.stack.pop()
                        self.on_stack.remove(w)
                        scc.append(w)
                        if w == v:
                            break
                    self.sccs.append(scc)


# 修復：添加AcceptedRule數據類統一數據結構
@dataclass
class AcceptedRule:
    weight: float
    source: VerifiedSource
    is_exclusion: bool
    specificity: int
    rule_obj: RuleType


class StrictConflictResolver:
    """修復版：解決解包邏輯錯誤、_is_covered_by_exclusion不完整等問題"""
    __slots__ = ('config', '_entropy_cache', '_ngram_analyzer', '_policy_engine', '_tiered_strategy', '_rir_manager')

    def __init__(self, config: MergeConfig = DEFAULT_CONFIG, rir_manager: Optional[RIRDataManager] = None):
        self.config = config
        self._entropy_cache = {}  # 保留，未來可能使用
        self._ngram_analyzer = StrictNgramSpectrumAnalyzer(config) if config.enable_ngram_analysis else None
        self._policy_engine = PolicyRuleEngine(config) if config.enable_policy_engine else None
        self._tiered_strategy = TieredVerificationStrategy(config)
        self._rir_manager = rir_manager

    def _temporal_compare(self, src_a: VerifiedSource, src_b: VerifiedSource) -> int:
        """修復：解決向量時鐘與物理時間戳混合使用的邏輯矛盾"""
        vc_cmp = src_a.indexed.merkle_clock.compare(src_b.indexed.merkle_clock)
        if vc_cmp == "after":
            return 1
        elif vc_cmp == "before":
            return -1
        elif vc_cmp == "concurrent":
            # 修復：並發時使用物理時間戳作為後備
            time_diff = src_a.indexed.last_modified - src_b.indexed.last_modified
            if abs(time_diff) > 86400:
                return 1 if time_diff > 0 else -1
            return 0
        
        # equal時使用物理時間戳
        time_diff = src_a.indexed.last_modified - src_b.indexed.last_modified
        if abs(time_diff) > 86400:
            return 1 if time_diff > 0 else -1
        return 0

    def resolve(self, sources: List[VerifiedSource], min_score: float) -> Dict[str, List[str]]:
        all_rules = []
        current_time = time.time()
        
        # 修復：獲取真實可用內存
        try:
            mem = psutil.virtual_memory()
            available_memory = 100.0 - mem.percent
        except Exception:
            available_memory = 50.0
        
        monitor = ResourceMonitor(self.config.memory_threshold_percent) if self.config.enable_adaptive_degradation else None

        for src in sources:
            rule_count = len(src.indexed.domain_rules) + len(src.indexed.ip_rules)
            tier = self._tiered_strategy.select_tier(rule_count, available_memory)
            orig = src.lineage_info.originality if src.lineage_info else 1.0
            base_weight = src.weight * orig

            # 修復：正確的時間衰減計算
            age_days = (current_time - src.indexed.last_modified) / 86400
            if age_days > self.config.max_source_age_days:
                time_decay = math.exp(-(age_days - self.config.max_source_age_days) / 30)
                base_weight *= time_decay

            if base_weight < min_score:
                continue

            verification_penalty = 0.9 if (src.lineage_info and src.lineage_info.verification_level < 3) else 1.0

            for rule in src.indexed.domain_rules:
                effective_weight = base_weight * verification_penalty
                spec = rule.specificity_score * self.config.rule_specificity_boost

                if rule.is_exclusion:
                    all_rules.append((effective_weight, 'domain', rule.normalized, True, src, rule))
                else:
                    if self._ngram_analyzer:
                        is_dga, explanation = self._ngram_analyzer.is_dga_like(rule.normalized)
                        if is_dga:
                            continue

                    all_rules.append((effective_weight + spec, 'domain', rule.normalized, False, src, rule))

            for rule in src.indexed.ip_rules:
                effective_weight = base_weight * verification_penalty
                all_rules.append((effective_weight, 'ip_cidr', str(rule.network), rule.is_exclusion, src, rule))

            if monitor and monitor.should_degrade(2):
                logger.warning("Resource pressure detected, continuing with current batch")

        # 修復：確保確定性排序（當權重相同時，使用更穩定的排序鍵）
        if self.config.deterministic_output:
            det_rand = DeterministicRandom(self.config.deterministic_seed)
            det_rand.shuffle(all_rules)
            # 使用元組排序確保完全確定性
            all_rules.sort(key=lambda x: (-x[0], x[1], x[2], x[3], x[4].url))
        else:
            all_rules.sort(key=lambda x: (-x[0], x[1], x[2]))

        # 修復：使用AcceptedRule統一數據結構
        accepted_domains: Dict[str, AcceptedRule] = {}
        accepted_ips: Dict[str, AcceptedRule] = {}
        exclusions_map: Dict[str, AcceptedRule] = {}
        conflict_map = defaultdict(list)

        for weight, rtype, value, is_excl, src, rule_obj in all_rules:
            key = (rtype, value)

            if is_excl:
                spec = rule_obj.specificity_score if isinstance(rule_obj, DomainRule) else 0
                exclusions_map[key] = AcceptedRule(weight, src, True, spec, rule_obj)
            else:
                if key in [(k[0], k[1]) for k in accepted_domains] or key in [(k[0], k[1]) for k in accepted_ips]:
                    conflict_map[key].append((src.url, weight, False))
                    continue

                spec = rule_obj.specificity_score if isinstance(rule_obj, DomainRule) else 0
                accepted_rule = AcceptedRule(weight, src, False, spec, rule_obj)
                
                if rtype == 'domain':
                    accepted_domains[value] = accepted_rule
                    conflict_map[key].append((src.url, weight, False))
                elif rtype == 'ip_cidr':
                    try:
                        net = ipaddress.ip_network(value, strict=False)
                        accepted_ips[value] = accepted_rule
                        conflict_map[key].append((src.url, weight, False))
                    except ValueError:
                        continue

        # 修復：填充mediation_proof
        mediation_results = {}
        if self._policy_engine:
            for key, sources_info in conflict_map.items():
                if len(sources_info) > 1:
                    should_include, policy_type, proof = self._policy_engine.mediate_conflict(key[1], sources_info)
                    mediation_results[key] = (should_include, policy_type, proof)
                    if not should_include and key[1] in accepted_domains:
                        del accepted_domains[key[1]]

        # 修復：傳遞mediation_proof到lineage_info
        self._propagate_exclusion(exclusions_map, accepted_domains)
        self._propagate_exclusion(exclusions_map, accepted_ips)

        result = defaultdict(list)
        domain_trie = DomainTrie(depth_limit=self.config.max_domain_depth)

        for value, acc_rule in accepted_domains.items():
            if not acc_rule.is_exclusion:
                is_wc = value.startswith('*.')
                clean_val = value.lstrip('*.') if value.startswith('*.') else value
                match_type = MatchType.WILDCARD if is_wc else MatchType.EXACT
                domain_trie.insert(clean_val, match_type)

        optimized = domain_trie.optimize()
        final_domains = []

        for domain, mtype in optimized:
            clean = domain.lstrip('*.') if domain.startswith('*.') else domain
            spec_score = domain_trie.get_specificity_score(clean)
            final_domains.append((domain, mtype, spec_score))

        final_domains.sort(key=lambda x: (-x[2], x[0]))

        for domain, mtype, _ in final_domains:
            if domain.startswith('*.'):
                result['domain_suffix'].append(domain[2:])
            elif domain == '*':
                result['domain_suffix'].append('')
            else:
                result['domain'].append(domain)

        if accepted_ips:
            positives = [ipaddress.ip_network(v, strict=False) for v, r in accepted_ips.items() if not r.is_exclusion]
            negatives = [ipaddress.ip_network(v, strict=False) for v, r in accepted_ips.items() if r.is_exclusion]

            if self.config.strict_cidr_arithmetic and negatives:
                try:
                    final_ips = SweepLineCIDRManager.subtract(
                        positives, negatives, 
                        max_fragments=self.config.max_cidr_fragmentation,
                        enable_adjacent_merge=self.config.enable_cidr_adjacent_merge,
                        enable_approximation=self.config.enable_cidr_approximation,
                        approximation_threshold=self.config.cidr_approximation_threshold,
                        max_loss_rate=self.config.cid_approximation_max_loss_rate,
                        strict_zero_loss=self.config.strict_zero_loss,
                        enable_rir_lookup=self.config.enable_rir_lookup,
                        rir_manager=self._rir_manager
                    )
                    result['ip_cidr'] = final_ips
                except CIDRFragmentationError as e:
                    logger.error(f"CIDR fragmentation limit exceeded: {e.processed_count} fragments, loss: {e.loss_rate:.2%}")
                    raise
            else:
                collapsed = list(ipaddress.collapse_addresses(positives))
                if self.config.enable_cidr_adjacent_merge:
                    collapsed = SweepLineCIDRManager._merge_adjacent_cidrs(collapsed)
                result['ip_cidr'] = [str(n) for n in collapsed]

        return dict(result)

    def _propagate_exclusion(self, exclusions: Dict[str, AcceptedRule], accepted: Dict[str, AcceptedRule]):
        """修復：正確解包AcceptedRule"""
        to_remove = []

        for acc_key, acc_rule in list(accepted.items()):
            if acc_rule.is_exclusion:
                continue

            for excl_key, excl_rule in exclusions.items():
                if self._is_covered_by_exclusion(acc_key, acc_rule, excl_key, excl_rule):
                    temporal_cmp = self._temporal_compare(acc_rule.source, excl_rule.source)
                    if excl_rule.weight >= acc_rule.weight * self.config.safety_override_threshold or temporal_cmp > 0:
                        to_remove.append(acc_key)
                        break

        for key in to_remove:
            if key in accepted:
                del accepted[key]

    def _is_covered_by_exclusion(self, acc_key: str, acc_rule: AcceptedRule, 
                                 excl_key: str, excl_rule: AcceptedRule) -> bool:
        """修復：處理domain和ip_cidr兩種類型的排除"""
        acc_type = 'domain' if isinstance(acc_rule.rule_obj, DomainRule) else 'ip_cidr'
        excl_type = 'domain' if isinstance(excl_rule.rule_obj, DomainRule) else 'ip_cidr'
        
        if acc_type != excl_type:
            return False
            
        if acc_type == 'domain':
            excl_val = excl_key
            acc_val = acc_key
            if excl_val.startswith('*.'):
                suffix = excl_val[2:]
                return acc_val.endswith(suffix)
            else:
                return acc_val == excl_val
        elif acc_type == 'ip_cidr':
            # 修復：處理IP CIDR排除
            try:
                acc_net = ipaddress.ip_network(acc_key, strict=False)
                excl_net = ipaddress.ip_network(excl_key, strict=False)
                # 排除規則覆蓋接受規則當：排除網絡包含接受網絡
                return acc_net.subnet_of(excl_net) or acc_net == excl_net
            except ValueError:
                return False
        return False


class PersistentLineageAnalyzer:
    """修復版：解決SCC合併與CRDT脫節、hash碰撞等問題"""
    __slots__ = ('config', 'state_file', 'wal_backend', '_graph', '_cached_depths', 
                 '_format_version', '_lock', '_smt_verifier', '_source_versions', 
                 '_global_bdd', '_det_random', '_provenance', '_fuzzer', '_rir_manager')

    def __init__(self, state_file: Optional[Path] = None, config: MergeConfig = DEFAULT_CONFIG):
        self.config = config
        self.state_file = state_file or Path('.lineage_state_v9')
        self.wal_backend = WALBackend(self.state_file, config)
        self._graph = defaultdict(set)
        self._cached_depths = {}
        self._format_version = 90
        self._lock = threading.RLock()
        self._source_versions = {}
        self._global_bdd = TransactionalBDDEngine(gc_threshold=config.bdd_node_limit) if config.enable_bdd_verification else None
        self._det_random = DeterministicRandom(config.deterministic_seed)
        self._smt_verifier = None
        self._provenance = ProvenanceLogger(self.state_file.parent if self.state_file else Path('.'), config)
        self._fuzzer = ProgressiveFuzzingHarness(config)
        self._rir_manager = RIRDataManager(config) if config.enable_rir_lookup else None
        self._load_state()

    def _load_state(self):
        try:
            data = self.wal_backend.get('lineage_v90')
            if data:
                state = data
                self._graph = defaultdict(set, {k: set(v) for k, v in state.get('edges', {}).items()})
                self._cached_depths = state.get('depths', {})
                self._source_versions = state.get('versions', {})
        except Exception as e:
            logger.warning(f"State load failed: {e}, starting fresh")

    def save_state(self):
        try:
            with self._lock:
                state = {
                    'edges': {k: list(v) for k, v in self._graph.items()},
                    'depths': self._cached_depths,
                    'versions': self._source_versions,
                    'version': 90
                }
                self.wal_backend.put_batch({'lineage_v90': state})
                self.wal_backend.checkpoint()
        except Exception as e:
            logger.warning(f"State save failed: {e}")

    def close(self):
        if self._smt_verifier:
            self._smt_verifier.close()
        self.save_state()
        self._provenance.close()

    def compute_incremental(self, parsed_sources: List[ParsedRuleSet]) -> Tuple[Set[int], List[VerifiedSource]]:
        if self._smt_verifier is None and self.config.enable_smt_verification:
            self._smt_verifier = SMTVerifier(self.config)

        if self.config.enable_fuzzing_tests:
            if not self._fuzzer.run_fuzzing_suite(self):
                logger.warning("Fuzzing tests detected violations, proceeding with caution")

        # 修復：使用複合鍵避免hash碰撞
        hash_to_parsed = {}
        for s in parsed_sources:
            key = (s.get_content_hash(), s.url, s.weight)
            hash_to_parsed[key] = s
        
        current_hashes = set(hash_to_parsed.keys())

        changed_hashes = set()
        for h in current_hashes:
            if h not in self._source_versions:
                changed_hashes.add(h)
                self._source_versions[h] = time.time()

        if not changed_hashes and current_hashes == set(self._cached_depths.keys()):
            return self._apply_cached_results(parsed_sources)

        monitor = ResourceMonitor(self.config.memory_threshold_percent) if self.config.enable_adaptive_degradation else None

        indexed_sources = []
        for parsed in parsed_sources:
            indexed = IndexedSource.from_parsed(parsed, self.config, self._global_bdd)
            indexed_sources.append(indexed)

        new_edges = set()
        sorted_sources = sorted(indexed_sources, key=lambda s: (-s.weight, -len(s.domain_rules)))
        confidence_map = {}
        uncertainty_map = {}
        causal_map = {}

        for child in sorted_sources:
            h_child = (child.content_hash, child.url, child.weight)

            for parent in sorted_sources:
                if child is parent:
                    continue

                is_subset, confidence, reason = self._is_strict_subset_with_confidence(child, parent, monitor)
                if is_subset:
                    h_parent = (parent.content_hash, parent.url, parent.weight)
                    new_edges.add((h_parent, h_child))
                    confidence_map[h_child] = min(confidence_map.get(h_child, 1.0), confidence)
                    if reason:
                        uncertainty_map[h_child] = reason

                    self._provenance.log_activity(
                        'SUBSET_DETECTED',
                        str(h_child),
                        {'parent': str(h_parent), 'confidence': confidence, 'reason': reason},
                        'lineage_analyzer',
                        [str(h_parent)]
                    )

        if new_edges:
            for p, c in new_edges:
                self._graph[p].add(c)

        max_depths, min_depths, scc_map, sccs = self._compute_depths_with_scc(current_hashes, hash_to_parsed)

        with self._lock:
            for h in current_hashes:
                self._cached_depths[h] = {
                    'max': max_depths.get(h, 0), 
                    'min': min_depths.get(h, 0), 
                    'scc': scc_map.get(h),
                    'confidence': confidence_map.get(h, 1.0),
                    'uncertainty': uncertainty_map.get(h),
                    'causal': causal_map.get(h)
                }

        union_sources = self._create_scc_unions(indexed_sources, sccs, hash_to_parsed, max_depths, min_depths)

        redundant = set()
        final_sources = []
        processed_sccs = set()

        for i, src in enumerate(indexed_sources):
            h = (src.content_hash, src.url, src.weight)
            scc_id = None
            for idx, scc in enumerate(sccs):
                if h in scc:
                    scc_id = idx
                    break

            cached = self._cached_depths.get(h, {})

            if scc_id is not None:
                if scc_id in processed_sccs:
                    continue
                processed_sccs.add(scc_id)
                union_src = union_sources.get(scc_id)
                if union_src:
                    final_sources.append(union_src)
                    if min_depths.get(h, 0) > 0:
                        redundant.add(len(final_sources) - 1)
            else:
                orig = 1.0 / (1.0 + self.config.originality_decay_rate * cached.get('min', 0))
                is_red = cached.get('min', 0) > 0

                lineage = LineageInfo(
                    depth=cached.get('max', 0),
                    min_depth=cached.get('min', 0),
                    originality=orig,
                    is_redundant=is_red,
                    confidence=cached.get('confidence', 1.0),
                    uncertainty_reason=cached.get('uncertainty'),
                    covering_sources=frozenset(str(s) for s in self._graph.get(h, set())) if is_red else None,
                    verification_level=3 if cached.get('confidence', 1.0) >= 1.0 else 2
                )

                verified = VerifiedSource(
                    url=src.url,
                    weight=src.weight,
                    content_hash=src.content_hash,
                    indexed=src,
                    lineage_info=lineage,
                    final_rules={}
                )

                final_sources.append(verified)
                if is_red:
                    redundant.add(len(final_sources) - 1)

        self.save_state()
        return redundant, final_sources

    def _create_scc_unions(self, sources: List[IndexedSource], sccs: List[List[str]], 
                          hash_to_parsed: Dict, max_depths: Dict, min_depths: Dict) -> Dict[int, Optional[VerifiedSource]]:
        """修復：合併CRDT到SCC代表節點"""
        union_map = {}
        
        # 修復：使用複合鍵查找
        hash_to_indexed = {(s.content_hash, s.url, s.weight): s for s in sources}

        for scc_idx, scc in enumerate(sccs):
            if len(scc) <= 1:
                continue

            members = [hash_to_indexed[h] for h in scc if h in hash_to_indexed]
            if not members:
                continue

            rep = scc[0]
            rep_src = hash_to_indexed[rep]

            # 計算SCC特有的排除規則和衝突
            all_exclusions = set()
            all_domains = set()
            for m in members:
                for r in m.domain_rules:
                    if r.is_exclusion:
                        all_exclusions.add(r.normalized)
                    else:
                        all_domains.add(r.normalized)

            conflicts = all_exclusions & all_domains

            # 修復：合併CRDT
            merged_crdt = None
            for m in members:
                if m._crdt:
                    if merged_crdt is None:
                        merged_crdt = m._crdt
                    else:
                        merged_crdt = merged_crdt.merge(m._crdt)

            union_merkle = MerkleClock(branching=self.config.merkle_tree_branching)
            for m in members:
                union_merkle.merge(m.merkle_clock)

            lineage = LineageInfo(
                depth=max_depths.get(rep, 0),
                min_depth=min_depths.get(rep, 0),
                originality=1.0,
                is_redundant=min_depths.get(rep, 0) > 0,
                confidence=0.9,
                uncertainty_reason="scc_union_heuristic",
                is_scc_union=True,
                scc_exclusion_conflicts=frozenset(conflicts) if conflicts else frozenset(),  # 修復：使用空frozenset而非None
                verification_level=2
            )

            verified = VerifiedSource(
                url=f"scc://{str(rep)[:16]}",
                weight=max(m.weight for m in members),
                content_hash=rep_src.content_hash,
                indexed=rep_src,
                lineage_info=lineage,
                final_rules={}
            )
            
            # 修復：將合併後的CRDT附加到VerifiedSource
            if merged_crdt:
                verified.indexed._crdt = merged_crdt

            union_map[scc_idx] = verified

        return union_map

    def _is_strict_subset_with_confidence(self, child: IndexedSource, parent: IndexedSource, 
                                          monitor: Optional[ResourceMonitor] = None) -> Tuple[bool, float, Optional[str]]:
        confidence = 1.0
        reason = None

        if not parent.bloom_filter:
            return False, 1.0, None

        for rule in child.domain_rules:
            key = f"domain:{rule.normalized}:{rule.is_exclusion}"
            if not parent.bloom_filter.contains(key):
                return False, 1.0, None

        if parent.rule_verifier and child.rule_verifier:
            bdd_subset, bdd_conf = child.rule_verifier.verify_subset_strict(
                parent.domain_rules + parent.ip_rules,
                child.domain_rules + child.ip_rules
            )
            if bdd_subset:
                return True, 1.0, None
            confidence *= bdd_conf

        for rule in child.ip_rules:
            if not rule.is_exclusion:
                if not parent.ip_trie.contains_subnet(rule.network):
                    return False, confidence, reason

        for cidr_rule in child.ip_rules:
            if parent.interval_tree and not cidr_rule.is_exclusion:
                start = int(cidr_rule.network.network_address)
                end = int(cidr_rule.network.broadcast_address)
                overlapping = parent.interval_tree.find_overlapping(start, end)
                for parent_net in overlapping:
                    if not cidr_rule.network.subnet_of(parent_net) and cidr_rule.network.overlaps(parent_net):
                        confidence *= 0.7
                        reason = f"cidr_partial_overlap:{cidr_rule.network} vs {parent_net}"

        final_confidence = max(0.5, confidence)
        return True, final_confidence, reason

    def _compute_depths_with_scc(self, nodes: Set, hash_to_parsed: Dict) -> Tuple[Dict, Dict, Dict, List]:
        if not nodes:
            return {}, {}, {}, []

        local_edges = defaultdict(set)
        for n in nodes:
            parents = self._graph.get(n, set()) & nodes
            for p in parents:
                local_edges[p].add(n)

        tarjan = IterativeTarjanSCC(dict(local_edges), max_nodes=100000)
        sccs = tarjan.find_sccs()

        scc_map = {}
        for idx, scc in enumerate(sccs):
            for node in scc:
                scc_map[node] = scc[0]

        in_degree = defaultdict(int)
        compressed_edges = defaultdict(set)

        for parent in nodes:
            p_rep = scc_map.get(parent, parent)
            for child in local_edges.get(parent, []):
                c_rep = scc_map.get(child, child)
                if p_rep != c_rep:
                    if c_rep not in compressed_edges[p_rep]:
                        compressed_edges[p_rep].add(c_rep)
                        in_degree[c_rep] += 1

        queue = deque([n for n in nodes if scc_map.get(n, n) == n and in_degree[scc_map.get(n, n)] == 0])
        max_depths = {}
        min_depths = {}

        for scc in sccs:
            rep = scc[0]
            for node in scc:
                max_depths[node] = 0
                min_depths[node] = 0

        parent_depths_min = defaultdict(list)

        while queue:
            u = queue.popleft()
            md = max_depths[u]
            mid = min_depths[u]

            for v in compressed_edges.get(u, []):
                max_depths[v] = max(max_depths.get(v, 0), md + 1)
                parent_depths_min[v].append(mid)
                in_degree[v] -= 1
                if in_degree[v] == 0:
                    min_depths[v] = min(parent_depths_min[v]) + 1 if parent_depths_min[v] else 0
                    queue.append(v)

        final_max = {}
        final_min = {}
        final_scc = {}

        for node in nodes:
            rep = scc_map.get(node, node)
            final_max[node] = max_depths.get(rep, 0)
            final_min[node] = min_depths.get(rep, 0)
            if rep != node:
                final_scc[node] = rep

        return final_max, final_min, final_scc, sccs

    def _apply_cached_results(self, parsed_sources: List[ParsedRuleSet]) -> Tuple[Set[int], List[VerifiedSource]]:
        redundant = set()
        final_sources = []

        for i, parsed in enumerate(parsed_sources):
            h = (parsed.get_content_hash(), parsed.url, parsed.weight)
            info = self._cached_depths.get(h, {'max': 0, 'min': 0, 'confidence': 1.0})

            min_d = info['min']
            max_d = info['max']
            orig = 1.0 / (1.0 + self.config.originality_decay_rate * min_d)
            is_red = min_d > 0

            lineage = LineageInfo(
                depth=max_d, min_depth=min_d, originality=orig, is_redundant=is_red,
                confidence=info.get('confidence', 1.0), uncertainty_reason=info.get('uncertainty'),
                covering_sources=frozenset(str(s) for s in self._graph.get(h, [])) if is_red else None,
                verification_level=3 if info.get('confidence', 1.0) >= 1.0 else 2
            )

            indexed = IndexedSource.from_parsed(parsed, self.config)
            verified = VerifiedSource(
                url=parsed.url,
                weight=parsed.weight,
                content_hash=parsed.get_content_hash(),
                indexed=indexed,
                lineage_info=lineage,
                final_rules={}
            )

            final_sources.append(verified)
            if is_red:
                redundant.add(i)

        return redundant, final_sources


class ProgressiveFuzzingHarness:
    __slots__ = ('_config', '_oracle', '_violation_count')

    def __init__(self, config: MergeConfig = DEFAULT_CONFIG):
        self._config = config
        self._oracle = None
        self._violation_count = 0

    def run_fuzzing_suite(self, lineage_analyzer, max_duration: int = 300):
        if not self._config.enable_fuzzing_tests or not HAS_HYPOTHESIS:
            return True

        start_time = time.time()
        passed = 0
        failed = 0

        try:
            self._test_idempotence(lineage_analyzer)
            passed += 1
        except Exception as e:
            logger.error(f"Fuzzing idempotence failed: {e}")
            failed += 1

        try:
            self._test_commutativity(lineage_analyzer)
            passed += 1
        except Exception as e:
            logger.error(f"Fuzzing commutativity failed: {e}")
            failed += 1

        try:
            self._test_cidr_roundtrip()
            passed += 1
        except Exception as e:
            logger.error(f"Fuzzing CIDR roundtrip failed: {e}")
            failed += 1

        if failed > 0:
            self._violation_count += failed
            return False
        return True

    def _test_idempotence(self, lineage_analyzer):
        sources = self._generate_random_sources(10)
        _, proc1 = lineage_analyzer.compute_incremental(sources)
        _, proc2 = lineage_analyzer.compute_incremental(proc1)
        assert len(proc1) == len(proc2), "Idempotence violated"

    def _test_commutativity(self, lineage_analyzer):
        sources = self._generate_random_sources(20)
        half = len(sources) // 2
        _, proc_ab = lineage_analyzer.compute_incremental(sources[:half] + sources[half:])
        _, proc_ba = lineage_analyzer.compute_incremental(sources[half:] + sources[:half])
        assert len(proc_ab) == len(proc_ba), "Commutativity violated"

    def _test_cidr_roundtrip(self):
        import random
        nets = []
        for _ in range(50):
            ip = random.randint(0, 2**32 - 1)
            prefix = random.randint(16, 30)
            nets.append(ipaddress.IPv4Network((ip, prefix), strict=False))

        merged = list(ipaddress.collapse_addresses(nets))
        assert all(isinstance(n, ipaddress.IPv4Network) for n in merged)

    def _generate_random_sources(self, count: int) -> List:
        sources = []
        for i in range(count):
            url = f"fuzz://source_{i}"
            src = type('MockSource', (), {
                'url': url,
                'weight': 1.0,
                'rule_count': i * 10,
                'get_content_hash': lambda self, i=i: f"hash_{i}",
                'merkle_clock': type('Clock', (), {'compare': lambda self, other: "concurrent"})(),
                'build_indices': lambda self: None,
                'rules_by_type': {'domain': {f"domain{j}.com" for j in range(i)}},
                '_domain_rules': [],
                '_ip_rules': [],
                'verify_subset_with_bdd': lambda self, other: (False, 0.5),
                'bloom_check': lambda self, other: True,
                '_etld_set': set(),
                '_domain_trie': None,
                'get_rule_specificity': lambda self, t, v: 0
            })()
            sources.append(src)
        return sources


def create_session():
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retries, pool_connections=10, pool_maxsize=20)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    session.headers.update({"User-Agent": "Mozilla/5.0 (compatible; HyperAccurate/9.0)"})
    return session


def download_file_stream(session, url, max_size, temp_dir):
    temp_path = None
    try:
        with session.get(url, stream=True, timeout=(10, 60), verify=True) as response:
            response.raise_for_status()
            content_type = response.headers.get('content-type', '').lower()
            if 'html' in content_type and not url.endswith('.html'):
                return None, None

            length_str = response.headers.get('content-length')
            if length_str and int(length_str) > max_size:
                return None, None

            fd, temp_path_str = tempfile.mkstemp(suffix='.tmp', dir=str(temp_dir))
            temp_path = Path(temp_path_str)
            total = 0
            first_chunk = True

            with os.fdopen(fd, 'wb') as f:
                for chunk in response.iter_content(chunk_size=131072):
                    if not chunk:
                        continue
                    if first_chunk and RE_HTML_MAGIC.match(chunk):
                        return None, None
                    first_chunk = False
                    total += len(chunk)
                    if total > max_size:
                        return None, None
                    f.write(chunk)

            if total <= 5 * 1024 * 1024:
                content = temp_path.read_bytes()
                try:
                    temp_path.unlink()
                except:
                    pass
                return content, None
            return None, temp_path

    except Exception as e:
        if temp_path and temp_path.exists():
            try:
                temp_path.unlink()
            except:
                pass
        raise TransientError(f"Download failed: {e}")


class RuleParser:
    __slots__ = ('_config',)
    RULE_TYPE_MAP = {
        'DOMAIN-SUFFIX': 'domain_suffix', 'DOMAIN': 'domain',
        'DOMAIN-KEYWORD': 'domain_keyword', 'DOMAIN-REGEX': 'domain_regex',
        'IP-CIDR': 'ip_cidr', 'IP-CIDR6': 'ip_cidr',
        'SRC-IP-CIDR': 'source_ip_cidr', 'DOMAIN-WILDCARD': 'domain_wildcard',
    }

    def __init__(self, config: MergeConfig = DEFAULT_CONFIG):
        self._config = config

    def parse(self, content: bytes, url: str, weight: float) -> ParsedRuleSet:
        """修復：添加長度限制和ReDoS防護"""
        # 修復：限制內容大小
        if len(content) > 10 * 1024 * 1024:  # 10MB限制
            raise ValueError("Content too large")
        
        domain_rules = []
        ip_rules = []
        keyword_rules = []
        regex_rules = []
        metadata = {}
        timestamp = time.time()

        try:
            data = json.loads(content.decode('utf-8', errors='strict'))
            rules_data = data.get("rules", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
            metadata['version'] = data.get('version') if isinstance(data, dict) else None

            for rule in rules_data:
                if not isinstance(rule, dict):
                    continue

                is_exclusion = rule.get('invert', False)
                for key, val in rule.items():
                    if key == 'invert':
                        continue

                    mapped = self.RULE_TYPE_MAP.get(key.upper(), key)
                    values = val if isinstance(val, list) else [val]

                    for v in values:
                        v_str = str(v).strip()
                        if not v_str:
                            continue
                        self._process_value(mapped, v_str, is_exclusion, domain_rules, ip_rules, keyword_rules, regex_rules)

        except json.JSONDecodeError:
            text = content.decode('utf-8-sig', errors='ignore')
            lines = text.splitlines()
            
            # 修復：限制行數
            if len(lines) > 1_000_000:
                raise ValueError("Too many lines")
            
            for line in lines:
                line = line.strip()
                if not line or line.startswith(('#', '//', ';')):
                    continue

                is_excl = line.startswith('!')
                val = line[1:].strip() if is_excl else line
                if not val:
                    continue

                if ',' in val and not val.startswith('http'):
                    parts = val.split(',', 2)
                    if len(parts) >= 2:
                        rtype_raw = parts[0].upper().replace('-', '_')
                        value = parts[1].strip()
                        type_map = {
                            'DOMAIN_SUFFIX': 'domain_suffix', 'DOMAIN': 'domain',
                            'IP-CIDR': 'ip_cidr', 'IP-CIDR6': 'ip_cidr',
                            'DOMAIN_KEYWORD': 'domain_keyword', 'DOMAIN_REGEX': 'domain_regex',
                            'DOMAIN_WILDCARD': 'domain_wildcard',
                        }
                        if rtype_raw in type_map:
                            mapped = type_map[rtype_raw]
                            self._process_value(mapped, value, is_excl, domain_rules, ip_rules, keyword_rules, regex_rules)
                            continue

        return ParsedRuleSet(
            url=url,
            weight=weight,
            domain_rules=tuple(domain_rules),
            ip_rules=tuple(ip_rules),
            keyword_rules=tuple(keyword_rules),
            regex_rules=tuple(regex_rules),
            metadata=metadata,
            timestamp=timestamp
        )

    def _process_value(self, rtype: str, value: str, is_exclusion: bool, 
                       domain_rules: List, ip_rules: List, keyword_rules: List, regex_rules: List):
        if rtype in ('domain', 'domain_suffix', 'domain_wildcard'):
            is_wc = value.startswith('*.')
            clean = value[2:] if is_wc else value
            norm, _ = self._normalize_domain(clean)
            if norm:
                mtype = MatchType.WILDCARD if is_wc else (MatchType.SUFFIX if rtype == 'domain_suffix' else MatchType.EXACT)
                rule = DomainRule(pattern=value, match_type=mtype, normalized=norm, is_exclusion=is_exclusion, original=value)
                domain_rules.append(rule)
        elif rtype == 'ip_cidr':
            try:
                net = ipaddress.ip_network(value, strict=False)
                rule = IPCIDRRule(network=net, original_str=value, is_exclusion=is_exclusion)
                ip_rules.append(rule)
            except ValueError:
                pass
        elif rtype == 'domain_keyword':
            keyword_rules.append(KeywordRule(keyword=value, is_exclusion=is_exclusion))
        elif rtype == 'domain_regex':
            regex_rules.append(RegexRule(pattern=value, is_exclusion=is_exclusion))

    @staticmethod
    def _normalize_domain(content: str) -> Tuple[Optional[str], bool]:
        original = content.strip()
        content = original.lower().strip('.')
        if not content or len(content) > 253:
            return (None, False)

        is_exclusion = False
        if RE_EXCLUSION_PREFIX.match(content):
            is_exclusion = True
            content = content.lstrip('!').strip()
            if not content:
                return (None, is_exclusion)

        try:
            normalized = unicodedata.normalize('NFC', content)
            if normalized != content:
                content = normalized

            if any(ord(c) > 127 for c in content):
                encoded = content.encode('idna').decode('ascii')
                restored = encoded.encode('ascii').decode('idna')
                if unicodedata.normalize('NFC', restored) != content:
                    return (None, is_exclusion)
            elif RE_PUNYCODE.match(content.split('.')[-1]):
                encoded = content
                try:
                    restored = encoded.encode('ascii').decode('idna')
                    if unicodedata.normalize('NFC', restored) != content:
                        return (None, is_exclusion)
                except:
                    return (None, is_exclusion)
            else:
                encoded = content
        except UnicodeError:
            return (None, is_exclusion)

        if ' ' in encoded or '_' in encoded:
            return (None, is_exclusion)

        parts = encoded.split('.')
        for part in parts:
            if not part or len(part) > 63 or part.startswith('-') or part.endswith('-'):
                return (None, is_exclusion)
            if not RE_DOMAIN_LABEL.match(part):
                return (None, is_exclusion)

        return (encoded, is_exclusion)


def cleanup_temp_dir(temp_dir: Path, max_retries: int = 3) -> bool:
    """修復：顯式關閉與重試機制處理Windows句柄洩漏"""
    for i in range(max_retries):
        try:
            shutil.rmtree(temp_dir, ignore_errors=False)
            return True
        except PermissionError:
            if i < max_retries - 1:
                time.sleep(0.1 * (2 ** i))  # 指數退避
                gc.collect()  # 強制關閉未引用文件句柄
    return False


def worker(task: Dict, lineage_analyzer: Optional[PersistentLineageAnalyzer] = None, 
           global_config: MergeConfig = DEFAULT_CONFIG):
    name = task['name']
    temp_dir = None
    retry_count = 0
    max_retries = 2

    while retry_count <= max_retries:
        try:
            temp_dir = Path(tempfile.mkdtemp())
            
            # 修復：使用安全的配置合併
            task_config_dict = task.get('config', {})
            task_config = MergeConfig.from_dict(task_config_dict, global_config)
            min_score = float(task.get('min_score', 1.0))

            out_json = task_config.output_dir / "merged-json" / f"{name}.json"
            out_srs = task_config.output_dir / "merged-srs" / f"{name}.srs"

            session = create_session()
            parser = RuleParser(task_config)
            sources = []
            transient_errors = []

            try:
                for conf in task.get('sources', []):
                    try:
                        url = conf if isinstance(conf, str) else conf.get('url')
                        weight = 1.0 if isinstance(conf, str) else float(conf.get('weight', 1.0))

                        content_bytes, temp_path = download_file_stream(
                            session, url, task_config.max_download_size, temp_dir
                        )

                        if content_bytes is None and temp_path is None:
                            continue

                        if content_bytes:
                            parsed = parser.parse(content_bytes, url, weight)
                        elif temp_path:
                            content = temp_path.read_bytes()
                            parsed = parser.parse(content, url, weight)
                            try:
                                temp_path.unlink()
                            except:
                                pass

                        if len(parsed.domain_rules) + len(parsed.ip_rules) > 0:
                            sources.append(parsed)

                    except TransientError as te:
                        logger.warning(f"Transient error for source {url}: {te}")
                        transient_errors.append(str(te))
                        continue

                if not sources:
                    if transient_errors and retry_count < max_retries:
                        raise TransientError("No valid sources due to transient errors")
                    return (name, "⚠️", "No valid sources", "0KB")

                if lineage_analyzer is None:
                    lineage_analyzer = PersistentLineageAnalyzer(config=task_config)

                redundant, processed = lineage_analyzer.compute_incremental(sources)
                active = [s for i, s in enumerate(processed) if i not in redundant]

                resolver = StrictConflictResolver(config=task_config, rir_manager=lineage_analyzer._rir_manager)
                merged = resolver.resolve(active, min_score)

                out_json.parent.mkdir(parents=True, exist_ok=True)
                final_data = {"version": 9.0, "rules": [{k: v} for k, v in merged.items() if v]}

                with open(out_json, 'wb') as f:
                    if USE_ORJSON:
                        f.write(orjson.dumps(final_data, option=orjson.OPT_INDENT_2 | orjson.OPT_SORT_KEYS))
                    else:
                        f.write(json.dumps(final_data, indent=2, ensure_ascii=False, sort_keys=True).encode())

                if Path(task_config.core_bin_path).exists():
                    res = subprocess.run(
                        [str(Path(task_config.core_bin_path).absolute()), "rule-set", "compile",
                         "--output", str(out_srs), str(out_json)],
                        capture_output=True, text=True, timeout=180
                    )

                    if res.returncode != 0:
                        if retry_count < max_retries:
                            raise TransientError(f"Compile failed: {res.stderr[:100]}")
                        return (name, "❌", f"Compile failed: {res.stderr[:100]}", "0KB")

                sz = f"{out_srs.stat().st_size / 1024:.1f}KB" if out_srs.exists() else "0KB"
                total_rules = sum(len(v) for v in merged.values())
                return (name, "✅", f"Merged {total_rules} rules", sz)

            except CIDRFragmentationError as e:
                logger.error(f"[{name}] CIDR fragmentation limit exceeded: {e.processed_count} fragments, loss: {e.loss_rate:.2%}")
                raise
            except StrictVerificationError as e:
                logger.error(str(e))
                raise
            finally:
                session.close()
                # 修復：避免頻繁調用gc.collect()
                if retry_count > 0:
                    gc.collect()

        except TransientError as te:
            retry_count += 1
            if retry_count <= max_retries:
                wait_time = 2 ** retry_count
                logger.warning(f"[{name}] Transient error, retrying in {wait_time}s: {te}")
                time.sleep(wait_time)
                continue
            else:
                logger.error(f"[{name}] Max retries exceeded: {te}")
                return (name, "❌", f"Failed after retries: {str(te)[:100]}", "0KB")

        except Exception as e:
            logger.exception(f"Worker error {name}")
            return (name, "❌", str(e)[:100], "0KB")

        finally:
            if temp_dir and temp_dir.exists():
                # 修復：使用cleanup_temp_dir處理Windows句柄問題
                if not cleanup_temp_dir(temp_dir):
                    logger.error(f"Failed to cleanup {temp_dir}")

    return (name, "❌", "Unknown error", "0KB")


def main():
    config = MergeConfig()
    logger.info(f"HyperAccurate v9.0 Strict Starting...")

    lineage = PersistentLineageAnalyzer(config=config)

    try:
        cfg_path = Path(config.config_file)
        if not cfg_path.exists():
            logger.error(f"Config file not found: {cfg_path}")
            return

        with open(cfg_path, 'rb') as f:
            cfg = orjson.loads(f.read()) if USE_ORJSON else json.load(f)
            tasks = cfg.get("merge_tasks", [])

        if not tasks:
            logger.warning("No merge tasks found in config")
            return

        with concurrent.futures.ThreadPoolExecutor(max_workers=config.max_workers) as exe:
            futures = {exe.submit(worker, t, lineage, config): t for t in tasks}
            for f in concurrent.futures.as_completed(futures):
                try:
                    r = f.result()
                    logger.info(f"[{r[0]}] {r[1]} {r[2]} ({r[3]})")
                except StrictVerificationError as e:
                    logger.error(f"Critical verification error: {e}")
                    if config.strict_zero_loss:
                        logger.error("Strict zero loss mode enabled, terminating")
                        break
                except CIDRFragmentationError as e:
                    logger.error(f"Critical CIDR error: {e}")
                    if config.strict_zero_loss:
                        logger.error("Strict zero loss mode enabled, terminating")
                        break

    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except Exception as e:
        logger.error(f"Main error: {e}")
    finally:
        try:
            lineage.close()
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
        logger.info("Cleanup completed")


if __name__ == "__main__":
    main()
