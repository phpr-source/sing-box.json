#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import bisect
import concurrent.futures
import hashlib
import io
import ipaddress
import itertools
import json
import logging
import math
import multiprocessing as mp
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from collections import defaultdict, OrderedDict, Counter, deque
from enum import IntEnum
from pathlib import Path
from typing import Any, Iterable, Optional, Union, List, Tuple, Dict, Set
from urllib.parse import urljoin, urlparse

import requests
import urllib3
import urllib3.util.connection
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

if sys.version_info < (3, 9):
    sys.exit("Error: Python 3.9+ is required")

sys.setrecursionlimit(3000)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

_orig_create_connection = urllib3.util.connection.create_connection
_dns_context = threading.local()

def _patched_create_connection(address: tuple[str, int], *args: Any, **kwargs: Any) -> socket.socket:
    host, port = address
    if getattr(_dns_context, 'forced_ip', None) and getattr(_dns_context, 'forced_host', None) == host:
        address = (_dns_context.forced_ip, port)
    return _orig_create_connection(address, *args, **kwargs)

urllib3.util.connection.create_connection = _patched_create_connection
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try: import orjson; USE_ORJSON = True
except ImportError: USE_ORJSON = False

try: import msgpack; USE_MSGPACK = True
except ImportError: USE_MSGPACK = False

try: from blake3 import blake3; USE_BLAKE3 = True
except ImportError: USE_BLAKE3 = False

try: import z3; HAS_Z3 = True
except ImportError: HAS_Z3 = False

CACHE_VERSION = 61
MAX_DOWNLOAD_RETRIES = 3
MAX_DNS_CACHE = 1024
MAX_BDD_DEPTH = 600
MAX_IP_RANGE_AGGREGATION_V4 = 2**24
MAX_IP_RANGE_AGGREGATION_V6 = 2**96
OP_NEG, OP_AND, OP_OR = 0, 1, 2

RE_DOMAIN_LABEL = re.compile(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$', re.IGNORECASE)
RE_TASK_NAME = re.compile(r'^[a-zA-Z0-9_-]+$')
RE_HASH_LIKE = re.compile(r'\b[a-f0-9]{32,64}\b', re.IGNORECASE)
RE_HTML_STRICT = re.compile(rb'(?:^[\s]*<(?:!DOCTYPE\s+html|html|head|body))', re.IGNORECASE | re.MULTILINE)
RE_IPV4_MAPPED_IPV6 = re.compile(r'^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:/(\d+))?$', re.IGNORECASE)

IPNetworkType = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

_DNS_CACHE: OrderedDict[str, Tuple[float, List[str]]] = OrderedDict()
_DNS_PENDING: Dict[str, threading.Event] = {}
_DNS_LOCK = threading.Lock()

class BDDDepthExceededError(Exception): pass
class TransientError(Exception): pass
class CIDRFragmentationError(Exception):
    def __init__(self, processed_count: int, limit: int, loss_rate: float = 0.0):
        super().__init__(f"CIDR fragmentation > {limit} ({processed_count}), loss {loss_rate:.2%}")

def fast_hash(data: bytes) -> str:
    return blake3(data).hexdigest() if USE_BLAKE3 else hashlib.sha256(data).hexdigest()

class MergeConfig:
    __slots__ = (
        'config_file', 'output_dir', 'core_bin_path', 'max_workers', 'max_download_size',
        'enable_ipv6', 'enable_smt_verification', 'smt_progressive_timeout',
        'enable_bdd_verification', 'bdd_node_limit', 'url_allow_private_ips',
        'max_concurrent_downloads', 'download_timeout_connect', 'download_timeout_read',
        'compile_timeout_seconds', 'max_bdd_var_cache_size', 'max_source_age_days',
        'enable_cache', 'bdd_lru_cache_size', 'max_verification_sources',
        'output_format', 'allow_policy', 'deny_policy', 'verify_ssl', 'max_cache_entries',
        'enable_dga_filter', 'enable_trie_compression', 'conflict_resolution',
        'enable_lineage', 'lineage_state_file', 'enable_reputation',
        'max_cidr_fragmentation', 'enable_cidr_approximation', 'cidr_approximation_max_loss_rate',
        'strict_zero_loss', 'smt_unknown_default', 'max_domain_length', 'fallback_on_fragmentation',
        'ipv4_garbage_threshold', 'ipv6_garbage_threshold'
    )

    def __init__(self, **kwargs: Any):
        self.config_file = kwargs.get('config_file', 'scripts/custom_merge.json')
        self.output_dir = Path(kwargs.get('output_dir', 'rules'))
        self.core_bin_path = kwargs.get('core_bin_path', os.getenv("SB_CORE_PATH", "./sb-core"))
        self.max_workers = int(kwargs.get('max_workers', 0)) or min(max(1, (os.cpu_count() or 4) * 2), 16)
        self.max_concurrent_downloads = max(10, int(kwargs.get('max_concurrent_downloads', 0)) or self.max_workers)
        self.max_download_size = int(kwargs.get('max_download_size', 150 * 1024 * 1024))
        self.url_allow_private_ips = bool(kwargs.get('url_allow_private_ips', False))
        self.download_timeout_connect = int(kwargs.get('download_timeout_connect', 10))
        self.download_timeout_read = int(kwargs.get('download_timeout_read', 60))
        self.verify_ssl = bool(kwargs.get('verify_ssl', True))
        self.enable_ipv6 = bool(kwargs.get('enable_ipv6', True))
        self.enable_dga_filter = bool(kwargs.get('enable_dga_filter', True))
        self.enable_trie_compression = bool(kwargs.get('enable_trie_compression', True))
        self.conflict_resolution = str(kwargs.get('conflict_resolution', 'specificity')).lower()
        self.max_cidr_fragmentation = int(kwargs.get('max_cidr_fragmentation', 5000))
        self.enable_cidr_approximation = bool(kwargs.get('enable_cidr_approximation', True))
        self.cidr_approximation_max_loss_rate = float(kwargs.get('cidr_approximation_max_loss_rate', 0.05))
        self.strict_zero_loss = bool(kwargs.get('strict_zero_loss', True))
        self.fallback_on_fragmentation = bool(kwargs.get('fallback_on_fragmentation', True))
        self.enable_smt_verification = bool(kwargs.get('enable_smt_verification', False))
        self.smt_progressive_timeout = tuple(kwargs.get('smt_progressive_timeout', (100, 500, 2000)))
        self.smt_unknown_default = bool(kwargs.get('smt_unknown_default', False))
        self.enable_bdd_verification = bool(kwargs.get('enable_bdd_verification', True))
        self.bdd_node_limit = int(kwargs.get('bdd_node_limit', 100000))
        self.max_bdd_var_cache_size = int(kwargs.get('max_bdd_var_cache_size', 10000))
        self.bdd_lru_cache_size = int(kwargs.get('bdd_lru_cache_size', 50000))
        self.max_verification_sources = int(kwargs.get('max_verification_sources', 20))
        self.enable_cache = bool(kwargs.get('enable_cache', True))
        self.max_cache_entries = int(kwargs.get('max_cache_entries', 500))
        self.max_source_age_days = int(kwargs.get('max_source_age_days', 30))
        self.enable_lineage = bool(kwargs.get('enable_lineage', True))
        self.lineage_state_file = kwargs.get('lineage_state_file', '.lineage_state')
        self.enable_reputation = bool(kwargs.get('enable_reputation', True))
        self.compile_timeout_seconds = int(kwargs.get('compile_timeout_seconds', 180))
        self.output_format = str(kwargs.get('output_format', 'json')).lower()
        self.allow_policy = str(kwargs.get('allow_policy', 'PROXY'))
        self.deny_policy = str(kwargs.get('deny_policy', 'REJECT'))
        self.max_domain_length = int(kwargs.get('max_domain_length', 253))
        self.ipv4_garbage_threshold = int(kwargs.get('ipv4_garbage_threshold', 8))
        self.ipv6_garbage_threshold = int(kwargs.get('ipv6_garbage_threshold', 48))

        if self.output_format not in ('json', 'surge', 'clash'):
            self.output_format = 'json'

    @classmethod
    def from_dict(cls, d: Dict[str, Any], base: 'MergeConfig') -> 'MergeConfig':
        kwargs = {}
        for key in cls.__slots__:
            if key in d and d[key] is not None:
                if key == 'output_dir': kwargs[key] = Path(d[key])
                elif key == 'smt_progressive_timeout': kwargs[key] = tuple(int(i) for i in d[key])
                else: kwargs[key] = d[key]
            else: kwargs[key] = getattr(base, key)
        return cls(**kwargs)

    def validate_core_path(self) -> bool:
        if not self.core_bin_path: return False
        p = Path(self.core_bin_path).expanduser().absolute()
        if not p.is_file(): return False
        try: os.chmod(p, p.stat().st_mode | 0o111)
        except OSError: pass
        return os.access(str(p), os.X_OK)

DEFAULT_CONFIG = MergeConfig()

class MatchType(IntEnum):
    EXACT = 1
    SUFFIX = 2
    WILDCARD = 3
    KEYWORD = 4
    REGEX = 5

class EntropyLevel(IntEnum):
    SAFE = 1
    SUSPICIOUS = 2
    DGA_CONFIRMED = 3

class EntropyAssessor:
    @staticmethod
    def assess(domain: str) -> EntropyLevel:
        if RE_HASH_LIKE.search(domain): return EntropyLevel.DGA_CONFIRMED
        parts = domain.split('.')
        if (len(parts) == 1 and len(parts[0]) < 3) or (len(parts) > 1 and len(parts[-1]) < 2): return EntropyLevel.DGA_CONFIRMED
        max_ent, max_dig, min_vow = 0.0, 0.0, 1.0
        vowels = set('aeiou')
        for p in parts:
            if len(p) < 6: continue
            length = len(p)
            freq = Counter(p)
            ent = -sum((c / length) * math.log2(c / length) for c in freq.values())
            n_ent = ent / math.log2(len(set(p))) if len(set(p)) > 1 else 0
            max_ent = max(max_ent, n_ent)
            max_dig = max(max_dig, sum(c.isdigit() for c in p) / length)
            min_vow = min(min_vow, sum(1 for c in p if c in vowels) / length)
        if max_ent > 0.95 and max_dig > 0.3 and min_vow < 0.1: return EntropyLevel.DGA_CONFIRMED
        if max_ent > 0.90 and max_dig > 0.2 and min_vow < 0.15: return EntropyLevel.SUSPICIOUS
        return EntropyLevel.SAFE

class DomainRule:
    __slots__ = ('match_type', 'normalized', 'is_exclusion', '_hash', 'specificity_score', 'attrs')
    def __init__(self, match_type: MatchType, normalized: str, is_exclusion: bool = False, specificity_score: int = 0, attrs: str = ""):
        self.match_type = match_type
        self.normalized = normalized
        self.is_exclusion = is_exclusion
        self.attrs = attrs
        self._hash = hash((self.normalized, self.match_type.value, self.is_exclusion))
        if specificity_score == 0:
            score = self.normalized.count('.') * 10
            if match_type == MatchType.EXACT: score += 8
            elif match_type == MatchType.SUFFIX: score += 3
            elif match_type == MatchType.WILDCARD: score += 1
            self.specificity_score = score
        else: self.specificity_score = specificity_score
    def __hash__(self) -> int: return self._hash
    def __eq__(self, o: Any) -> bool: return type(self) is type(o) and self._hash == o._hash and self.normalized == o.normalized

class IPCIDRRule:
    __slots__ = ('is_exclusion', 'version', 'start_int', 'end_int', 'prefixlen', '_hash', 'attrs')
    def __init__(self, start_int: int, end_int: int, prefixlen: int, version: int, is_exclusion: bool = False, attrs: str = ""):
        self.is_exclusion, self.version = is_exclusion, version
        self.start_int, self.end_int, self.prefixlen = start_int, end_int, prefixlen
        self.attrs = attrs
        self._hash = hash((self.version, self.start_int, self.prefixlen, self.is_exclusion))
    def __hash__(self) -> int: return self._hash
    def __eq__(self, o: Any) -> bool: return type(self) is type(o) and self._hash == o._hash

class GenericRule:
    __slots__ = ('type', 'val', 'is_exclusion', 'attrs', '_hash')
    def __init__(self, typ: str, val: str, is_exclusion: bool = False, attrs: str = ""):
        self.type, self.val, self.is_exclusion, self.attrs = typ, val, is_exclusion, attrs
        self._hash = hash((self.type, self.val, self.is_exclusion))
    def __hash__(self) -> int: return self._hash
    def __eq__(self, o: Any) -> bool: return type(self) is type(o) and self._hash == o._hash

RuleType = Union[DomainRule, IPCIDRRule, GenericRule]

class IntervalMerger:
    @staticmethod
    def _union_intervals(ivs: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
        if not ivs: return []
        ivs.sort(key=lambda x: x[0])
        merged = [ivs[0]]
        for s, e in ivs[1:]:
            last_s, last_e = merged[-1]
            if s <= last_e + 1: merged[-1] = (last_s, max(last_e, e))
            else: merged.append((s, e))
        return merged

    @staticmethod
    def _subtract_intervals(base_ivs: List[Tuple[int, int]], excl_ivs: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
        if not base_ivs: return []
        if not excl_ivs: return base_ivs
        events = []
        for s, e in base_ivs:
            events.extend([(s, 1), (e + 1, -1)])
        for s, e in excl_ivs:
            events.extend([(s, 2), (e + 1, -2)])
        events.sort(key=lambda x: (x[0], -abs(x[1])))
        result, a_cnt, d_cnt, prev_x = [], 0, 0, -1
        for x, op in events:
            if a_cnt > 0 and d_cnt == 0 and x > prev_x: result.append((prev_x, x - 1))
            if op == 1: a_cnt += 1
            elif op == -1: a_cnt -= 1
            elif op == 2: d_cnt += 1
            elif op == -2: d_cnt -= 1
            prev_x = x
        return IntervalMerger._union_intervals(result)

    @classmethod
    def resolve_weighted_ips(cls, rules_with_weights: List[Tuple[float, IPCIDRRule]], version: int) -> Tuple[List[Tuple[int, int, str]], List[Tuple[int, int, str]]]:
        events = []
        for i, (w, r) in enumerate(rules_with_weights):
            if r.version != version: continue
            rw = int(round(w, 5) * 100000)
            events.extend([(r.start_int, 1, rw, r.is_exclusion, r.attrs, i), (r.end_int + 1, -1, rw, r.is_exclusion, r.attrs, i)])

        events.sort(key=lambda x: x[0])
        active_a, active_d = {}, {}
        acc_a, acc_d = [], []
        i_idx, n, prev_x = 0, len(events), -1

        while i_idx < n:
            x = events[i_idx][0]
            if x > prev_x and prev_x != -1:
                max_a = max((v[0] for v in active_a.values()), default=-1)
                max_d = max((v[0] for v in active_d.values()), default=-1)

                if max_d >= 0 and max_d >= max_a:
                    attr = next((v[1] for k, v in sorted(active_d.items()) if v[0] == max_d), "")
                    acc_d.append((prev_x, x - 1, attr))
                elif max_a >= 0 and max_a > max_d:
                    attr = next((v[1] for k, v in sorted(active_a.items()) if v[0] == max_a), "")
                    acc_a.append((prev_x, x - 1, attr))

            while i_idx < n and events[i_idx][0] == x:
                _, op, rw, is_excl, attrs, r_id = events[i_idx]
                tgt = active_d if is_excl else active_a
                if op == 1: tgt[r_id] = (rw, attrs)
                else: tgt.pop(r_id, None)
                i_idx += 1
            prev_x = x

        def _merge_adj(ivs: List[Tuple[int, int, str]]) -> List[Tuple[int, int, str]]:
            if not ivs: return []
            res = [ivs[0]]
            for s, e, attr in ivs[1:]:
                ls, le, lattr = res[-1]
                if s <= le + 1 and attr == lattr: res[-1] = (ls, max(le, e), attr)
                else: res.append((s, e, attr))
            return res

        return _merge_adj(acc_a), _merge_adj(acc_d)

    @staticmethod
    def approximate_collapse(cidrs: List[IPNetworkType], target_count: int) -> Tuple[List[IPNetworkType], float]:
        if len(cidrs) <= target_count: return cidrs, 0.0
        orig_hosts = sum(c.num_addresses for c in cidrs)
        if orig_hosts == 0: return [], 0.0
        cidrs.sort(key=lambda x: x.num_addresses, reverse=True)
        kept = list(ipaddress.collapse_addresses(cidrs[:target_count]))
        new_hosts = sum(c.num_addresses for c in kept)
        loss = max(0.0, 1.0 - (new_hosts / orig_hosts))
        return kept, loss

    @classmethod
    def to_cidrs(cls, intervals: List[Tuple[int, int, str]], version: int, config: MergeConfig) -> List[Tuple[str, str]]:
        exact_networks = []
        width = 32 if version == 4 else 128
        fn = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
        agg_limit = MAX_IP_RANGE_AGGREGATION_V4 if version == 4 else MAX_IP_RANGE_AGGREGATION_V6

        def _fast_cidr_split(start: int, end: int):
            cur = start
            while cur <= end:
                max_sz = (cur & -cur) if cur != 0 else (1 << width)
                rem = end - cur + 1
                if max_sz > rem:
                    max_sz = 1 << (rem.bit_length() - 1)
                prefixlen = width - max_sz.bit_length() + 1
                yield ipaddress.ip_network(f"{fn(cur)}/{prefixlen}", strict=False)
                cur += max_sz

        for s, e, attr in intervals:
            r_sz = e - s + 1
            if r_sz > agg_limit: exact_networks.extend((n, attr) for n in _fast_cidr_split(s, e))
            else:
                try: exact_networks.extend((n, attr) for n in ipaddress.summarize_address_range(fn(s), fn(e)))
                except (ValueError, TypeError): exact_networks.extend((n, attr) for n in _fast_cidr_split(s, e))
                    
        if len(exact_networks) <= config.max_cidr_fragmentation: 
            return [(str(n), a) for n, a in exact_networks]
            
        if not config.enable_cidr_approximation:
            if config.fallback_on_fragmentation:
                logger.info(f"CIDR fragmented ({len(exact_networks)} > limit). Truncating.")
                exact_networks.sort(key=lambda x: x[0].num_addresses, reverse=True)
                grp = defaultdict(list)
                for n, a in exact_networks[:config.max_cidr_fragmentation]: grp[a].append(n)
                res = []
                for a, ns in grp.items(): res.extend((str(k), a) for k in ipaddress.collapse_addresses(ns))
                return res[:config.max_cidr_fragmentation]
            raise CIDRFragmentationError(len(exact_networks), config.max_cidr_fragmentation, 0.0)
            
        grp = defaultdict(list)
        for n, a in exact_networks: grp[a].append(n)
        res, tot_loss = [], 0.0
        total_exact = max(1, len(exact_networks))
        
        for a, ns in grp.items():
            budget = max(1, int(config.max_cidr_fragmentation * (len(ns) / total_exact)))
            kept, loss = cls.approximate_collapse(ns, budget)
            tot_loss = max(tot_loss, loss)
            res.extend((str(k), a) for k in kept)
        
        if len(res) > config.max_cidr_fragmentation:
            if config.fallback_on_fragmentation:
                logger.info(f"CIDR still fragmented after approx. Strict truncating to {config.max_cidr_fragmentation}.")
                res.sort(key=lambda x: ipaddress.ip_network(x[0], strict=False).num_addresses, reverse=True)
                res = res[:config.max_cidr_fragmentation]
            else: raise CIDRFragmentationError(len(res), config.max_cidr_fragmentation, tot_loss)
            
        if tot_loss > config.cidr_approximation_max_loss_rate or (tot_loss > 0 and config.strict_zero_loss):
            if config.fallback_on_fragmentation: return res
            raise CIDRFragmentationError(len(exact_networks), config.max_cidr_fragmentation, tot_loss)
            
        return res

class TrieNode:
    __slots__ = ('children', 'types')
    def __init__(self):
        self.children = {}
        self.types = 0

class DomainTrieOptimizer:
    def __init__(self):
        self.root = TrieNode()
        
    def insert(self, rule: DomainRule) -> None:
        node = self.root
        for part in reversed(rule.normalized.split('.')):
            if part not in node.children: node.children[part] = TrieNode()
            node = node.children[part]
        node.types |= (1 << rule.match_type.value)

    def is_covered(self, domain: str) -> bool:
        node = self.root
        parts = domain.split('.')
        for i, part in enumerate(reversed(parts)):
            if (node.types & (1 << MatchType.SUFFIX.value)): return True
            if (node.types & (1 << MatchType.WILDCARD.value)) and i < len(parts) - 1: return True
            if part not in node.children: return False
            node = node.children[part]
        return bool(node.types & ((1 << MatchType.EXACT.value) | (1 << MatchType.SUFFIX.value)))

    def optimize(self, is_exclusion: bool) -> List[DomainRule]:
        res = []
        def _dfs(node: TrieNode, path: List[str], parent_has_suffix: bool):
            is_suf = bool(node.types & (1 << MatchType.SUFFIX.value))
            if parent_has_suffix: return
            cur = '.'.join(reversed(path))
            if is_suf:
                res.append(DomainRule(MatchType.SUFFIX, cur, is_exclusion))
                return
            if node.types & (1 << MatchType.WILDCARD.value): res.append(DomainRule(MatchType.WILDCARD, cur, is_exclusion))
            if node.types & (1 << MatchType.EXACT.value): res.append(DomainRule(MatchType.EXACT, cur, is_exclusion))
            for lbl, ch in node.children.items():
                path.append(lbl)
                _dfs(ch, path, parent_has_suffix or is_suf)
                path.pop()
        for lbl, ch in self.root.children.items(): _dfs(ch, [lbl], False)
        return res

class VersionedBDDNode:
    __slots__ = ('var', 'low', 'high', '_node_id')
    def __init__(self, n_id: int, v: Any, l: Optional['VersionedBDDNode'], h: Optional['VersionedBDDNode']):
        self.var, self.low, self.high, self._node_id = v, l, h, n_id
    def __hash__(self) -> int: return self._node_id
    def __eq__(self, o: Any) -> bool: return self._node_id == getattr(o, '_node_id', -3)

class BDDEngine:
    __slots__ = ('var_map', 'var_counter', 'true_node', 'false_node', '_op_cache', '_op_max', '_node_cache', '_node_max', '_var_nodes', '_id_ctr')
    def __init__(self, node_max: int = 50000, op_max: int = 50000):
        self.var_map, self.var_counter, self._id_ctr = {}, 0, 0
        self._op_cache, self._node_cache, self._var_nodes = OrderedDict(), {}, {}
        self._op_max, self._node_max = op_max, node_max
        self.false_node = VersionedBDDNode(self._next_id(), -2, None, None)
        self.true_node = VersionedBDDNode(self._next_id(), -1, None, None)
        self._cache(self.false_node)
        self._cache(self.true_node)

    def _next_id(self) -> int:
        nid = self._id_ctr; self._id_ctr += 1
        return nid
        
    def _cache(self, n: Optional[VersionedBDDNode]) -> None:
        if n:
            k = (n.var, n.low._node_id if n.low else -1, n.high._node_id if n.high else -1)
            if k not in self._node_cache:
                if len(self._node_cache) >= self._node_max: raise BDDDepthExceededError()
                self._node_cache[k] = n

    def get_var(self, name: Any) -> int:
        if name not in self.var_map:
            self.var_map[name] = self.var_counter
            self.var_counter += 1
        return self.var_map[name]

    def ith_var(self, i: int) -> VersionedBDDNode:
        if i not in self._var_nodes:
            n = VersionedBDDNode(self._next_id(), i, self.false_node, self.true_node)
            self._var_nodes[i] = n
            self._cache(n)
        return self._var_nodes[i]

    def neg(self, n: VersionedBDDNode, d: int = 0) -> VersionedBDDNode:
        if d > MAX_BDD_DEPTH: raise BDDDepthExceededError()
        if n is self.true_node: return self.false_node
        if n is self.false_node: return self.true_node
        k = (OP_NEG, n._node_id, -1)
        if k in self._op_cache:
            self._op_cache.move_to_end(k)
            return self._op_cache[k]
        res = self._create(n.var, self.neg(n.low, d + 1) if n.low else None, self.neg(n.high, d + 1) if n.high else None)
        self._op_cache[k] = res
        if len(self._op_cache) > self._op_max: self._op_cache.popitem(last=False)
        return res

    def apply_and(self, f: VersionedBDDNode, g: VersionedBDDNode, d: int = 0) -> VersionedBDDNode: return self._apply(f, g, OP_AND, d)
    def apply_or(self, f: VersionedBDDNode, g: VersionedBDDNode, d: int = 0) -> VersionedBDDNode: return self._apply(f, g, OP_OR, d)

    def _apply(self, f: VersionedBDDNode, g: VersionedBDDNode, op: int, d: int = 0) -> VersionedBDDNode:
        if d > MAX_BDD_DEPTH: raise BDDDepthExceededError()
        if f is self.false_node or g is self.false_node: return self.false_node if op == OP_AND else (g if f is self.false_node else f)
        if f is self.true_node: return g if op == OP_AND else self.true_node
        if g is self.true_node: return f if op == OP_AND else self.true_node
        if f is g: return f
        k = (op, min(f._node_id, g._node_id), max(f._node_id, g._node_id))
        if k in self._op_cache:
            self._op_cache.move_to_end(k)
            return self._op_cache[k]
        if f.var == g.var: res = self._create(f.var, self._apply(f.low, g.low, op, d + 1), self._apply(f.high, g.high, op, d + 1))
        elif f.var < g.var: res = self._create(f.var, self._apply(f.low, g, op, d + 1), self._apply(f.high, g, op, d + 1))
        else: res = self._create(g.var, self._apply(f, g.low, op, d + 1), self._apply(f, g.high, op, d + 1))
        self._op_cache[k] = res
        if len(self._op_cache) > self._op_max: self._op_cache.popitem(last=False)
        return res

    def _create(self, var: int, l: Optional[VersionedBDDNode], h: Optional[VersionedBDDNode]) -> VersionedBDDNode:
        if l is h and l is not None: return l
        c = self._node_cache.get((var, l._node_id if l else -1, h._node_id if h else -1))
        if c: return c
        n = VersionedBDDNode(self._next_id(), var, l, h)
        self._cache(n)
        return n

    def sat_ratio(self, n: VersionedBDDNode) -> float:
        if n is self.false_node: return 0.0
        if n is self.true_node: return 1.0
        cache = {}
        def _ratio(node, d):
            if node is None or d > MAX_BDD_DEPTH or node is self.false_node: return 0.0
            if node is self.true_node: return 1.0
            if node in cache: return cache[node]
            r = 0.5 * _ratio(node.low, d + 1) + 0.5 * _ratio(node.high, d + 1)
            cache[node] = r
            return r
        return _ratio(n, 0)
    
    def clear(self) -> None:
        self._op_cache.clear()
        self._node_cache.clear()
        self._var_nodes.clear()
        self.var_map.clear()
        self.var_counter = self._id_ctr = 0
        self.false_node = VersionedBDDNode(self._next_id(), -2, None, None)
        self.true_node = VersionedBDDNode(self._next_id(), -1, None, None)
        self._cache(self.false_node)
        self._cache(self.true_node)

class BDDRuleVerifier:
    __slots__ = ('eng', '_ip_vars', '_max_c')
    def __init__(self, eng: BDDEngine, max_c: int = 10000):
        self.eng, self._max_c, self._ip_vars = eng, max_c, OrderedDict()

    def _get_v(self, ver: int, bp: int) -> VersionedBDDNode:
        k = (ver, bp)
        if k in self._ip_vars:
            self._ip_vars.move_to_end(k)
            return self._ip_vars[k]
        n = self.eng.ith_var(self.eng.get_var(('ip', ver, bp)))
        self._ip_vars[k] = n
        if len(self._ip_vars) > self._max_c: self._ip_vars.popitem(last=False)
        return n

    def encode(self, start: int, plen: int, ver: int) -> VersionedBDDNode:
        w = 32 if ver == 4 else 128
        if plen == 0: return self.eng.true_node
        res = self.eng.true_node
        for bp in range(min(plen, w)):
            v = self._get_v(ver, bp)
            if ((start >> (w - 1 - bp)) & 1) == 0: v = self.eng.neg(v)
            res = self.eng.apply_and(res, v)
        return res

    def build(self, allows: List[IPCIDRRule], denys: List[IPCIDRRule], ver: int) -> VersionedBDDNode:
        if not allows and not denys: return self.eng.false_node
        for r in allows + denys:
            for bp in range(r.prefixlen): self._get_v(ver, bp)
        a_bdd = self.eng.false_node
        for r in allows: a_bdd = self.eng.apply_or(a_bdd, self.encode(r.start_int, r.prefixlen, ver))
        if not denys: return a_bdd
        d_bdd = self.eng.false_node
        for r in denys: d_bdd = self.eng.apply_or(d_bdd, self.encode(r.start_int, r.prefixlen, ver))
        return self.eng.apply_and(a_bdd, self.eng.neg(d_bdd))

    def verify(self, pa: List[IPCIDRRule], pd: List[IPCIDRRule], ca: List[IPCIDRRule], is_deny: bool) -> Tuple[bool, float]:
        if not ca: return True, 1.0
        def _chk(pa_v, pd_v, ca_v, ver):
            if not ca_v: return True, 1.0
            if not pa_v and not is_deny: return False, 0.0
            try:
                if is_deny: p_bdd = self.build(pd_v, [], ver)
                else: p_bdd = self.build(pa_v, pd_v, ver)
                c_bdd = self.build(ca_v, [], ver)
                diff = self.eng.apply_and(c_bdd, self.eng.neg(p_bdd))
                if diff is self.eng.false_node: return True, 1.0
                cr = self.eng.sat_ratio(c_bdd)
                if cr == 0.0: return True, 1.0
                return False, max(0.0, min(1.0, 1.0 - (self.eng.sat_ratio(diff) / cr)))
            except BDDDepthExceededError:
                return False, 0.0
        v4_pa = [r for r in pa if r.version==4]; v6_pa = [r for r in pa if r.version==6]
        v4_pd = [r for r in pd if r.version==4]; v6_pd = [r for r in pd if r.version==6]
        v4_ca = [r for r in ca if r.version==4]; v6_ca = [r for r in ca if r.version==6]
        ok_v4, c_v4 = _chk(v4_pa, v4_pd, v4_ca, 4)
        ok_v6, c_v6 = _chk(v6_pa, v6_pd, v6_ca, 6)
        return (ok_v4 and ok_v6), min(c_v4 if v4_ca and not ok_v4 else 1.0, c_v6 if v6_ca and not ok_v6 else 1.0)

def _z3_worker(p_allow, p_deny, c_rules, is_deny, ver, timeouts):
    try:
        import z3
        ctx = z3.Context()
        s = z3.Solver(ctx=ctx)
        w = 32 if ver == 4 else 128
        def _b(rs):
            if not rs: return z3.BoolVal(False, ctx=ctx)
            x = z3.BitVec(f'x_v{ver}', w, ctx=ctx)
            tms = []
            for start, plen in rs:
                if plen == 0: return z3.BoolVal(True, ctx=ctx)
                tms.append(z3.LShR(x, w - plen) == (start >> (w - plen)))
            return z3.Or(*tms, ctx=ctx)
        c_expr = _b(c_rules)
        if is_deny: target_expr = _b(p_deny)
        else: target_expr = z3.And(_b(p_allow), z3.Not(_b(p_deny), ctx=ctx), ctx=ctx)
        for t in timeouts:
            s.push()
            s.set("timeout", t)
            s.add(c_expr)
            s.add(z3.Not(target_expr, ctx=ctx))
            res = s.check()
            s.pop()
            if res == z3.unsat: return True, 1.0, "unsat"
            elif res == z3.sat: return False, 0.0, "sat"
        return False, 0.0, "unknown"
    except Exception as e:
        return False, 0.0, f"err:{e}"

class ProcessIsolatedSMTVerifier:
    def __init__(self, cfg: MergeConfig):
        self.enabled = HAS_Z3 and cfg.enable_smt_verification
        self.tms = cfg.smt_progressive_timeout

    def verify(self, executor: concurrent.futures.ProcessPoolExecutor, p_allow: List[IPCIDRRule], p_deny: List[IPCIDRRule], c_rules: List[IPCIDRRule], is_deny: bool) -> Tuple[bool, float, str]:
        if not self.enabled or not c_rules or executor is None: return True, 1.0, "bypassed"
        v4_pa = [(r.start_int, r.prefixlen) for r in p_allow if r.version==4]
        v6_pa = [(r.start_int, r.prefixlen) for r in p_allow if r.version==6]
        v4_pd = [(r.start_int, r.prefixlen) for r in p_deny if r.version==4]
        v6_pd = [(r.start_int, r.prefixlen) for r in p_deny if r.version==6]
        v4_ca = [(r.start_int, r.prefixlen) for r in c_rules if r.version==4]
        v6_ca = [(r.start_int, r.prefixlen) for r in c_rules if r.version==6]
        timeout_seconds = max(self.tms) / 1000.0 + 1.0
        try:
            if v4_ca: v4_ok, v4_c, v4_m = executor.submit(_z3_worker, v4_pa, v4_pd, v4_ca, is_deny, 4, self.tms).result(timeout=timeout_seconds)
            else: v4_ok, v4_c, v4_m = True, 1.0, "triv"
        except concurrent.futures.TimeoutError:
            v4_ok, v4_c, v4_m = False, 0.0, "timeout"
        try:
            if v6_ca: v6_ok, v6_c, v6_m = executor.submit(_z3_worker, v6_pa, v6_pd, v6_ca, is_deny, 6, self.tms).result(timeout=timeout_seconds)
            else: v6_ok, v6_c, v6_m = True, 1.0, "triv"
        except concurrent.futures.TimeoutError:
            v6_ok, v6_c, v6_m = False, 0.0, "timeout"
        return (v4_ok and v6_ok), min(v4_c, v6_c), f"{v4_m},{v6_m}"

class CoverageChecker:
    __slots__ = ('_exact_domains', '_wildcard_domains', '_suffix_domains', '_v4_a', '_v4_d', '_v6_a', '_v6_d')
    def __init__(self, parent_rules: Iterable[RuleType]):
        self._exact_domains, self._wildcard_domains, self._suffix_domains = set(), set(), set()
        v4_a, v4_d, v6_a, v6_d = [], [], [], []
        for r in parent_rules:
            if isinstance(r, DomainRule):
                k = (r.normalized, r.is_exclusion)
                if r.match_type == MatchType.EXACT: self._exact_domains.add(k)
                elif r.match_type == MatchType.WILDCARD: self._wildcard_domains.add(k)
                elif r.match_type == MatchType.SUFFIX: self._suffix_domains.add(k)
            elif isinstance(r, IPCIDRRule):
                target = v4_d if r.is_exclusion else v4_a if r.version == 4 else v6_d if r.is_exclusion else v6_a
                target.append((r.start_int, r.end_int))
        self._v4_a = IntervalMerger._union_intervals(v4_a)
        self._v4_d = IntervalMerger._union_intervals(v4_d)
        self._v6_a = IntervalMerger._union_intervals(v6_a)
        self._v6_d = IntervalMerger._union_intervals(v6_d)

    def _domain_covered(self, r: DomainRule) -> bool:
        k = (r.normalized, r.is_exclusion)
        if r.match_type == MatchType.EXACT and (k in self._exact_domains or k in self._suffix_domains): return True
        if r.match_type == MatchType.WILDCARD and (k in self._wildcard_domains or k in self._suffix_domains): return True
        if r.match_type == MatchType.SUFFIX and k in self._suffix_domains: return True
        parts = r.normalized.split('.')
        for i in range(1, len(parts)):
            if (".".join(parts[i:]), r.is_exclusion) in self._suffix_domains or (".".join(parts[i:]), r.is_exclusion) in self._wildcard_domains: return True
        return False

    def calculate(self, child_rules: Iterable[RuleType]) -> float:
        covered = total = 0
        for r in child_rules:
            total += 1
            if isinstance(r, DomainRule):
                if self._domain_covered(r): covered += 1
            elif isinstance(r, IPCIDRRule):
                lst = self._v4_d if r.is_exclusion else self._v4_a if r.version == 4 else self._v6_d if r.is_exclusion else self._v6_a
                if not lst: continue
                starts = [s for s, _ in lst]
                idx = bisect.bisect_right(starts, r.start_int) - 1
                if idx >= 0 and r.end_int <= lst[idx][1]: covered += 1
        return (covered / total) if total > 0 else 1.0

class WALBackend:
    __slots__ = ('db_path', 'data', '_max', '_lck')
    def __init__(self, p: Path, c: MergeConfig):
        self.db_path = p.with_suffix('.ldb')
        self.data, self._max, self._lck = {}, c.max_cache_entries, threading.RLock()
        with self._lck:
            if not self.db_path.exists(): return
            try:
                raw = self.db_path.read_bytes()
                if len(raw) > 24 and hashlib.blake2b(raw[24:], digest_size=16).digest() == raw[:16]:
                    db = raw[24:]
                    if USE_MSGPACK: self.data = msgpack.unpackb(db, raw=False)
                    elif USE_ORJSON: self.data = orjson.loads(db)
                    else: self.data = json.loads(db.decode('utf-8'))
            except Exception: pass

    def get(self, k: str) -> Any:
        with self._lck: return self.data.get(k)
            
    def put_batch(self, upd: Dict[str, Any]) -> None:
        with self._lck:
            self.data.update(upd)
            if len(self.data) > self._max:
                sorted_items = sorted([(k, v.get('ts', 0)) for k, v in self.data.items() if isinstance(v, dict)], key=lambda x: x[1])
                for k, _ in sorted_items[:len(self.data)-self._max]: del self.data[k]
            try:
                if USE_MSGPACK: b = msgpack.packb(self.data, use_bin_type=True)
                elif USE_ORJSON: b = orjson.dumps(self.data)
                else: b = json.dumps(self.data, separators=(',', ':')).encode('utf-8')
                tp = Path(f"{self.db_path}.tmp")
                with open(tp, 'wb') as f:
                    f.write(hashlib.blake2b(b, digest_size=16).digest())
                    f.write(struct.pack('>d', time.time()))
                    f.write(b)
                    f.flush()
                    os.fsync(f.fileno())
                tp.replace(self.db_path)
            except Exception: pass

class ParsedRuleSet:
    __slots__ = ('url', 'domain_rules', 'ip_rules', 'generic_rules', 'ts', 'hash', 'weight', 'initial_weight', 'compiled_regexes')
    def __init__(self, u: str, d: Tuple[DomainRule,...], i: Tuple[IPCIDRRule,...], g: Tuple[GenericRule,...], t: float, h: str = "", w: float = 1.0):
        self.url, self.domain_rules, self.ip_rules, self.generic_rules, self.ts = u, d, i, g, t
        self.weight = self.initial_weight = w
        self.hash = h or fast_hash(b"".join(b"%d%d%s" % (r.match_type.value, r.is_exclusion, r.normalized.encode('utf-8')) for r in d) + b"".join(b"%d%d%d" % (r.version, r.start_int, r.prefixlen) for r in i) + b"".join(b"%s%s%d" % (r.type.encode('utf-8'), r.val.encode('utf-8'), r.is_exclusion) for r in g))
        
        self.compiled_regexes = []
        for r in d:
            if r.match_type == MatchType.REGEX:
                try: self.compiled_regexes.append(re.compile(r.normalized, re.IGNORECASE)) # 已修正：將 val 改為 normalized
                except re.error: pass

class SourceSignature:
    __slots__ = ('url', 'initial_weight', 'final_weight', 'hash', 'depth', 'originality', 'd_hashes', 'i_hashes', 'rule_count')
    def __init__(self, url: str, weight: float, c_hash: str, d_hash: set, i_hash: set, count: int):
        self.url, self.initial_weight, self.final_weight, self.hash = url, weight, weight, c_hash
        self.d_hashes, self.i_hashes, self.rule_count, self.depth, self.originality = d_hash, i_hash, count, 0, 1.0

    @classmethod
    def from_parsed(cls, ps: 'ParsedRuleSet') -> 'SourceSignature':
        return cls(ps.url, ps.weight, ps.hash, {r._hash for r in ps.domain_rules}, {r._hash for r in ps.ip_rules}, len(ps.domain_rules)+len(ps.ip_rules))

class SemanticLineageAnalyzer:
    def __init__(self, path: Path, enable: bool):
        self.path = path.with_suffix('.msgpack' if USE_MSGPACK else '.json')
        self.enable, self.graph, self.in_deg, self.exist_hashes = enable, defaultdict(set), Counter(), set()
        self._lock = threading.RLock()
        if self.enable and self.path.exists():
            try:
                data = msgpack.unpackb(self.path.read_bytes(), raw=False) if USE_MSGPACK else json.loads(self.path.read_text('utf-8'))
                self.exist_hashes = set(data.get('hashes', []))
                for k, lst in data.get('graph', {}).items(): self.graph[k] = set(lst)
                self.in_deg = Counter(data.get('in_deg', {}))
            except Exception: pass

    def save(self) -> None:
        if not self.enable: return
        clean_graph = {k: list(v.intersection(self.exist_hashes)) for k, v in self.graph.items() if k in self.exist_hashes}
        clean_in_deg = {k: 0 for k in self.exist_hashes}
        for k, v_set in clean_graph.items():
            for v in v_set: clean_in_deg[v] += 1
        data = {'hashes': list(self.exist_hashes), 'graph': clean_graph, 'in_deg': clean_in_deg}
        try:
            b = msgpack.packb(data, use_bin_type=True) if USE_MSGPACK else json.dumps(data, separators=(',', ':')).encode('utf-8')
            tp = self.path.with_suffix('.tmp')
            with open(tp, 'wb') as f:
                f.write(b); f.flush(); os.fsync(f.fileno())
            tp.replace(self.path)
        except Exception: pass
            
    def _is_subset_semantic(self, child: 'ParsedRuleSet', parent_trie: DomainTrieOptimizer, parent: 'ParsedRuleSet') -> bool:
        child_v4 = IntervalMerger._union_intervals([(r.start_int, r.end_int) for r in child.ip_rules if r.version == 4])
        parent_v4 = IntervalMerger._union_intervals([(r.start_int, r.end_int) for r in parent.ip_rules if r.version == 4])
        if IntervalMerger._subtract_intervals(child_v4, parent_v4): return False
            
        child_v6 = IntervalMerger._union_intervals([(r.start_int, r.end_int) for r in child.ip_rules if r.version == 6])
        parent_v6 = IntervalMerger._union_intervals([(r.start_int, r.end_int) for r in parent.ip_rules if r.version == 6])
        if IntervalMerger._subtract_intervals(child_v6, parent_v6): return False
            
        c_gen = {(r.type, r.val, r.is_exclusion) for r in child.generic_rules}
        p_gen = {(r.type, r.val, r.is_exclusion) for r in parent.generic_rules}
        if not c_gen.issubset(p_gen): return False
            
        p_kws = [r.normalized for r in parent.domain_rules if r.match_type == MatchType.KEYWORD] # 已修正：將 val 改為 normalized
        p_rex = {r.normalized for r in parent.domain_rules if r.match_type == MatchType.REGEX} # 已修正：將 val 改為 normalized
        
        for r in child.domain_rules:
            if r.match_type not in (MatchType.KEYWORD, MatchType.REGEX):
                covered = parent_trie.is_covered(r.normalized)
                if not covered and p_kws: covered = any(pk in r.normalized for pk in p_kws)
                if not covered and parent.compiled_regexes: covered = any(pat.search(r.normalized) for pat in parent.compiled_regexes)
                if not covered: return False
            elif r.match_type == MatchType.KEYWORD:
                if not p_kws or not any(pk in r.normalized for pk in p_kws): return False # 已修正：將 val 改為 normalized
            elif r.match_type == MatchType.REGEX:
                if r.normalized not in p_rex: return False # 已修正：將 val 改為 normalized
        return True

    def compute(self, parsed_srcs: List['ParsedRuleSet'], sigs: List[SourceSignature]) -> Set[int]:
        if not self.enable: return set()
        with self._lock:
            new_hashes = {s.hash for s in parsed_srcs if s.hash not in self.exist_hashes}
            if new_hashes:
                tries = {}
                def get_trie(idx):
                    if idx not in tries:
                        t = DomainTrieOptimizer()
                        for r in parsed_srcs[idx].domain_rules: t.insert(r)
                        tries[idx] = t
                    return tries[idx]
                    
                for i in range(len(parsed_srcs)):
                    for j in range(i+1, len(parsed_srcs)):
                        p_i, p_j = parsed_srcs[i], parsed_srcs[j]
                        if p_i.hash in new_hashes or p_j.hash in new_hashes:
                            if self._is_subset_semantic(p_i, get_trie(j), p_j):
                                if p_i.hash not in self.graph[p_j.hash]:
                                    self.graph[p_j.hash].add(p_i.hash)
                                    self.in_deg[p_i.hash] += 1
                            if self._is_subset_semantic(p_j, get_trie(i), p_i):
                                if p_j.hash not in self.graph[p_i.hash]:
                                    self.graph[p_i.hash].add(p_j.hash)
                                    self.in_deg[p_j.hash] += 1
                        
            q = deque([s.hash for s in sigs if self.in_deg.get(s.hash, 0) == 0])
            depths = {s.hash: 0 for s in sigs}
            local_in_deg = Counter({s.hash: self.in_deg.get(s.hash, 0) for s in sigs})
            
            while q:
                u = q.popleft()
                for v in self.graph.get(u, set()):
                    if v in depths:
                        depths[v] = max(depths[v], depths[u] + 1)
                        local_in_deg[v] -= 1
                        if local_in_deg[v] == 0: q.append(v)
            
            red = set()
            for i, s in enumerate(sigs):
                s.depth = depths.get(s.hash, 0)
                s.originality = math.pow(0.7, s.depth)
                self.exist_hashes.add(s.hash)
                if s.depth > 0: red.add(i)
            self.save()
            return red

class DynamicReputationEngine:
    def __init__(self, sources: List['ParsedRuleSet'], cache: Optional[WALBackend], cfg: MergeConfig):
        self.sources, self.cache, self.cfg = sources, cache, cfg

    def evaluate(self) -> None:
        N = len(self.sources)
        if N == 0: return
        freq = Counter()
        for src in self.sources:
            for r in src.domain_rules: freq[r._hash] += 1
            for r in src.ip_rules: freq[r._hash] += 1
            for r in src.generic_rules: freq[r._hash] += 1
            
        for src in self.sources:
            tot = len(src.domain_rules) + len(src.ip_rules) + len(src.generic_rules)
            if tot == 0:
                src.weight = 0.0
                continue
            garbage = 0
            for r in src.domain_rules:
                if r.normalized.count('.') == 0 or EntropyAssessor.assess(r.normalized) == EntropyLevel.DGA_CONFIRMED: garbage += 1
            for r in src.ip_rules:
                if r.version == 4 and r.prefixlen <= self.cfg.ipv4_garbage_threshold: garbage += 1
                elif r.version == 6 and r.prefixlen <= self.cfg.ipv6_garbage_threshold: garbage += 1
            
            align = sum(freq[r._hash] for r in itertools.chain(src.domain_rules, src.ip_rules, src.generic_rules)) / max(1, N * tot)
            garbage_ratio = garbage / max(1, tot)
            
            h_rep = 1.0
            if self.cache:
                c_data = self.cache.get(f"rep:{src.url}")
                if c_data and isinstance(c_data, dict):
                    h_rep = c_data.get('rep', 1.0)
            
            fw = align * math.exp(-5 * garbage_ratio)
            smoothed_rep = h_rep * 0.7 + fw * 0.3
            src.weight = src.initial_weight * smoothed_rep
            
            if self.cache: self.cache.put_batch({f"rep:{src.url}": {'rep': smoothed_rep, 'ts': time.time()}})
                
        max_w = max((s.weight for s in self.sources), default=1.0)
        if max_w > 0: 
            for s in self.sources: s.weight /= max_w

class RuleParser:
    __slots__ = ('_cfg', '_dga')
    RMAP = {
        'DOMAIN-SUFFIX': 'domain_suffix', 'HOST-SUFFIX': 'domain_suffix',
        'DOMAIN': 'domain', 'HOST': 'domain', 'DOMAIN-WILDCARD': 'domain_wildcard',
        'DOMAIN-KEYWORD': 'domain_keyword', 'HOST-KEYWORD': 'domain_keyword',
        'DOMAIN-REGEX': 'domain_regex', 'IP-CIDR': 'ip_cidr', 'IP-CIDR6': 'ip_cidr',
        'SRC-IP-CIDR': 'source_ip_cidr', 'GEOIP': 'geoip', 'DST-PORT': 'port',
        'SRC-PORT': 'source_port', 'PORT-RANGE': 'port_range', 'SRC-PORT-RANGE': 'source_port_range',
        'PROCESS-NAME': 'process_name', 'PROCESS-PATH': 'process_path',
        'PACKAGE-NAME': 'package_name', 'USER': 'user', 'USER-ID': 'user_id',
        'CLASH-MODE': 'clash_mode', 'WIFI-SSID': 'wifi_ssid', 'WIFI-BSSID': 'wifi_bssid',
        'RULE-SET': 'rule_set', 'USER-AGENT': 'user_agent'
    }

    def __init__(self, c: MergeConfig):
        self._cfg, self._dga = c, c.enable_dga_filter

    def parse(self, src: Union[bytes, Path], url: str) -> ParsedRuleSet:
        dom, ip, gen = [], [], []
        
        try:
            if isinstance(src, Path):
                with src.open('rb') as f: header = f.read(1024)
            else: header = src[:1024]
            is_j = header.find(b'{') != -1
        except OSError: 
            return ParsedRuleSet(url, (), (), (), time.time())
        
        def _add(typ: Optional[str], val: str, is_excl: bool, attrs: str = "") -> None:
            if typ in ('domain', 'domain_suffix', 'domain_wildcard') and val:
                n = val[2:].strip().lower().strip('.') if val.startswith('*.') else val.strip().lower().strip('.')
                if not n.isascii():
                    try: n = n.encode('idna').decode('ascii')
                    except UnicodeError: return
                if not n or len(n) > self._cfg.max_domain_length or ' ' in n: return
                if not all(RE_DOMAIN_LABEL.match(p) for p in n.split('.')): return
                if self._dga and EntropyAssessor.assess(n) == EntropyLevel.DGA_CONFIRMED: return
                mt = MatchType.WILDCARD if typ == 'domain_wildcard' or val.startswith('*.') else (MatchType.SUFFIX if typ == 'domain_suffix' else MatchType.EXACT)
                dom.append(DomainRule(mt, n, is_excl, 0, attrs))
            elif typ in ('domain_keyword', 'domain_regex'):
                dom.append(DomainRule(MatchType.KEYWORD if typ == 'domain_keyword' else MatchType.REGEX, val, is_excl, 0, attrs))
            elif typ in ('ip_cidr', 'source_ip_cidr'):
                m = RE_IPV4_MAPPED_IPV6.match(val)
                if m:
                    v4_ip = m.group(1)
                    prefix = int(m.group(2)) if m.group(2) else 32
                    if prefix >= 96: prefix -= 96
                    val = f"{v4_ip}/{prefix}"
                try: 
                    net = ipaddress.ip_network(val, strict=False)
                    if net.version == 4 or self._cfg.enable_ipv6: ip.append(IPCIDRRule(int(net.network_address), int(net.broadcast_address), net.prefixlen, net.version, is_excl, attrs))
                except ValueError: pass
            elif typ: gen.append(GenericRule(typ, val, is_excl, attrs))

        if is_j:
            try:
                if isinstance(src, Path):
                    with src.open('rb') as f: raw = f.read()
                else: raw = src
                if raw.startswith(b'\xef\xbb\xbf'): raw = raw[3:]
                data = orjson.loads(raw) if USE_ORJSON else json.loads(raw.decode('utf-8', errors='ignore'))
                del raw 
                rules_node = data.get('rules', []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
                for r in rules_node:
                    if not isinstance(r, dict): continue
                    is_excl = r.get('invert', False)
                    for k, v in r.items():
                        if k == 'invert': continue
                        mt = self.RMAP.get(k.upper(), k)
                        vals = v if isinstance(v, list) else [v]
                        
                        extra_attrs = [f"{ek}={ev}" for ek, ev in r.items() if ek not in ('invert', k, 'version', 'rules') and not isinstance(ev, (list, dict))]
                        attr_str = ",".join(extra_attrs)
                        
                        for val in vals:
                            if str(val).strip(): _add(mt, str(val).strip(), is_excl, attr_str)
                return ParsedRuleSet(url, tuple(dom), tuple(ip), tuple(gen), time.time())
            except Exception as e: logger.debug(f"JSON parsing fallback for {url}: {e}")
            
        def _stream(iterator):
            for ln in iterator:
                ln = ln.strip()
                if not ln or ln.startswith(('#', '//', ';')): continue
                is_excl = ln.startswith('!')
                v = ln[1:].strip() if is_excl else ln
                p = v.split(',')
                if len(p) >= 2 and p[0].upper() in self.RMAP: 
                    _add(self.RMAP[p[0].upper()], p[1].strip(), is_excl, ','.join(p[2:]).strip())
                else: 
                    _add('domain', v, is_excl, "")
                
        try:
            if isinstance(src, Path):
                with open(src, 'r', encoding='utf-8-sig', errors='ignore') as f: 
                    f.seek(0)
                    _stream(f)
            else:
                with io.TextIOWrapper(io.BytesIO(src), encoding='utf-8-sig') as f: 
                    _stream(f)
        except OSError: pass
        return ParsedRuleSet(url, tuple(dom), tuple(ip), tuple(gen), time.time())

def resolve_hostname(hostname: str) -> List[str]:
    with _DNS_LOCK:
        if hostname in _DNS_CACHE:
            ts, ips = _DNS_CACHE[hostname]
            if time.time() - ts < 300:
                _DNS_CACHE.move_to_end(hostname)
                return ips
            del _DNS_CACHE[hostname]
        if hostname in _DNS_PENDING:
            ev, wait = _DNS_PENDING[hostname], True
        else:
            ev, wait = threading.Event(), False
            _DNS_PENDING[hostname] = ev
    if wait:
        ev.wait(10)
        with _DNS_LOCK: return _DNS_CACHE.get(hostname, (0, []))[1]
    ips = []
    try:
        results = socket.getaddrinfo(hostname, None)
        for res in results:
            ip_str = res[4][0].split('%')[0]
            try:
                if not ipaddress.ip_address(ip_str).is_link_local: ips.append(ip_str)
            except ValueError: pass
        ips = list(set(ips))
    except Exception: pass
    with _DNS_LOCK:
        _DNS_CACHE[hostname] = (time.time(), ips)
        _DNS_CACHE.move_to_end(hostname)
        if len(_DNS_CACHE) > MAX_DNS_CACHE: _DNS_CACHE.popitem(last=False)
        _DNS_PENDING.pop(hostname, None)
        ev.set()
    return ips

def _dl_single(cfg: MergeConfig, url: str, td: Path, cache: Optional[WALBackend], parser: RuleParser) -> Tuple[Optional[ParsedRuleSet], Optional[dict]]:
    ckey = f"p:{CACHE_VERSION}:{url}"
    if cache:
        l = cache.get(ckey)
        if l and time.time() - l.get('ts', 0) < cfg.max_source_age_days * 86400:
            doms = tuple(DomainRule(MatchType(r['match_type']), r['normalized'], r.get('is_exclusion', False), r.get('specificity_score', 0), r.get('attrs', '')) for r in l.get('d', []))
            ips = tuple(IPCIDRRule(r['s'], r['e'], r['p'], r['v'], r.get('i', False), r.get('attrs', '')) for r in l.get('i', []))
            gens = tuple(GenericRule(r['t'], r['v'], r.get('i', False), r.get('attrs', '')) for r in l.get('g', []))
            return ParsedRuleSet(l['url'], doms, ips, gens, l['ts'], l['hash']), None

    for _ in range(MAX_DOWNLOAD_RETRIES):
        rc, curl, vis, tmp, ok = 0, url, set(), None, False
        try:
            while rc < 5:
                if curl in vis: break
                vis.add(curl)
                p = urlparse(curl)
                if not p.hostname: break
                ips = resolve_hostname(p.hostname)
                if not ips: break
                redir = False
                for ip in ips:
                    _dns_context.forced_host = p.hostname
                    _dns_context.forced_ip = ip
                    try:
                        with requests.Session() as s:
                            s.headers.update({'Connection': 'close'})
                            s.mount('https://', HTTPAdapter(max_retries=Retry(total=1)))
                            s.mount('http://', HTTPAdapter(max_retries=Retry(total=1)))
                            with s.get(curl, stream=True, timeout=(cfg.download_timeout_connect, cfg.download_timeout_read), allow_redirects=False, headers={"User-Agent": "StrictRuleMerger/13.6 Ultimate"}) as resp:
                                if resp.status_code in (301, 302, 303, 307, 308):
                                    curl = urljoin(curl, resp.headers.get('Location', ''))
                                    rc, redir = rc + 1, True
                                    break
                                resp.raise_for_status()
                                fd, pstr = tempfile.mkstemp(suffix='.tmp', dir=str(td))
                                tmp = Path(pstr)
                                html_check_count, is_html_error = 0, False
                                with os.fdopen(fd, 'wb') as f:
                                    for chunk in resp.iter_content(131072):
                                        if not chunk: continue
                                        if html_check_count < 3:
                                            if RE_HTML_STRICT.search(chunk) and not curl.endswith('.html'):
                                                is_html_error = True
                                                break
                                            html_check_count += 1
                                        f.write(chunk)
                                if is_html_error: raise TransientError("HTML content detected")
                                ok = True
                                break
                    except (requests.RequestException, TransientError):
                        if tmp and tmp.exists():
                            tmp.unlink(missing_ok=True)
                            tmp = None
                    finally:
                        _dns_context.forced_host, _dns_context.forced_ip = None, None
                if redir: continue
                break
        finally: pass
        if not ok or not tmp: continue
        
        srs = None
        if url.endswith('.srs') and cfg.validate_core_path():
            srs, json_f = tmp, tmp.with_suffix('.json')
            try:
                subprocess.run([str(Path(cfg.core_bin_path).expanduser().absolute()), "rule-set", "decompile", "--output", str(json_f), str(srs)], check=True, capture_output=True, timeout=cfg.compile_timeout_seconds)
                tmp = json_f
            except Exception: pass
            finally: srs.unlink(missing_ok=True)
            
        try:
            ps = parser.parse(tmp, url)
            ts = None
            if cache and (ps.domain_rules or ps.ip_rules or ps.generic_rules):
                d_rules = [{'match_type': r.match_type.value, 'normalized': r.normalized, 'is_exclusion': r.is_exclusion, 'specificity_score': r.specificity_score, 'attrs': r.attrs} for r in ps.domain_rules]
                i_rules = [{'s': r.start_int, 'e': r.end_int, 'p': r.prefixlen, 'v': r.version, 'i': r.is_exclusion, 'attrs': r.attrs} for r in ps.ip_rules]
                g_rules = [{'t': r.type, 'v': r.val, 'i': r.is_exclusion, 'attrs': r.attrs} for r in ps.generic_rules]
                ts = {ckey: {'url': ps.url, 'ts': ps.ts, 'hash': ps.hash, 'd': d_rules, 'i': i_rules, 'g': g_rules}}
            return ps, ts
        except Exception: pass
        finally: tmp.unlink(missing_ok=True)
    return None, None

def _verify_rule_group(name: str, bdd: Optional[BDDRuleVerifier], smt_executor: Optional[concurrent.futures.ProcessPoolExecutor], smt_cfg: Optional[MergeConfig], cov: CoverageChecker, 
                       pa_dom: List[DomainRule], pd_dom: List[DomainRule], c_dom: List[DomainRule], 
                       pa_ip: List[IPCIDRRule], pd_ip: List[IPCIDRRule], c_ip: List[IPCIDRRule], 
                       src_url: str, is_deny: bool, res: Dict[str, Any]) -> Tuple[bool, float]:
    ip_ok, dom_ok, ip_conf, dom_conf = True, True, 1.0, 1.0
    if c_ip:
        if bdd:
            try:
                ip_ok, ip_conf = bdd.verify(pd_ip, [], c_ip, True) if is_deny else bdd.verify(pa_ip, pd_ip, c_ip, False)
                if not ip_ok: res['issues'].append({'source': src_url, 'verifier': 'BDD_IP', 'type': f"{name}_ip_not_subset", 'confidence': ip_conf})
            except Exception: pass
        elif smt_executor and smt_cfg and smt_cfg.enable_smt_verification:
            try:
                verifier = ProcessIsolatedSMTVerifier(smt_cfg)
                if is_deny: ip_ok, ip_conf, msg = verifier.verify(smt_executor, [], pd_ip, c_ip, True) 
                else: ip_ok, ip_conf, msg = verifier.verify(smt_executor, pa_ip, pd_ip, c_ip, False)
                if not ip_ok: res['issues'].append({'source': src_url, 'verifier': 'SMT_IP', 'type': f"{name}_ip_not_subset", 'confidence': ip_conf, 'message': msg})
            except Exception: pass
        else:
            ip_conf = cov.calculate(c_ip)
            ip_ok = ip_conf >= 1.0
            if not ip_ok: res['issues'].append({'source': src_url, 'verifier': 'Coverage_IP', 'type': f"{name}_ip_not_covered", 'confidence': ip_conf})

    if c_dom:
        dom_conf = cov.calculate(c_dom)
        dom_ok = dom_conf >= 1.0
        if not dom_ok: res['issues'].append({'source': src_url, 'verifier': 'Coverage_DOM', 'type': f"{name}_dom_not_covered", 'confidence': dom_conf})
    return (ip_ok and dom_ok), min(ip_conf, dom_conf)

def run_verifications(parsed_sets: List[ParsedRuleSet], p_dom_allow: List[DomainRule], p_dom_deny: List[DomainRule], p_ip_allow: List[IPCIDRRule], p_ip_deny: List[IPCIDRRule], bdd_verifier: Optional[BDDRuleVerifier], smt_executor: Optional[concurrent.futures.ProcessPoolExecutor], config: MergeConfig) -> Dict[str, Any]:
    results, total_sources, passed, coverages = {'issues': [], 'stats': {}}, 0, 0, []
    coverage_checker = CoverageChecker(itertools.chain(p_dom_allow, p_ip_allow, p_dom_deny, p_ip_deny))
    for src in sorted(parsed_sets, key=lambda x: -x.weight)[:config.max_verification_sources]:
        ca = [r for r in src.domain_rules if not r.is_exclusion]
        cia = [r for r in src.ip_rules if not r.is_exclusion]
        cd = [r for r in src.domain_rules if r.is_exclusion]
        cid = [r for r in src.ip_rules if r.is_exclusion]
        if not (ca or cia or cd or cid): continue
        total_sources += 1
        src_passed, cov_components = True, []
        def check(name: str, is_deny: bool, c_d: List[DomainRule], c_i: List[IPCIDRRule]) -> None:
            nonlocal src_passed
            if c_d or c_i:
                ok, conf = _verify_rule_group(name, bdd_verifier, smt_executor, config, coverage_checker, p_dom_allow, p_dom_deny, c_d, p_ip_allow, p_ip_deny, c_i, src.url, is_deny, results)
                src_passed = src_passed and ok
                cov_components.append(conf)
        check('domain_allow', False, ca, cia)
        check('domain_deny', True, cd, cid)
        if src_passed: passed += 1
        coverages.append(min(cov_components) if cov_components else 1.0)
    if total_sources > 0: results['stats'] = {'total_sources': total_sources, 'passed': passed, 'pass_rate': passed / total_sources, 'avg_coverage': sum(coverages) / len(coverages)}
    return results

def _format_policy(attrs: str, default_pol: str) -> str:
    if not attrs: return default_pol
    first_attr = attrs.split(',')[0].strip()
    if first_attr.upper() in ('NO-RESOLVE', 'EXTENDED-MATCHING'):
        return f"{default_pol},{attrs}"
    return attrs

def worker(task: Dict[str, Any], global_cfg: MergeConfig, lin: Optional[SemanticLineageAnalyzer] = None, smt_executor: Optional[concurrent.futures.ProcessPoolExecutor] = None) -> Tuple[str, str, str, str]:
    name = task.get('name', '')
    if not name or not RE_TASK_NAME.match(name): return (name, "❌", "Invalid name", "0KB")
    td, cache = None, None
    try:
        td = Path(tempfile.mkdtemp(prefix=f"sb_merge_{name}_"))
        cfg = MergeConfig.from_dict(task.get('config', {}), global_cfg)
        out_p = cfg.output_dir / f"merged-{cfg.output_format}" / f"{name}.{'list' if cfg.output_format == 'surge' else 'yaml' if cfg.output_format == 'clash' else 'json'}"
        out_p.parent.mkdir(parents=True, exist_ok=True)
        min_score_threshold = float(task.get('min_score', 0.0))
        
        if cfg.enable_cache:
            cdir = Path.cwd() / ".cache" / "rule_merger" / name
            try:
                cdir.mkdir(parents=True, exist_ok=True)
                cache = WALBackend(cdir / "source_cache", cfg)
            except OSError: pass

        parser, sources, upd = RuleParser(cfg), [], {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=cfg.max_concurrent_downloads) as ex:
            futs = {}
            for s in task.get('sources', []):
                s_url = s if isinstance(s, str) else s.get('url')
                s_weight = 1.0 if isinstance(s, str) else float(s.get('weight', 1.0))
                if s_url: futs[ex.submit(_dl_single, cfg, s_url, td, cache, parser)] = (s_url, s_weight)
            for fu in concurrent.futures.as_completed(futs):
                ps, u = fu.result()
                if ps:
                    _, manual_weight = futs[fu]
                    ps.weight = ps.initial_weight = manual_weight
                    sources.append(ps)
                    upd.update(u or {})
        if cache and upd: cache.put_batch(upd)
        if not sources: return (name, "⚠️", "No valid sources", "0KB")

        if cfg.enable_reputation: DynamicReputationEngine(sources, cache, cfg).evaluate()
        if lin:
            sigs = [SourceSignature.from_parsed(s) for s in sources]
            red = lin.compute(sources, sigs)
            sig_map = {s.hash: s for s in sigs}
            for s in sources:
                if s.hash in sig_map: s.weight *= sig_map[s.hash].originality
                
        if min_score_threshold <= 0:
            min_score_threshold = max(0.01, (sum(s.weight for s in sources) / len(sources)) * 0.35)

        rule_scores, dom_objs, ip_objs, gen_objs = defaultdict(float), {}, {}, {}
        for src in sources:
            for r in src.domain_rules:
                rule_scores[r._hash] += src.weight
                if r._hash not in dom_objs: dom_objs[r._hash] = (src.weight, r)
                else:
                    existing_w, existing_r = dom_objs[r._hash]
                    if src.weight > existing_w: dom_objs[r._hash] = (src.weight, r)
                    elif src.weight == existing_w and cfg.conflict_resolution == 'specificity':
                        if r.specificity_score > existing_r.specificity_score: dom_objs[r._hash] = (src.weight, r)
            for r in src.ip_rules:
                rule_scores[r._hash] += src.weight
                ip_objs[r._hash] = r
            for r in src.generic_rules:
                rule_scores[r._hash] += src.weight
                if r._hash not in gen_objs: gen_objs[r._hash] = (src.weight, r)
                else:
                    existing_w, _ = gen_objs[r._hash]
                    if src.weight > existing_w: gen_objs[r._hash] = (src.weight, r)

        allow_trie, deny_trie, others, ip_weights = DomainTrieOptimizer(), DomainTrieOptimizer(), set(), []
        for h, score in rule_scores.items():
            if score >= min_score_threshold:
                if h in dom_objs:
                    _, r = dom_objs[h]
                    if r.match_type in (MatchType.KEYWORD, MatchType.REGEX): others.add(r)
                    else: (deny_trie if r.is_exclusion else allow_trie).insert(r)
                elif h in ip_objs: ip_weights.append((score, ip_objs[h]))
                elif h in gen_objs: 
                    others.add(gen_objs[h][1])
                
        if cfg.enable_trie_compression:
            p_dom_a = allow_trie.optimize(False)
            p_dom_d = deny_trie.optimize(True)
        else:
            p_dom_a = [r for h, (w, r) in dom_objs.items() if rule_scores[h] >= min_score_threshold and not r.is_exclusion]
            p_dom_d = [r for h, (w, r) in dom_objs.items() if rule_scores[h] >= min_score_threshold and r.is_exclusion]
            
        v4_a_ivs, v4_d_ivs = IntervalMerger.resolve_weighted_ips(ip_weights, 4)
        v6_a_ivs, v6_d_ivs = IntervalMerger.resolve_weighted_ips(ip_weights, 6)
        
        try:
            f_a_ip_strs = IntervalMerger.to_cidrs(v4_a_ivs, 4, cfg) + IntervalMerger.to_cidrs(v6_a_ivs, 6, cfg)
            f_d_ip_strs = IntervalMerger.to_cidrs(v4_d_ivs, 4, cfg) + IntervalMerger.to_cidrs(v6_d_ivs, 6, cfg)
        except CIDRFragmentationError as e: 
            logger.error(f"[{name}] Task Failed: {e}")
            return (name, "❌", "CIDR Limit Exceeded & Fallback Failed", "0KB")
        
        issues = []
        if cfg.enable_bdd_verification or (HAS_Z3 and cfg.enable_smt_verification):
            eng = BDDEngine(cfg.bdd_node_limit, cfg.bdd_lru_cache_size)
            bdd = BDDRuleVerifier(eng, cfg.max_bdd_var_cache_size) if cfg.enable_bdd_verification else None
            va_ips = [IPCIDRRule(int(ipaddress.ip_network(s, strict=False).network_address), int(ipaddress.ip_network(s, strict=False).broadcast_address), ipaddress.ip_network(s, strict=False).prefixlen, 6 if ':' in s else 4, False) for s, _ in f_a_ip_strs]
            vd_ips = [IPCIDRRule(int(ipaddress.ip_network(s, strict=False).network_address), int(ipaddress.ip_network(s, strict=False).broadcast_address), ipaddress.ip_network(s, strict=False).prefixlen, 6 if ':' in s else 4, True) for s, _ in f_d_ip_strs]
            verify_results = run_verifications(sources, p_dom_a, p_dom_d, va_ips, vd_ips, bdd, smt_executor, cfg)
            for iss in verify_results.get('issues', []): issues.append(f"{iss['type']} ({iss['verifier']})")
            if bdd: eng.clear()

        all_d = p_dom_a + p_dom_d + list(others)
        all_d.sort(key=lambda r: (int(not getattr(r, 'is_exclusion', False)), -getattr(r, 'specificity_score', 0), getattr(r, 'normalized', getattr(r, 'val', ''))))
        
        is_sg, is_cl = cfg.output_format == 'surge', cfg.output_format == 'clash'
        if is_sg or is_cl:
            pf = "  - " if is_cl else ""
            with open(out_p, 'w', encoding='utf-8') as f:
                if is_cl: f.write("payload:\n")
                for r in all_d:
                    pol = _format_policy(getattr(r, 'attrs', ''), cfg.deny_policy if getattr(r, 'is_exclusion', False) else cfg.allow_policy)
                    if isinstance(r, GenericRule):
                        typ_str = r.type.replace('_', '-').upper()
                        f.write(f"{pf}{typ_str},{r.val},{pol}\n")
                        continue
                    
                    typ = 'DOMAIN' if r.match_type == MatchType.EXACT else 'DOMAIN-SUFFIX' if r.match_type == MatchType.SUFFIX else 'DOMAIN-KEYWORD' if r.match_type == MatchType.KEYWORD else 'DOMAIN-REGEX' if r.match_type == MatchType.REGEX else 'DOMAIN-WILDCARD'
                    val = f"*.{r.normalized}" if r.match_type == MatchType.WILDCARD else r.normalized
                    f.write(f"{pf}{typ},{val},{pol}\n")
                    
                for s, attr in f_a_ip_strs: 
                    f.write(f"{pf}IP-CIDR{'6' if ':' in s else ''},{s},{_format_policy(attr, cfg.allow_policy)}\n")
                for s, attr in f_d_ip_strs: 
                    f.write(f"{pf}IP-CIDR{'6' if ':' in s else ''},{s},{_format_policy(attr, cfg.deny_policy)}\n")
        else:
            rbt = defaultdict(list)
            for r in all_d:
                if isinstance(r, GenericRule):
                    rbt[(r.type, r.is_exclusion)].append(r.val)
                    continue
                typ = 'domain' if r.match_type == MatchType.EXACT else 'domain_suffix' if r.match_type == MatchType.SUFFIX else 'domain_keyword' if r.match_type == MatchType.KEYWORD else 'domain_regex' if r.match_type == MatchType.REGEX else 'domain_wildcard'
                rbt[(typ, r.is_exclusion)].append(r.normalized)
            for s, _ in f_a_ip_strs: rbt[('ip_cidr', False)].append(s)
            for s, _ in f_d_ip_strs: rbt[('ip_cidr', True)].append(s)
            
            jr = [{'invert': True, **{t: v}} if excl else {t: v} for (t, excl), v in rbt.items()]
                
            fd = {"version": 1, "rules": jr}
            if USE_ORJSON: out_p.write_bytes(orjson.dumps(fd, option=orjson.OPT_INDENT_2))
            else: out_p.write_text(json.dumps(fd, indent=2, ensure_ascii=False), encoding='utf-8')

        out_srs = None
        if cfg.core_bin_path and cfg.validate_core_path() and cfg.output_format == 'json':
            out_srs = out_p.with_suffix('.srs')
            try: subprocess.run([str(Path(cfg.core_bin_path).expanduser().absolute()), "rule-set", "compile", "--output", str(out_srs), str(out_p)], check=True, capture_output=True)
            except Exception: pass

        sz = f"{(out_srs if out_srs and out_srs.exists() else out_p).stat().st_size / 1024:.1f}KB"
        rcnt = len(all_d) + len(f_a_ip_strs) + len(f_d_ip_strs)
        if issues: return (name, "⚠️", f"Issues: {len(issues)} | Processed: {rcnt}", sz)
        return (name, "✅", f"Tiered Merged: {rcnt} rules", sz)

    except Exception as e:
        logger.exception(f"[{name}] Task Error")
        return (name, "❌", str(e)[:100], "0KB")
    finally:
        if td and td.exists(): shutil.rmtree(td, ignore_errors=True)

def main() -> int:
    cfg, cfg_path, tasks = DEFAULT_CONFIG, Path(DEFAULT_CONFIG.config_file), []
    if cfg_path.exists():
        try:
            data = orjson.loads(cfg_path.read_bytes()) if USE_ORJSON else json.loads(cfg_path.read_text('utf-8'))
            cfg = MergeConfig.from_dict(data.get('global', {}), cfg)
            tasks = data.get('merge_tasks', [])
        except Exception: pass

    if not tasks: return 0
    lin = SemanticLineageAnalyzer(Path(cfg.lineage_state_file), cfg.enable_lineage)
    res, exe, intr, smt_executor = [], None, False, None
    if HAS_Z3 and cfg.enable_smt_verification:
        smt_ctx = mp.get_context('spawn') if hasattr(mp, 'get_context') else mp
        smt_executor = concurrent.futures.ProcessPoolExecutor(max_workers=1, mp_context=smt_ctx)
    try:
        exe = concurrent.futures.ThreadPoolExecutor(max_workers=min(cfg.max_workers, len(tasks)))
        futs = [exe.submit(worker, t, cfg, lin, smt_executor) for t in tasks]
        for f in concurrent.futures.as_completed(futs):
            try: res.append(f.result())
            except Exception as e: logger.error(f"Execution Error: {e}")
        if smf := os.getenv('GITHUB_STEP_SUMMARY'):
            try:
                with open(smf, 'a', encoding='utf-8') as f:
                    f.write("## Custom Merge Report\n| Task | Status | Details | Size |\n|---|---|---|---|\n")
                    for r in sorted(res, key=lambda x: x[0]): f.write(f"| {r[0]} | {r[1]} | {r[2]} | {r[3]} |\n")
            except OSError: pass
    except KeyboardInterrupt:
        intr = True
        for fu in futs: fu.cancel()
        if exe: exe.shutdown(wait=False, cancel_futures=True)
        return 130
    finally:
        if exe and not intr: exe.shutdown(wait=True)
        if smt_executor: smt_executor.shutdown(wait=True)
    return 1 if any(r[1] == "❌" for r in res) else 0

if __name__ == '__main__':
    sys.exit(main())
