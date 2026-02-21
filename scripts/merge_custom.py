#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import bisect
import concurrent.futures
import hashlib
import io
import ipaddress
import itertools
import json
import logging
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
from collections import defaultdict, OrderedDict
from enum import IntEnum
from pathlib import Path
from typing import Any, Iterable, Optional, Union
from urllib.parse import urljoin, urlparse

import requests
import urllib3
import urllib3.util.connection
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

if sys.version_info < (3, 9):
    print("Error: Python 3.9 or higher is required", file=sys.stderr)
    sys.exit(1)

_orig_create_connection = urllib3.util.connection.create_connection
_dns_context = threading.local()

def _patched_create_connection(address: tuple[str, int], *args: Any, **kwargs: Any) -> socket.socket:
    host, port = address
    forced_ip = getattr(_dns_context, 'forced_ip', None)
    forced_host = getattr(_dns_context, 'forced_host', None)
    if forced_ip and forced_host and host == forced_host:
        address = (forced_ip, port)
    return _orig_create_connection(address, *args, **kwargs)

urllib3.util.connection.create_connection = _patched_create_connection
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import orjson
    USE_ORJSON = True
    JSONDecodeErrorType = orjson.JSONDecodeError
except ImportError:
    USE_ORJSON = False
    JSONDecodeErrorType = json.JSONDecodeError

try:
    import msgpack
    USE_MSGPACK = True
except ImportError:
    USE_MSGPACK = False

try:
    import z3
    HAS_Z3 = True
except ImportError:
    HAS_Z3 = False

logger = logging.getLogger(__name__)

CACHE_VERSION: int = 12
MAX_LINE_LENGTH: int = 10000
MAX_DOMAIN_LABELS: int = 127
MAX_DOMAIN_LENGTH: int = 253
MAX_TASK_NAME_LENGTH: int = 100
DEFAULT_RETRIES: int = 3
MAX_DOWNLOAD_RETRIES: int = 3
SMALL_FILE_THRESHOLD: int = 5 * 1024 * 1024
MAX_BDD_DEPTH: int = 500
MAX_BACKOFF_SECONDS: int = 60
HTML_CHECK_THRESHOLD: int = 3
MAX_DNS_CACHE: int = 1024

OP_NEG = 0
OP_AND = 1
OP_OR = 2

RE_DOMAIN_LABEL = re.compile(r'^[a-z0-9_](?:[a-z0-9-_]{0,61}[a-z0-9_])?$', re.ASCII)
RE_HTML_STRICT = re.compile(rb'(?:^[\s]*<(?:!DOCTYPE\s+html|html|head|body))', re.IGNORECASE | re.MULTILINE)
RE_TASK_NAME = re.compile(r'^[a-zA-Z0-9_-]+$')

IPNetworkType = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

_DNS_CACHE: OrderedDict[str, tuple[float, list[str]]] = OrderedDict()
_DNS_PENDING: dict[str, threading.Event] = {}
_DNS_LOCK = threading.Lock()

class BDDDepthExceededError(Exception):
    pass

def parse_version(ver: str) -> tuple[int, int, int]:
    parts = list(map(int, re.findall(r'\d+', ver))) + [0, 0, 0]
    return (parts[0], parts[1], parts[2])

class CIDRFragmentationError(Exception):
    def __init__(self, processed_count: int, limit: int, loss_rate: float = 0.0, cidrs: Optional[list[IPNetworkType]] = None) -> None:
        self.processed_count = processed_count
        self.limit = limit
        self.loss_rate = loss_rate
        self.cidrs = cidrs or []
        super().__init__(f"CIDR fragmentation > {limit} ({processed_count}), loss {self.loss_rate:.2%}")

class TransientError(Exception):
    pass

class SecurityViolationError(Exception):
    pass

class MergeConfig:
    __slots__ = (
        'config_file', 'output_dir', 'core_bin_path', 'max_workers', 'max_download_size',
        'max_cidr_fragmentation', 'enable_ipv6', 'strict_zero_loss', 'max_domain_depth',
        'enable_cidr_approximation', 'cidr_approximation_max_loss_rate', 'enable_smt_verification',
        'smt_progressive_timeout', 'enable_bdd_verification', 'bdd_node_limit', 'url_allow_private_ips',
        'max_concurrent_downloads', 'download_timeout_connect', 'download_timeout_read',
        'compile_timeout_seconds', 'max_bdd_var_cache_size', 'max_source_age_days',
        'allow_local_core', 'enable_cache', 'bdd_lru_cache_size', 'max_verification_sources',
        'smt_unknown_default', 'conflict_resolution', 'output_format', 'allow_policy',
        'deny_policy', 'verify_ssl', 'max_cache_entries'
    )

    def __init__(self, **kwargs: Any) -> None:
        self.config_file = kwargs.get('config_file', 'scripts/custom_merge.json')
        self.output_dir = Path(kwargs.get('output_dir', 'rules'))
        self.core_bin_path = kwargs.get('core_bin_path', "")
        self.max_workers = int(kwargs.get('max_workers', 0))
        self.max_download_size = int(kwargs.get('max_download_size', 150 * 1024 * 1024))
        self.max_cidr_fragmentation = int(kwargs.get('max_cidr_fragmentation', 5000))
        self.enable_ipv6 = bool(kwargs.get('enable_ipv6', True))
        self.strict_zero_loss = bool(kwargs.get('strict_zero_loss', True))
        self.max_domain_depth = int(kwargs.get('max_domain_depth', MAX_DOMAIN_LABELS))
        self.enable_cidr_approximation = bool(kwargs.get('enable_cidr_approximation', True))
        self.cidr_approximation_max_loss_rate = float(kwargs.get('cidr_approximation_max_loss_rate', 0.05))
        self.enable_smt_verification = bool(kwargs.get('enable_smt_verification', False))
        self.smt_progressive_timeout = tuple(kwargs.get('smt_progressive_timeout', (100, 500, 2000, 5000)))
        self.enable_bdd_verification = bool(kwargs.get('enable_bdd_verification', True))
        self.bdd_node_limit = int(kwargs.get('bdd_node_limit', 100000))
        self.url_allow_private_ips = bool(kwargs.get('url_allow_private_ips', False))
        self.max_concurrent_downloads = int(kwargs.get('max_concurrent_downloads', 0))
        self.download_timeout_connect = int(kwargs.get('download_timeout_connect', 10))
        self.download_timeout_read = int(kwargs.get('download_timeout_read', 60))
        self.compile_timeout_seconds = int(kwargs.get('compile_timeout_seconds', 180))
        self.max_bdd_var_cache_size = int(kwargs.get('max_bdd_var_cache_size', 10000))
        self.max_source_age_days = int(kwargs.get('max_source_age_days', 30))
        self.allow_local_core = bool(kwargs.get('allow_local_core', False))
        self.enable_cache = bool(kwargs.get('enable_cache', True))
        self.bdd_lru_cache_size = int(kwargs.get('bdd_lru_cache_size', 50000))
        self.max_verification_sources = int(kwargs.get('max_verification_sources', 20))
        self.smt_unknown_default = bool(kwargs.get('smt_unknown_default', False))
        self.conflict_resolution = str(kwargs.get('conflict_resolution', 'first')).lower()
        self.output_format = str(kwargs.get('output_format', 'json')).lower()
        self.allow_policy = str(kwargs.get('allow_policy', 'PROXY'))
        self.deny_policy = str(kwargs.get('deny_policy', 'REJECT'))
        self.verify_ssl = bool(kwargs.get('verify_ssl', True))
        self.max_cache_entries = int(kwargs.get('max_cache_entries', 500))
        self._validate()

    def _validate(self) -> None:
        if self.max_cidr_fragmentation < 5000:
            logger.warning(f"max_cidr_fragmentation ({self.max_cidr_fragmentation}) is below recommended 5000")
        if self.max_download_size < 150 * 1024 * 1024:
            logger.warning(f"max_download_size ({self.max_download_size}) is below recommended 150MB")
        if self.max_source_age_days < 1:
            self.max_source_age_days = 1
        if self.compile_timeout_seconds < 30:
            self.compile_timeout_seconds = 30
        
        self.max_workers = max(0, self.max_workers)
        if self.max_workers == 0:
            self.max_workers = min(max(1, os.cpu_count() or 4) * 2, 16)
        if self.max_concurrent_downloads <= 0:
            self.max_concurrent_downloads = max(10, self.max_workers)

        self.max_domain_depth = max(1, min(MAX_DOMAIN_LABELS, self.max_domain_depth))
        self.max_verification_sources = max(1, self.max_verification_sources)
        self.bdd_node_limit = max(10000, self.bdd_node_limit)
        self.bdd_lru_cache_size = max(5000, self.bdd_lru_cache_size)
        self.max_cache_entries = max(10, self.max_cache_entries)

        if not self.smt_progressive_timeout or not all(isinstance(t, int) and t > 0 for t in self.smt_progressive_timeout):
            self.smt_progressive_timeout = (100, 500, 2000, 5000)

        self.cidr_approximation_max_loss_rate = max(0.0, min(1.0, self.cidr_approximation_max_loss_rate))
        if self.conflict_resolution not in ('first', 'specificity'):
            self.conflict_resolution = 'first'
        if self.output_format not in ('json', 'surge', 'clash'):
            self.output_format = 'json'

        self.allow_policy = self.allow_policy or 'PROXY'
        self.deny_policy = self.deny_policy or 'REJECT'

    @classmethod
    def from_dict(cls, d: dict[str, Any], base: MergeConfig) -> MergeConfig:
        merged: dict[str, Any] = {}
        for key in cls.__slots__:
            if key in d and d[key] is not None:
                val = d[key]
                if key == 'output_dir' and isinstance(val, str):
                    val = Path(val)
                elif key == 'smt_progressive_timeout' and isinstance(val, (list, tuple)):
                    val = tuple(int(item) for item in val)
                merged[key] = val
            else:
                merged[key] = getattr(base, key)
        return cls(**merged)

    def validate_core_path(self) -> bool:
        if not self.core_bin_path:
            return True
        if not self.allow_local_core:
            return False
        path = Path(self.core_bin_path).expanduser()
        if not path.is_file() or not os.access(str(path), os.X_OK):
            logger.error(f"Core binary invalid or not executable: {path}")
            return False
        return True

    def is_url_allowed(self, url: str) -> tuple[bool, str]:
        try:
            parsed = urlparse(url)
            scheme = parsed.scheme.lower()
            if scheme not in ('http', 'https'):
                return False, f"Scheme '{scheme}' not allowed"
            if not parsed.netloc:
                return False, "Empty netloc"
            hostname = parsed.hostname
            if not hostname:
                return False, "Empty or invalid hostname"
            if not self.url_allow_private_ips:
                try:
                    ip = ipaddress.ip_address(hostname)
                    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
                        return False, f"Private/reserved IP not allowed: {hostname}"
                except ValueError:
                    pass
            return True, "OK"
        except Exception as e:
            return False, str(e)

DEFAULT_CONFIG = MergeConfig()

class MatchType(IntEnum):
    EXACT = 1
    SUFFIX = 2
    WILDCARD = 3

class DomainRule:
    __slots__ = ('pattern', 'match_type', 'normalized', 'is_exclusion', 'specificity_score', '_hash')

    def __init__(self, pattern: str, match_type: MatchType, normalized: str, is_exclusion: bool = False, specificity_score: int = 0):
        self.pattern = pattern
        self.match_type = match_type
        self.normalized = normalized or pattern
        self.is_exclusion = is_exclusion

        if specificity_score == 0:
            score = self.normalized.count('.') * 10
            if self.match_type == MatchType.EXACT:
                score += 8
            elif self.match_type == MatchType.SUFFIX:
                score += 3
            elif self.match_type == MatchType.WILDCARD:
                score += 1
            self.specificity_score = score
        else:
            self.specificity_score = specificity_score

        self._hash = hash((self.normalized, self.match_type, self.is_exclusion))

    def __hash__(self) -> int:
        return self._hash

    def __eq__(self, other: Any) -> bool:
        if type(self) is not type(other): return NotImplemented
        return (self._hash == other._hash and
                self.match_type == other.match_type and
                self.is_exclusion == other.is_exclusion and
                self.normalized == other.normalized)

class IPCIDRRule:
    __slots__ = ('network', 'original_str', 'is_exclusion', 'version', 'start_int', 'end_int', 'prefixlen', '_hash')

    def __init__(self, network: IPNetworkType, original_str: str = "", is_exclusion: bool = False):
        self.network = network
        self.original_str = original_str or str(network)
        self.is_exclusion = is_exclusion
        self.version = network.version
        self.start_int = int(network.network_address)
        self.end_int = int(network.broadcast_address)
        self.prefixlen = network.prefixlen
        self._hash = hash((self.version, self.start_int, self.prefixlen, self.is_exclusion))

    def __hash__(self) -> int:
        return self._hash

    def __eq__(self, other: Any) -> bool:
        if type(self) is not type(other): return NotImplemented
        return (self._hash == other._hash and
                self.is_exclusion == other.is_exclusion and
                self.version == other.version and
                self.prefixlen == other.prefixlen and
                self.start_int == other.start_int)

RuleType = Union[DomainRule, IPCIDRRule]

def rules_digest(rules: Iterable[RuleType]) -> int:
    fs = frozenset(r._hash for r in rules)
    return hash(fs) if fs else 0

class VersionedBDDNode:
    __slots__ = ('var', 'low', 'high', '_node_id')

    def __init__(self, node_id: int, var: Any, low: Optional[VersionedBDDNode], high: Optional[VersionedBDDNode]) -> None:
        self.var = var
        self.low = low
        self.high = high
        self._node_id = node_id

    def __hash__(self) -> int:
        return self._node_id

    def __eq__(self, other: Any) -> bool:
        return self._node_id == getattr(other, '_node_id', -3)

class BDDEngine:
    __slots__ = ('var_map', 'var_counter', 'true_node', 'false_node',
                 '_op_cache', '_op_cache_max', '_node_cache', '_node_cache_max',
                 '_var_nodes', '_node_id_counter')

    def __init__(self, node_cache_max: int = 50000, op_cache_max: int = 50000) -> None:
        self.var_map: dict[Any, int] = {}
        self.var_counter = 0
        self._op_cache: OrderedDict[tuple[int, int, int], VersionedBDDNode] = OrderedDict()
        self._op_cache_max = op_cache_max
        self._node_cache: dict[tuple[int, int, int], VersionedBDDNode] = {}
        self._node_cache_max = node_cache_max
        self._node_id_counter = 0
        self.false_node = VersionedBDDNode(self._next_node_id(), -2, None, None)
        self.true_node = VersionedBDDNode(self._next_node_id(), -1, None, None)
        self._var_nodes: dict[int, VersionedBDDNode] = {}
        self._cache_node(self.false_node)
        self._cache_node(self.true_node)

    def _next_node_id(self) -> int:
        nid = self._node_id_counter
        self._node_id_counter += 1
        return nid

    def _get_cached_node(self, var: int, low_id: int, high_id: int) -> Optional[VersionedBDDNode]:
        return self._node_cache.get((var, low_id, high_id))

    def _cache_node(self, node: Optional[VersionedBDDNode]) -> None:
        if node is None:
            return
        key = (node.var, node.low._node_id if node.low else -1, node.high._node_id if node.high else -1)
        if key not in self._node_cache:
            if len(self._node_cache) >= self._node_cache_max:
                raise BDDDepthExceededError(f"BDD node limit reached ({self._node_cache_max})")
            self._node_cache[key] = node

    def get_var(self, name: Any) -> int:
        if name not in self.var_map:
            self.var_map[name] = self.var_counter
            self.var_counter += 1
        return self.var_map[name]

    def ith_var(self, i: int) -> VersionedBDDNode:
        if i not in self._var_nodes:
            node = VersionedBDDNode(self._next_node_id(), i, self.false_node, self.true_node)
            self._var_nodes[i] = node
            self._cache_node(node)
        return self._var_nodes[i]

    def neg(self, node: VersionedBDDNode, depth: int = 0) -> VersionedBDDNode:
        if depth > MAX_BDD_DEPTH: raise BDDDepthExceededError(f"BDD recursion depth exceeded ({MAX_BDD_DEPTH})")
        if node is self.true_node: return self.false_node
        if node is self.false_node: return self.true_node

        cache_key = (OP_NEG, node._node_id, -1)
        if cache_key in self._op_cache:
            self._op_cache.move_to_end(cache_key)
            return self._op_cache[cache_key]

        res = self._create_node(node.var, self.neg(node.low, depth + 1) if node.low else None,
                                self.neg(node.high, depth + 1) if node.high else None)
        self._op_cache[cache_key] = res
        if len(self._op_cache) > self._op_cache_max:
            self._op_cache.popitem(last=False)
        return res

    def apply_and(self, f: VersionedBDDNode, g: VersionedBDDNode, depth: int = 0) -> VersionedBDDNode:
        return self._apply_op(f, g, OP_AND, depth)

    def apply_or(self, f: VersionedBDDNode, g: VersionedBDDNode, depth: int = 0) -> VersionedBDDNode:
        return self._apply_op(f, g, OP_OR, depth)

    def apply_implies(self, f: VersionedBDDNode, g: VersionedBDDNode, depth: int = 0) -> VersionedBDDNode:
        return self.apply_or(self.neg(f, depth), g, depth)

    def _apply_op(self, f: VersionedBDDNode, g: VersionedBDDNode, op: int, depth: int = 0) -> VersionedBDDNode:
        if depth > MAX_BDD_DEPTH: raise BDDDepthExceededError(f"BDD recursion depth exceeded ({MAX_BDD_DEPTH})")

        if f is self.false_node or g is self.false_node:
            return self.false_node if op == OP_AND else (g if f is self.false_node else f)
        if f is self.true_node:
            return g if op == OP_AND else self.true_node
        if g is self.true_node:
            return f if op == OP_AND else self.true_node
        if f is g:
            return f

        cache_key = (op, min(f._node_id, g._node_id), max(f._node_id, g._node_id))
        if cache_key in self._op_cache:
            self._op_cache.move_to_end(cache_key)
            return self._op_cache[cache_key]

        if f.var == g.var:
            res = self._create_node(f.var, self._apply_op(f.low, g.low, op, depth + 1),
                                    self._apply_op(f.high, g.high, op, depth + 1))
        elif f.var < g.var:
            res = self._create_node(f.var, self._apply_op(f.low, g, op, depth + 1),
                                    self._apply_op(f.high, g, op, depth + 1))
        else:
            res = self._create_node(g.var, self._apply_op(f, g.low, op, depth + 1),
                                    self._apply_op(f, g.high, op, depth + 1))

        self._op_cache[cache_key] = res
        if len(self._op_cache) > self._op_cache_max:
            self._op_cache.popitem(last=False)
        return res

    def _create_node(self, var: int, low: Optional[VersionedBDDNode], high: Optional[VersionedBDDNode]) -> VersionedBDDNode:
        if low is high and low is not None:
            return low
        cached = self._get_cached_node(var, low._node_id if low else -1, high._node_id if high else -1)
        if cached:
            return cached
        node = VersionedBDDNode(self._next_node_id(), var, low, high)
        self._cache_node(node)
        return node

    def sat_ratio(self, node: VersionedBDDNode) -> float:
        if node is self.false_node: return 0.0
        if node is self.true_node: return 1.0
        cache: dict[VersionedBDDNode, float] = {}

        def _ratio(n: Optional[VersionedBDDNode], depth: int) -> float:
            if n is None: return 0.0
            if depth > MAX_BDD_DEPTH: raise BDDDepthExceededError(f"BDD sat_ratio depth exceeded ({MAX_BDD_DEPTH})")
            if n is self.false_node: return 0.0
            if n is self.true_node: return 1.0
            if n in cache: return cache[n]
            res = 0.5 * _ratio(n.low, depth + 1) + 0.5 * _ratio(n.high, depth + 1)
            cache[n] = res
            return res

        return _ratio(node, 0)

    def implies(self, f: VersionedBDDNode, g: VersionedBDDNode) -> bool:
        return self.apply_implies(f, g) is self.true_node

    def clear(self) -> None:
        self._op_cache.clear()
        self._node_cache.clear()
        self._var_nodes.clear()
        self.var_map.clear()
        self.var_counter = 0
        self._node_id_counter = 0
        self.false_node = VersionedBDDNode(self._next_node_id(), -2, None, None)
        self.true_node = VersionedBDDNode(self._next_node_id(), -1, None, None)
        self._cache_node(self.false_node)
        self._cache_node(self.true_node)


def split_ip_by_version(rules: list[IPCIDRRule]) -> tuple[list[IPCIDRRule], list[IPCIDRRule]]:
    return [r for r in rules if r.version == 4], [r for r in rules if r.version == 6]


def split_networks_by_version(nets: list[IPNetworkType]) -> tuple[list[IPNetworkType], list[IPNetworkType]]:
    return [n for n in nets if n.version == 4], [n for n in nets if n.version == 6]


class BDDRuleVerifier:
    __slots__ = ('engine', '_ip_vars', '_max_cache_size')

    def __init__(self, engine: BDDEngine, max_cache_size: int = 10000) -> None:
        self.engine = engine
        self._ip_vars: OrderedDict[tuple[int, int], VersionedBDDNode] = OrderedDict()
        self._max_cache_size = max_cache_size

    def _get_ip_var(self, ver: int, bp: int) -> VersionedBDDNode:
        key = (ver, bp)
        if key in self._ip_vars:
            self._ip_vars.move_to_end(key)
            return self._ip_vars[key]
        node = self.engine.ith_var(self.engine.get_var(('ip', ver, bp)))
        self._ip_vars[key] = node
        if len(self._ip_vars) > self._max_cache_size:
            self._ip_vars.popitem(last=False)
        return node

    def _preallocate_vars(self, rules: list[IPCIDRRule]) -> None:
        for r in rules:
            for bp in range(r.prefixlen):
                self._get_ip_var(r.version, bp)

    def encode_ip_rule(self, rule: IPCIDRRule) -> VersionedBDDNode:
        addr = rule.start_int
        plen = rule.prefixlen
        ver = rule.version
        width = 32 if ver == 4 else 128
        if plen == 0:
            return self.engine.true_node
        res = self.engine.true_node
        for bp in range(min(plen, width)):
            bit = (addr >> (width - 1 - bp)) & 1
            bv_node = self._get_ip_var(ver, bp)
            if bit == 0:
                bv_node = self.engine.neg(bv_node)
            res = self.engine.apply_and(res, bv_node)
        return res

    def build_rule_set_expression(self, allow_rules: list[IPCIDRRule], deny_rules: list[IPCIDRRule]) -> VersionedBDDNode:
        if not allow_rules and not deny_rules:
            return self.engine.false_node
        self._preallocate_vars(allow_rules + deny_rules)

        allow_bdd = self.engine.false_node
        for r in allow_rules:
            allow_bdd = self.engine.apply_or(allow_bdd, self.encode_ip_rule(r))

        if not deny_rules:
            return allow_bdd

        deny_bdd = self.engine.false_node
        for r in deny_rules:
            deny_bdd = self.engine.apply_or(deny_bdd, self.encode_ip_rule(r))

        return self.engine.apply_and(allow_bdd, self.engine.neg(deny_bdd))

    def verify_subset_strict(self, p_allow: list[IPCIDRRule], p_deny: list[IPCIDRRule], c_allow: list[IPCIDRRule]) -> tuple[bool, float]:
        if not c_allow: return True, 1.0

        def _verify_ver(p_v_allow: list[IPCIDRRule], p_v_deny: list[IPCIDRRule], c_v_allow: list[IPCIDRRule]) -> tuple[bool, float]:
            if not c_v_allow: return True, 1.0
            if not p_v_allow: return False, 0.0
            try:
                p_bdd = self.build_rule_set_expression(p_v_allow, p_v_deny)
                c_bdd = self.build_rule_set_expression(c_v_allow, [])
                if self.engine.implies(c_bdd, p_bdd): return True, 1.0
                c_ratio = self.engine.sat_ratio(c_bdd)
                if c_ratio == 0.0: return True, 1.0
                diff = self.engine.apply_and(c_bdd, self.engine.neg(p_bdd))
                d_ratio = self.engine.sat_ratio(diff)
                if d_ratio == 0.0: return True, 1.0
                return False, max(0.0, min(1.0, 1.0 - (d_ratio / c_ratio)))
            except BDDDepthExceededError as e:
                logger.error(f"BDD verification depth exceeded: {e}")
                return False, 0.0

        v4_p_a, v6_p_a = split_ip_by_version(p_allow)
        v4_p_d, v6_p_d = split_ip_by_version(p_deny)
        v4_c_a, v6_c_a = split_ip_by_version(c_allow)

        ok_v4, conf_v4 = _verify_ver(v4_p_a, v4_p_d, v4_c_a)
        ok_v6, conf_v6 = _verify_ver(v6_p_a, v6_p_d, v6_c_a)

        conf = min(conf_v4 if v4_c_a and not ok_v4 else 1.0, conf_v6 if v6_c_a and not ok_v6 else 1.0)
        return (ok_v4 and ok_v6), conf

    def verify_deny_subset(self, p_deny: list[IPCIDRRule], c_deny: list[IPCIDRRule]) -> tuple[bool, float]:
        if not c_deny: return True, 1.0

        def _verify_ver(p_v_deny: list[IPCIDRRule], c_v_deny: list[IPCIDRRule]) -> tuple[bool, float]:
            if not c_v_deny: return True, 1.0
            if not p_v_deny: return False, 0.0
            try:
                parent_bdd = self.build_rule_set_expression(p_v_deny, [])
                child_bdd = self.build_rule_set_expression(c_v_deny, [])
                diff = self.engine.apply_and(child_bdd, self.engine.neg(parent_bdd))
                if diff is self.engine.false_node: return True, 1.0
                c_ratio = self.engine.sat_ratio(child_bdd)
                if c_ratio == 0.0: return True, 1.0
                d_ratio = self.engine.sat_ratio(diff)
                return False, max(0.0, min(1.0, 1.0 - (d_ratio / c_ratio)))
            except BDDDepthExceededError as e:
                logger.error(f"BDD deny verification depth exceeded: {e}")
                return False, 0.0

        v4_p_d, v6_p_d = split_ip_by_version(p_deny)
        v4_c_d, v6_c_d = split_ip_by_version(c_deny)

        ok_v4, conf_v4 = _verify_ver(v4_p_d, v4_c_d)
        ok_v6, conf_v6 = _verify_ver(v6_p_d, v6_c_d)

        conf = min(conf_v4 if v4_c_d and not ok_v4 else 1.0, conf_v6 if v6_c_d and not ok_v6 else 1.0)
        return (ok_v4 and ok_v6), conf

    def clear(self) -> None:
        self._ip_vars.clear()
        self.engine.clear()

class SMTVerifier:
    __slots__ = ('enabled', '_z3_available', '_solver_cache', '_config',
                 '_timeout_stages', '_cache_lock', '_max_cache_size', '_solver_pool')
    _SMT_CACHE_VERSION = 15

    def __init__(self, config: MergeConfig) -> None:
        self._config = config
        self._z3_available = HAS_Z3 and config.enable_smt_verification
        self.enabled = self._z3_available
        self._solver_cache: OrderedDict[tuple[int, int, int], tuple[bool, float, str]] = OrderedDict()
        self._cache_lock = threading.RLock()
        self._max_cache_size = config.max_bdd_var_cache_size
        self._timeout_stages = config.smt_progressive_timeout
        self._solver_pool = threading.local()

    def _get_z3_context(self) -> Any:
        if not hasattr(self._solver_pool, 'ctx'):
            self._solver_pool.ctx = z3.Context()
        return getattr(self._solver_pool, 'ctx')

    def _get_solver(self) -> Any:
        if not hasattr(self._solver_pool, 'solver'):
            self._solver_pool.solver = z3.Solver(ctx=self._get_z3_context())
        return getattr(self._solver_pool, 'solver')

    def _reset_solver(self) -> None:
        if hasattr(self._solver_pool, 'solver'):
            delattr(self._solver_pool, 'solver')
        if hasattr(self._solver_pool, 'ctx'):
            delattr(self._solver_pool, 'ctx')

    def clear_thread_state(self) -> None:
        """清除当前线程的 Z3 上下文和求解器，防止内存泄漏"""
        self._reset_solver()

    def _verify_with_timeouts(self, s: Any, child_expr: Any, parent_expr: Any, label: str) -> tuple[bool, float, str]:
        ctx = self._get_z3_context()
        solver_broken = False
        try:
            for timeout in self._timeout_stages:
                s.push()
                s.set("timeout", timeout)
                s.add(child_expr)
                s.add(z3.Not(parent_expr, ctx=ctx))
                res = s.check()
                s.pop()
                if res == z3.unsat:
                    return True, 1.0, f"{label}unsat"
                elif res == z3.sat:
                    return False, 0.0, f"{label}sat"
            return False, 0.0, f"{label}unknown"
        except Exception as e:
            solver_broken = True
            logger.error(f"SMT {label} error: {e}")
            return False, 0.0, f"{label}z3_error"
        finally:
            if solver_broken:
                self._reset_solver()

    def _build_domain_expr(self, rules: list[DomainRule], var_name: str = 'x_domain') -> Optional[Any]:
        if not rules: return None
        ctx = self._get_z3_context()
        x_domain = z3.String(var_name, ctx=ctx)
        terms = []
        for r in rules:
            if r.match_type == MatchType.EXACT:
                terms.append(x_domain == z3.StringVal(r.normalized, ctx=ctx))
            elif r.match_type == MatchType.SUFFIX:
                terms.append(z3.Or(
                    x_domain == z3.StringVal(r.normalized, ctx=ctx),
                    z3.And(z3.Length(x_domain) > len(r.normalized),
                           z3.SuffixOf(z3.StringVal('.' + r.normalized, ctx=ctx), x_domain), ctx=ctx), ctx=ctx))
            elif r.match_type == MatchType.WILDCARD:
                terms.append(z3.And(z3.Length(x_domain) > len(r.normalized) + 1,
                                    z3.SuffixOf(z3.StringVal('.' + r.normalized, ctx=ctx), x_domain), ctx=ctx))
        if not terms: return None
        return z3.Or(*terms, ctx=ctx) if len(terms) > 1 else terms[0]

    def _build_ip_expr(self, rules: list[IPCIDRRule], version: int, var_name: str) -> Optional[Any]:
        if not rules: return None
        ctx = self._get_z3_context()
        width = 32 if version == 4 else 128
        x_ip = z3.BitVec(var_name, width, ctx=ctx)
        terms = []
        for rule in rules:
            addr, plen = rule.start_int, rule.prefixlen
            if plen == 0: return z3.BoolVal(True, ctx=ctx)
            shifted = z3.LShR(x_ip, width - plen)
            target = addr >> (width - plen)
            terms.append(shifted == target)
        return z3.Or(*terms, ctx=ctx) if terms else None

    def _build_parent_expr(self, allow_expr: Optional[Any], deny_expr: Optional[Any], ctx: Any) -> Any:
        if allow_expr is None:
            return z3.BoolVal(False, ctx=ctx)
        elif deny_expr is None:
            return allow_expr
        return z3.And(allow_expr, z3.Not(deny_expr, ctx=ctx), ctx=ctx)

    def verify_allow_subset(self,
                            p_dom_allow: list[DomainRule], p_dom_deny: list[DomainRule], c_dom_allow: list[DomainRule],
                            p_ip_allow: list[IPCIDRRule], p_ip_deny: list[IPCIDRRule], c_ip_allow: list[IPCIDRRule],
                            parent_digest: int) -> tuple[bool, float, str]:
        if not self.enabled: return False, 0.0, "smt_disabled"
        if not c_dom_allow and not c_ip_allow: return True, 1.0, "trivial"

        c_digest = rules_digest(itertools.chain(c_dom_allow, c_ip_allow))
        key = (self._SMT_CACHE_VERSION, parent_digest, c_digest)

        with self._cache_lock:
            if key in self._solver_cache:
                self._solver_cache.move_to_end(key)
                return self._solver_cache[key]

        domain_ok, domain_conf, domain_msg = self._verify_domain_allow_subset(p_dom_allow, p_dom_deny, c_dom_allow)
        ip_ok, ip_conf, ip_msg = self._verify_ip_allow_subset(p_ip_allow, p_ip_deny, c_ip_allow)

        overall_ok = (not c_dom_allow or domain_ok) and (not c_ip_allow or ip_ok)
        conf = min(domain_conf if c_dom_allow and not domain_ok else 1.0, ip_conf if c_ip_allow and not ip_ok else 1.0)
        res = (overall_ok, conf, f"domain:{domain_msg},ip:{ip_msg}")

        with self._cache_lock:
            self._solver_cache[key] = res
            if len(self._solver_cache) > self._max_cache_size:
                self._solver_cache.popitem(last=False)

        if not overall_ok and self._config.smt_unknown_default and ("unknown" in domain_msg or "unknown" in ip_msg):
            return True, 0.5, "unknown"
        return res

    def _verify_domain_allow_subset(self, p_allow: list[DomainRule], p_deny: list[DomainRule], c_allow: list[DomainRule]) -> tuple[bool, float, str]:
        if not c_allow: return True, 1.0, "trivial"
        s, ctx = self._get_solver(), self._get_z3_context()
        child_expr = self._build_domain_expr(c_allow, 'x_domain')
        if child_expr is None: return True, 1.0, "trivial"
        
        parent_expr = self._build_parent_expr(
            self._build_domain_expr(p_allow, 'x_domain'),
            self._build_domain_expr(p_deny, 'x_domain'),
            ctx
        )
        return self._verify_with_timeouts(s, child_expr, parent_expr, "")

    def _verify_ip_version_allow_subset(self, p_allow: list[IPCIDRRule], p_deny: list[IPCIDRRule], c_allow: list[IPCIDRRule], version: int) -> tuple[bool, float, str]:
        if not c_allow: return True, 1.0, f"v{version}_trivial"
        s, ctx = self._get_solver(), self._get_z3_context()
        child_expr = self._build_ip_expr(c_allow, version, f'x_ipv{version}')
        if child_expr is None: return True, 1.0, f"v{version}_trivial"
        
        parent_expr = self._build_parent_expr(
            self._build_ip_expr(p_allow, version, f'x_ipv{version}'),
            self._build_ip_expr(p_deny, version, f'x_ipv{version}'),
            ctx
        )
        return self._verify_with_timeouts(s, child_expr, parent_expr, f"v{version}_")

    def _verify_ip_allow_subset(self, p_allow: list[IPCIDRRule], p_deny: list[IPCIDRRule], c_allow: list[IPCIDRRule]) -> tuple[bool, float, str]:
        if not c_allow: return True, 1.0, "trivial,trivial"
        v4_p_a, v6_p_a = split_ip_by_version(p_allow)
        v4_p_d, v6_p_d = split_ip_by_version(p_deny)
        v4_c_a, v6_c_a = split_ip_by_version(c_allow)

        v4_ok, v4_conf, v4_msg = self._verify_ip_version_allow_subset(v4_p_a, v4_p_d, v4_c_a, 4)
        v6_ok, v6_conf, v6_msg = self._verify_ip_version_allow_subset(v6_p_a, v6_p_d, v6_c_a, 6)
        return (v4_ok and v6_ok), min(v4_conf, v6_conf), f"{v4_msg},{v6_msg}"

    def verify_deny_subset(self, p_dom_deny: list[DomainRule], c_dom_deny: list[DomainRule], p_ip_deny: list[IPCIDRRule], c_ip_deny: list[IPCIDRRule], parent_digest: int) -> tuple[bool, float, str]:
        if not self.enabled: return False, 0.0, "smt_disabled"
        if not c_dom_deny and not c_ip_deny: return True, 1.0, "trivial"

        c_digest = rules_digest(itertools.chain(c_dom_deny, c_ip_deny))
        key = (self._SMT_CACHE_VERSION, parent_digest, c_digest)

        with self._cache_lock:
            if key in self._solver_cache:
                self._solver_cache.move_to_end(key)
                return self._solver_cache[key]

        domain_ok, domain_conf, domain_msg = self._verify_domain_deny_subset(p_dom_deny, c_dom_deny)
        ip_ok, ip_conf, ip_msg = self._verify_ip_deny_subset(p_ip_deny, c_ip_deny)

        overall_ok = (not c_dom_deny or domain_ok) and (not c_ip_deny or ip_ok)
        conf = min(domain_conf if c_dom_deny and not domain_ok else 1.0, ip_conf if c_ip_deny and not ip_ok else 1.0)
        res = (overall_ok, conf, f"domain:{domain_msg},ip:{ip_msg}")

        with self._cache_lock:
            self._solver_cache[key] = res
            if len(self._solver_cache) > self._max_cache_size:
                self._solver_cache.popitem(last=False)

        if not overall_ok and self._config.smt_unknown_default and ("unknown" in domain_msg or "unknown" in ip_msg):
            return True, 0.5, "unknown"
        return res

    def _verify_domain_deny_subset(self, p_deny: list[DomainRule], c_deny: list[DomainRule]) -> tuple[bool, float, str]:
        if not c_deny: return True, 1.0, "trivial"
        s, ctx = self._get_solver(), self._get_z3_context()
        child_expr = self._build_domain_expr(c_deny, 'x_domain_deny')
        if child_expr is None: return True, 1.0, "trivial"
        parent_expr = self._build_domain_expr(p_deny, 'x_domain_deny') or z3.BoolVal(False, ctx=ctx)
        return self._verify_with_timeouts(s, child_expr, parent_expr, "")

    def _verify_ip_version_deny_subset(self, p_deny: list[IPCIDRRule], c_deny: list[IPCIDRRule], version: int) -> tuple[bool, float, str]:
        if not c_deny: return True, 1.0, f"v{version}_trivial"
        s, ctx = self._get_solver(), self._get_z3_context()
        child_expr = self._build_ip_expr(c_deny, version, f'x_ipv{version}')
        if child_expr is None: return True, 1.0, f"v{version}_trivial"
        parent_expr = self._build_ip_expr(p_deny, version, f'x_ipv{version}') or z3.BoolVal(False, ctx=ctx)
        return self._verify_with_timeouts(s, child_expr, parent_expr, f"v{version}_")

    def _verify_ip_deny_subset(self, p_deny: list[IPCIDRRule], c_deny: list[IPCIDRRule]) -> tuple[bool, float, str]:
        if not c_deny: return True, 1.0, "trivial,trivial"
        v4_p_d, v6_p_d = split_ip_by_version(p_deny)
        v4_c_d, v6_c_d = split_ip_by_version(c_deny)

        v4_ok, v4_conf, v4_msg = self._verify_ip_version_deny_subset(v4_p_d, v4_c_d, 4)
        v6_ok, v6_conf, v6_msg = self._verify_ip_version_deny_subset(v6_p_d, v6_c_d, 6)
        return (v4_ok and v6_ok), min(v4_conf, v6_conf), f"{v4_msg},{v6_msg}"

class CoverageChecker:
    __slots__ = ('_exact_domains', '_wildcard_domains', '_suffix_domains',
                 '_ipv4_allow', '_ipv4_deny', '_ipv6_allow', '_ipv6_deny',
                 '_ipv4_allow_starts', '_ipv4_deny_starts', '_ipv6_allow_starts', '_ipv6_deny_starts')

    def __init__(self, parent_rules: Iterable[RuleType]) -> None:
        self._exact_domains = set()
        self._wildcard_domains = set()
        self._suffix_domains = set()

        ipv4_allow_nets, ipv4_deny_nets = [], []
        ipv6_allow_nets, ipv6_deny_nets = [], []

        for r in parent_rules:
            if isinstance(r, DomainRule):
                key = (r.normalized, r.is_exclusion)
                if r.match_type == MatchType.EXACT:
                    self._exact_domains.add(key)
                elif r.match_type == MatchType.WILDCARD:
                    self._wildcard_domains.add(key)
                elif r.match_type == MatchType.SUFFIX:
                    self._suffix_domains.add(key)
            else:
                if r.version == 4:
                    (ipv4_deny_nets if r.is_exclusion else ipv4_allow_nets).append(r.network)
                else:
                    (ipv6_deny_nets if r.is_exclusion else ipv6_allow_nets).append(r.network)

        self._ipv4_allow = self._collapse_networks(ipv4_allow_nets)
        self._ipv4_deny = self._collapse_networks(ipv4_deny_nets)
        self._ipv6_allow = self._collapse_networks(ipv6_allow_nets)
        self._ipv6_deny = self._collapse_networks(ipv6_deny_nets)

        self._ipv4_allow_starts = [start for start, _ in self._ipv4_allow]
        self._ipv4_deny_starts = [start for start, _ in self._ipv4_deny]
        self._ipv6_allow_starts = [start for start, _ in self._ipv6_allow]
        self._ipv6_deny_starts = [start for start, _ in self._ipv6_deny]

    @staticmethod
    def _collapse_networks(nets: list[IPNetworkType]) -> list[tuple[int, int]]:
        if not nets: return []
        return sorted((int(net.network_address), int(net.broadcast_address)) for net in ipaddress.collapse_addresses(nets))

    def _domain_covered(self, r: DomainRule) -> bool:
        key = (r.normalized, r.is_exclusion)
        if r.match_type == MatchType.EXACT:
            if key in self._exact_domains or key in self._suffix_domains: return True
        elif r.match_type == MatchType.WILDCARD:
            if key in self._wildcard_domains or key in self._suffix_domains: return True
        elif r.match_type == MatchType.SUFFIX:
            if key in self._suffix_domains: return True

        parts = r.normalized.split('.')
        for i in range(1, len(parts)):
            pkey = (".".join(parts[i:]), r.is_exclusion)
            if pkey in self._suffix_domains or pkey in self._wildcard_domains:
                return True
        return False

    def calculate(self, child_rules: Iterable[RuleType]) -> float:
        covered = total = 0
        for r in child_rules:
            total += 1
            if isinstance(r, DomainRule):
                if self._domain_covered(r): covered += 1
            else:
                if r.version == 4:
                    lst = self._ipv4_deny if r.is_exclusion else self._ipv4_allow
                    starts = self._ipv4_deny_starts if r.is_exclusion else self._ipv4_allow_starts
                else:
                    lst = self._ipv6_deny if r.is_exclusion else self._ipv6_allow
                    starts = self._ipv6_deny_starts if r.is_exclusion else self._ipv6_allow_starts

                if not lst: continue
                idx = bisect.bisect_right(starts, r.start_int) - 1
                if idx >= 0 and r.end_int <= lst[idx][1]: covered += 1
        return (covered / total) if total > 0 else 1.0


class SweepLineCIDRManager:
    @classmethod
    def approximate_collapse(cls, nets: list[IPNetworkType], target: int) -> tuple[list[IPNetworkType], float]:
        if target <= 0: return [], 1.0
        nets = list(ipaddress.collapse_addresses(nets))
        if len(nets) <= target: return nets, 0.0

        orig_hosts = sum(n.num_addresses for n in nets)
        if orig_hosts == 0: return [], 1.0

        nets.sort(key=lambda x: -x.num_addresses)
        kept = nets[:target]
        loss = max(0.0, 1.0 - sum(n.num_addresses for n in kept) / orig_hosts)
        return kept, loss

    @classmethod
    def _subtract_version(cls, base: list[IPNetworkType], exclude: list[IPNetworkType], width: int, max_frag: Optional[int] = None) -> list[IPNetworkType]:
        if not base: return []
        if not exclude:
            cidrs = list(ipaddress.collapse_addresses(base))
            if max_frag and len(cidrs) > max_frag: raise CIDRFragmentationError(len(cidrs), max_frag, 0.0, cidrs)
            return cidrs

        max_addr = (1 << width) - 1
        events: list[tuple[int, int]] = []

        for net in base:
            events.append((int(net.network_address), 2))
            if (e := int(net.broadcast_address)) < max_addr: events.append((e + 1, 0))

        for net in exclude:
            events.append((int(net.network_address), 3))
            if (e := int(net.broadcast_address)) < max_addr: events.append((e + 1, 1))

        events.sort()

        intervals, merged_intervals = [], []
        base_depth, excl_depth, prev = 0, 0, events[0][0]

        for pos, prio in events:
            if pos > prev and base_depth > 0 and excl_depth == 0: intervals.append((prev, pos - 1))
            if prio == 0: base_depth -= 1
            elif prio == 1: excl_depth -= 1
            elif prio == 2: base_depth += 1
            elif prio == 3: excl_depth += 1
            prev = pos

        if base_depth > 0 and excl_depth == 0: intervals.append((prev, max_addr))

        for s, e in intervals:
            if not merged_intervals:
                merged_intervals.append((s, e))
            else:
                last_s, last_e = merged_intervals[-1]
                if s <= last_e + 1: merged_intervals[-1] = (last_s, max(last_e, e))
                else: merged_intervals.append((s, e))

        cidrs = []
        ver = 4 if width == 32 else 6
        
        for s, e in merged_intervals:
            if s <= e:
                try:
                    if ver == 4:
                        cidrs.extend(ipaddress.summarize_address_range(ipaddress.IPv4Address(s), ipaddress.IPv4Address(e)))
                    else:
                        cidrs.extend(ipaddress.summarize_address_range(ipaddress.IPv6Address(s), ipaddress.IPv6Address(e)))
                except (ValueError, TypeError):
                    pass

        if max_frag and len(cidrs) > max_frag: raise CIDRFragmentationError(len(cidrs), max_frag, 0.0, cidrs)
        return cidrs

    @classmethod
    def subtract(cls, base_nets: list[IPNetworkType], exclude_nets: Iterable[IPNetworkType], max_fragments: int = 5000,
                 enable_approximation: bool = False, max_loss_rate: float = 0.05, strict_zero_loss: bool = True) -> list[IPNetworkType]:
        v4_base, v6_base = split_networks_by_version(base_nets)
        v4_excl, v6_excl = split_networks_by_version(list(exclude_nets))

        def process_version(base_list: list[IPNetworkType], excl_list: list[IPNetworkType], width: int) -> list[IPNetworkType]:
            try:
                return cls._subtract_version(base_list, excl_list, width, max_fragments)
            except CIDRFragmentationError as e:
                if enable_approximation and e.cidrs:
                    res, loss = cls.approximate_collapse(e.cidrs, max_fragments)
                    if loss > max_loss_rate or (strict_zero_loss and loss > 0):
                        raise CIDRFragmentationError(len(res), max_fragments, loss, res)
                    return res
                raise

        total = (process_version(v4_base, v4_excl, 32) if v4_base else []) + (process_version(v6_base, v6_excl, 128) if v6_base else [])
        if not total: return []

        if len(total) > max_fragments:
            if not enable_approximation:
                raise CIDRFragmentationError(len(total), max_fragments, 0.0, total)
            v4_res, v6_res = split_networks_by_version(total)
            target_v4 = int(max_fragments * len(v4_res) / len(total)) if v4_res else 0
            target_v6 = max_fragments - target_v4
            if target_v4 == 0 and v4_res: target_v4, target_v6 = 1, max_fragments - 1
            if target_v6 == 0 and v6_res: target_v6, target_v4 = 1, max_fragments - 1

            v4_approx, loss_v4 = cls.approximate_collapse(v4_res, target_v4) if v4_res else ([], 0.0)
            v6_approx, loss_v6 = cls.approximate_collapse(v6_res, target_v6) if v6_res else ([], 0.0)
            total = v4_approx + v6_approx
            loss = max(loss_v4, loss_v6)
            if loss > 0:
                if strict_zero_loss or loss > max_loss_rate: raise CIDRFragmentationError(len(total), max_fragments, loss, total)
                logger.warning(f"CIDR approximation loss max {loss:.2%} due to fragmentation, resulting in {len(total)} CIDRs")
        return total


class WALBackend:
    __slots__ = ('db_path', 'data', '_config', '_timestamp', '_lock', '_max_entries', '_pending_write_ts')

    def __init__(self, db_path: Path, config: MergeConfig) -> None:
        self.db_path = db_path.with_suffix('.ldb')
        self.data: dict[str, Any] = {}
        self._config = config
        self._max_entries = config.max_cache_entries
        self._timestamp = 0.0
        self._pending_write_ts = 0.0
        self._lock = threading.RLock()
        self._load()

    def _load(self) -> None:
        with self._lock:
            if not self.db_path.exists(): return
            try:
                content = self.db_path.read_bytes()
                if len(content) < 24: return
                cs, ts_bytes, db = content[:16], content[16:24], content[24:]
                if hashlib.blake2b(db, digest_size=16).digest() != cs:
                    logger.warning(f"Checksum mismatch for {self.db_path}")
                    return
                self._timestamp = struct.unpack('>d', ts_bytes)[0]
                if USE_MSGPACK:
                    try:
                        self.data = msgpack.unpackb(db, raw=False)
                        return
                    except Exception: pass
                if USE_ORJSON:
                    try:
                        self.data = orjson.loads(db)
                        return
                    except Exception: pass
                self.data = json.loads(db.decode('utf-8'))
            except Exception as e:
                logger.error(f"Failed to load DB {self.db_path}: {e}")

    def _snapshot(self) -> bool:
        tmp = Path(f"{self.db_path}.tmp.{os.getpid()}.{threading.get_ident()}")
        try:
            with self._lock:
                if len(self.data) > self._max_entries:
                    items = [(k, v.get('timestamp', time.time()) if isinstance(v, dict) else time.time()) for k, v in self.data.items()]
                    items.sort(key=lambda x: x[1])
                    for k, _ in items[:len(self.data) - self._max_entries]:
                        del self.data[k]

                current_ts = time.time()
                ts_bytes = struct.pack('>d', current_ts)

                if USE_MSGPACK: db_bytes = msgpack.packb(self.data, use_bin_type=True)
                elif USE_ORJSON: db_bytes = orjson.dumps(self.data)
                else: db_bytes = json.dumps(self.data, sort_keys=True, separators=(',', ':')).encode('utf-8')

                digest = hashlib.blake2b(db_bytes, digest_size=16).digest()
                self._pending_write_ts = current_ts

            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            
            try:
                f = os.fdopen(fd, 'wb')
            except Exception:
                os.close(fd)
                raise
                
            with f:
                f.write(digest)
                f.write(ts_bytes)
                f.write(db_bytes)
                f.flush()
                os.fsync(f.fileno())

            with self._lock:
                if self._pending_write_ts == current_ts:
                    tmp.replace(self.db_path)
                    self._timestamp = current_ts
                else:
                    tmp.unlink(missing_ok=True)
            return True
        except Exception as e:
            logger.error(f"Snapshot failed: {e}")
            if tmp.exists(): tmp.unlink(missing_ok=True)
            return False

    def get(self, key: str) -> Any:
        with self._lock: return self.data.get(key)

    def put_batch(self, updates: dict[str, Any]) -> bool:
        with self._lock: self.data.update(updates)
        return self._snapshot()


class ParsedRuleSet:
    __slots__ = ('url', 'weight', 'domain_rules', 'ip_rules', 'timestamp', 'content_hash')

    def __init__(self, url: str, weight: float, domain_rules: tuple[DomainRule, ...], ip_rules: tuple[IPCIDRRule, ...], timestamp: float, content_hash: str = ""):
        self.url = url
        self.weight = weight
        self.domain_rules = domain_rules
        self.ip_rules = ip_rules
        self.timestamp = timestamp

        if not content_hash:
            h = hashlib.sha256()
            for r in sorted(self.domain_rules, key=lambda x: (x.normalized, x.match_type.value, x.is_exclusion)):
                h.update(b"D%d%d%s" % (r.match_type.value, r.is_exclusion, r.normalized.encode('ascii', errors='ignore')))
            for ir in sorted(self.ip_rules, key=lambda x: (x.version, x.start_int, x.prefixlen, x.is_exclusion)):
                h.update(b"I%d%d%d%d" % (ir.version, ir.start_int, ir.prefixlen, ir.is_exclusion))
            self.content_hash = h.hexdigest()
        else:
            self.content_hash = content_hash


def _looks_like_json(data: bytes) -> bool:
    if not data:
        return False
    start = 3 if data.startswith(b'\xef\xbb\xbf') else 0
    end = min(start + 1024, len(data))
    for i in range(start, end):
        b = data[i]
        if b in (123, 91):  # '{' or '['
            return True
        if b not in (32, 9, 10, 13):  # 空白字符
            return False
    return False


class RuleParser:
    __slots__ = ('_config', '_max_domain_depth')
    RULE_TYPE_MAP = {
        'DOMAIN-SUFFIX': 'domain_suffix', 'DOMAIN': 'domain',
        'DOMAIN-WILDCARD': 'domain_wildcard', 'IP-CIDR': 'ip_cidr', 'IP-CIDR6': 'ip_cidr',
    }

    def __init__(self, config: MergeConfig) -> None:
        self._config = config
        self._max_domain_depth = config.max_domain_depth

    def parse(self, source: Union[bytes, Path], url: str, weight: float) -> ParsedRuleSet:
        dom: list[DomainRule] = []
        ip: list[IPCIDRRule] = []

        try:
            if isinstance(source, Path):
                with source.open('rb') as f:
                    head = f.read(4096)
                is_json = _looks_like_json(head)
            else:
                is_json = _looks_like_json(source)
        except OSError as e:
            logger.warning(f"File read error for {url}: {e}")
            return ParsedRuleSet(url, weight, (), (), timestamp=time.time())

        if is_json:
            try:
                if USE_ORJSON:
                    if isinstance(source, Path):
                        with source.open('rb') as f:
                            raw_bytes = f.read()
                    else:
                        raw_bytes = source
                    
                    if raw_bytes.startswith(b'\xef\xbb\xbf'):
                        raw_bytes = raw_bytes[3:]
                    data = orjson.loads(raw_bytes)
                    # 立即释放原始字节数组，降低峰值内存
                    del raw_bytes
                else:
                    if isinstance(source, Path):
                        with source.open('r', encoding='utf-8-sig', errors='ignore') as f:
                            data = json.load(f)
                    else:
                        data = json.loads(source.decode('utf-8-sig', errors='ignore'))

                rules = data.get('rules', []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
                
                for rule in rules:
                    if not isinstance(rule, dict): continue
                    is_excl = rule.get('invert', False)
                    for k, v in rule.items():
                        if k == 'invert': continue
                        mt = self.RULE_TYPE_MAP.get(k.upper(), k)
                        if isinstance(v, list):
                            for val in v:
                                if (s := str(val).strip()): self._add_rule(mt, s, is_excl, dom, ip)
                        elif (s := str(v).strip()):
                            self._add_rule(mt, s, is_excl, dom, ip)
                return ParsedRuleSet(url, weight, tuple(dom), tuple(ip), timestamp=time.time())
            except (ValueError, TypeError, JSONDecodeErrorType, MemoryError) as e:
                logger.debug(f"JSON parsing failed for {url}, falling back to text: {e}")
                dom.clear()
                ip.clear()

        def _process_text_stream(stream: Iterable[str]) -> None:
            for line in stream:
                line = line.strip()
                if len(line) > MAX_LINE_LENGTH or not line or line.startswith(('#', '//', ';')): continue
                is_excl = line.startswith('!')
                val = line[1:].strip() if is_excl else line
                if ',' in val:
                    parts = val.split(',', 2)
                    if len(parts) >= 2 and (m := self.RULE_TYPE_MAP.get(parts[0].upper())):
                        self._add_rule(m, parts[1].strip(), is_excl, dom, ip)
                else:
                    self._add_rule('domain', val, is_excl, dom, ip)

        try:
            if isinstance(source, Path):
                with open(source, 'r', encoding='utf-8-sig', errors='ignore') as f:
                    _process_text_stream(f)
            else:
                with io.TextIOWrapper(io.BytesIO(source), encoding='utf-8-sig', errors='ignore') as f:
                    _process_text_stream(f)
        except OSError as e:
            logger.warning(f"Text streaming failed for {url}: {e}")
            return ParsedRuleSet(url, weight, (), (), timestamp=time.time())

        return ParsedRuleSet(url, weight, tuple(dom), tuple(ip), timestamp=time.time())

    def _add_rule(self, typ: Optional[str], val: str, is_excl: bool, dom: list[DomainRule], ip: list[IPCIDRRule]) -> None:
        if typ in ('domain', 'domain_suffix', 'domain_wildcard'):
            if not val: return
            expected_type = MatchType.WILDCARD if typ == 'domain_wildcard' else (MatchType.SUFFIX if typ == 'domain_suffix' else MatchType.EXACT)
            clean = val[2:] if val.startswith('*.') else val
            if val.startswith('*.'): expected_type = MatchType.WILDCARD
            norm = self._normalize_domain(clean)
            if norm: dom.append(DomainRule(val, expected_type, norm, is_excl))
        elif typ == 'ip_cidr':
            try:
                net = ipaddress.ip_network(val, strict=False)
                if net.version == 6 and not self._config.enable_ipv6: return
                ip.append(IPCIDRRule(net, val, is_excl))
            except ValueError:
                pass

    def _normalize_domain(self, d: str) -> Optional[str]:
        d = d.strip().lower().strip('.')
        if not d or len(d) > MAX_DOMAIN_LENGTH or ' ' in d: return None
        if not d.isascii():
            try: d = d.encode('idna').decode('ascii')
            except UnicodeError: return None
        if len(d) > MAX_DOMAIN_LENGTH: return None
        parts = d.split('.')
        if len(parts) > self._max_domain_depth: return None
        for part in parts:
            if not part or len(part) > 63 or not RE_DOMAIN_LABEL.match(part): return None
        return d


def create_session() -> requests.Session:
    s = requests.Session()
    retry = Retry(total=DEFAULT_RETRIES, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry, pool_connections=1, pool_maxsize=1)
    s.mount('http://', adapter)
    s.mount('https://', adapter)
    s.headers.update({"User-Agent": "StrictRuleMerger/9.0"})
    return s


def resolve_hostname(hostname: str, config: MergeConfig) -> list[str]:
    with _DNS_LOCK:
        if hostname in _DNS_CACHE:
            ts, ips = _DNS_CACHE[hostname]
            if time.time() - ts < 300:
                _DNS_CACHE.move_to_end(hostname)
                return ips
            del _DNS_CACHE[hostname]

        if hostname in _DNS_PENDING:
            event = _DNS_PENDING[hostname]
            wait_for_event = True
        else:
            event = threading.Event()
            _DNS_PENDING[hostname] = event
            wait_for_event = False

    if wait_for_event:
        event.wait(timeout=10)
        with _DNS_LOCK: return _DNS_CACHE.get(hostname, (0, []))[1]

    ips = []
    try:
        results = socket.getaddrinfo(hostname, None)
        ips_set = set()
        for res in results:
            ip_str = res[4][0].split('%')[0]
            if ip_str in ips_set: continue
            try:
                ip = ipaddress.ip_address(ip_str)
                if ip.is_link_local or (not config.enable_ipv6 and ip.version == 6): continue
                if not config.url_allow_private_ips and (ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast): continue
                ips_set.add(ip_str)
                ips.append(ip_str)
            except ValueError: continue
    except Exception: 
        pass
    finally:
        with _DNS_LOCK:
            _DNS_CACHE[hostname] = (time.time(), ips)
            _DNS_CACHE.move_to_end(hostname)
            if len(_DNS_CACHE) > MAX_DNS_CACHE: _DNS_CACHE.popitem(last=False)
            _DNS_PENDING.pop(hostname, None)
            event.set()
    return ips


def download_file_stream(url: str, config: MergeConfig, temp_dir: Path) -> tuple[Optional[bytes], Optional[Path], Optional[str]]:
    redirect_count = 0
    current_url = url
    visited = set()
    tmp_path = None
    success = False

    try:
        while redirect_count < 5:
            if current_url in visited: return None, None, "redirect_loop"
            visited.add(current_url)

            allowed, reason = config.is_url_allowed(current_url)
            if not allowed: return None, None, "url_not_allowed"

            parsed_current = urlparse(current_url)
            current_hostname = parsed_current.hostname
            if not current_hostname: return None, None, "no_hostname"

            current_public_ips = resolve_hostname(current_hostname, config)
            if not current_public_ips: return None, None, "no_public_ips"

            last_err = None
            tmp_path = None
            redirected_this_loop = False

            for attempt_ip in current_public_ips:
                _dns_context.forced_host = current_hostname
                _dns_context.forced_ip = attempt_ip

                try:
                    with create_session() as session:
                        with session.get(
                            current_url, stream=True,
                            timeout=(config.download_timeout_connect, config.download_timeout_read),
                            verify=config.verify_ssl, allow_redirects=False
                        ) as resp:
                            if resp.status_code in (301, 302, 303, 307, 308):
                                location = resp.headers.get('Location')
                                if not location: return None, None, "redirect_without_location"
                                current_url = urljoin(current_url, location)
                                redirect_count += 1
                                redirected_this_loop = True
                                break

                            resp.raise_for_status()
                            if 'html' in resp.headers.get('content-type', '').lower() and not url.endswith('.html'):
                                return None, None, "html_content"

                            buffer = bytearray()
                            use_file = False
                            total = html_check_count = 0

                            for chunk in resp.iter_content(128 * 1024):
                                if not chunk: continue
                                if html_check_count < HTML_CHECK_THRESHOLD:
                                    if RE_HTML_STRICT.search(chunk): return None, None, "html_detected"
                                    html_check_count += 1
                                total += len(chunk)
                                if total > config.max_download_size: return None, None, "size_exceeded"

                                if not use_file:
                                    buffer.extend(chunk)
                                    if total > SMALL_FILE_THRESHOLD:
                                        use_file = True
                                        fd, path_str = tempfile.mkstemp(suffix='.tmp', dir=str(temp_dir))
                                        tmp_path = Path(path_str)
                                        try:
                                            tmp_file = os.fdopen(fd, 'wb')
                                        except Exception:
                                            os.close(fd)
                                            raise
                                        with tmp_file:
                                            tmp_file.write(buffer)
                                            buffer.clear()
                                            for subsequent_chunk in resp.iter_content(128 * 1024):
                                                if not subsequent_chunk: continue
                                                total += len(subsequent_chunk)
                                                if total > config.max_download_size: return None, None, "size_exceeded"
                                                tmp_file.write(subsequent_chunk)
                                        break

                            if total == 0: return None, None, "empty_content"
                            success = True
                            return (None, tmp_path, None) if use_file else (bytes(buffer), None, None)

                except requests.RequestException as e:
                    if tmp_path and tmp_path.exists(): tmp_path.unlink(missing_ok=True)
                    tmp_path = None
                    last_err = e
                finally:
                    _dns_context.forced_host = None
                    _dns_context.forced_ip = None

            if redirected_this_loop: continue

            if isinstance(last_err, requests.HTTPError):
                status = last_err.response.status_code if last_err.response else 0
                if 500 <= status < 600: raise TransientError(f"HTTP 5xx error for {url}") from last_err
                elif status == 429: raise TransientError(f"HTTP 429 Too Many Requests for {url}") from last_err
                elif 400 <= status < 500: return None, None, f"http_error_{status}"
                return None, None, f"http_error_{status}" if status else "http_error_unknown"
            elif isinstance(last_err, (requests.Timeout, requests.ConnectionError)):
                raise TransientError("connection error") from last_err
            elif last_err:
                return None, None, f"request_error: {type(last_err).__name__}"

            return None, None, "no_valid_ips"

        return None, None, "too_many_redirects"
    finally:
        if not success and tmp_path and tmp_path.exists():
            tmp_path.unlink(missing_ok=True)


def download_sources(task_cfg: MergeConfig, sources_conf: list[Union[str, dict[str, Any]]], temp_dir: Path, cache: Optional[WALBackend]) -> tuple[list[ParsedRuleSet], list[str]]:
    parser = RuleParser(task_cfg)
    sources: list[ParsedRuleSet] = []
    parse_errors: list[str] = []
    batch_updates: dict[str, Any] = {}

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=task_cfg.max_concurrent_downloads)
    future_to_url = {}
    interrupted = False
    try:
        for src_conf in sources_conf:
            url = src_conf if isinstance(src_conf, str) else src_conf.get('url')
            if not url: continue
            weight = 1.0 if isinstance(src_conf, str) else float(src_conf.get('weight', 1.0))
            future = executor.submit(_download_single_source, task_cfg, url, weight, temp_dir, cache, parser)
            future_to_url[future] = url

        for future in concurrent.futures.as_completed(future_to_url):
            url = future_to_url[future]
            try:
                ps, error, cache_update = future.result()
                if ps:
                    sources.append(ps)
                    if cache_update: batch_updates.update(cache_update)
                elif error:
                    parse_errors.append(f"{url}: {error}")
            except Exception as e:
                parse_errors.append(f"{url}: unexpected error: {str(e)[:50]}")
    except (KeyboardInterrupt, SystemExit):
        interrupted = True
        for fu in future_to_url: fu.cancel()
        executor.shutdown(wait=False, cancel_futures=True)
        raise
    finally:
        if not interrupted: executor.shutdown(wait=True)

    if cache and batch_updates:
        if not cache.put_batch(batch_updates):
            logger.warning("Failed to write cache updates")

    return sources, parse_errors


def _download_single_source(task_cfg: MergeConfig, url: str, weight: float, temp_dir: Path, cache: Optional[WALBackend], parser: RuleParser) -> tuple[Optional[ParsedRuleSet], Optional[str], Optional[dict[str, Any]]]:
    cache_key = f"parsed:{CACHE_VERSION}:{url}"
    if cache:
        loaded = cache.get(cache_key)
        if isinstance(loaded, dict):
            try:
                dom_rules = tuple(DomainRule(d['pattern'], MatchType(d['match_type']), d['normalized'], d['is_exclusion'], d.get('specificity_score', 0)) for d in loaded.get('domain_rules', []))
                ip_rules = tuple(IPCIDRRule(ipaddress.ip_network(d['network']), d['original_str'], d['is_exclusion']) for d in loaded.get('ip_rules', []))
                cached_ps = ParsedRuleSet(loaded['url'], loaded['weight'], dom_rules, ip_rules, loaded['timestamp'], loaded['content_hash'])
                if time.time() - cached_ps.timestamp < task_cfg.max_source_age_days * 86400:
                    return ParsedRuleSet(cached_ps.url, weight, cached_ps.domain_rules, cached_ps.ip_rules, cached_ps.timestamp, cached_ps.content_hash), None, None
            except Exception as e:
                logger.warning(f"Failed to load cached source {url}: {e}")

    src_retry = 0
    while src_retry <= MAX_DOWNLOAD_RETRIES:
        tmp_path = None
        try:
            data, tmp_path, err = download_file_stream(url, task_cfg, temp_dir)
            if data is None and tmp_path is None:
                if err: return None, err, None
                break

            try:
                if data is not None: ps = parser.parse(data, url, weight)
                elif tmp_path:
                    ps = parser.parse(tmp_path, url, weight)
                else: continue

                if ps.domain_rules or ps.ip_rules:
                    to_store = None
                    if cache:
                        to_store = {cache_key: {
                            'url': ps.url, 'weight': ps.weight,
                            'domain_rules': [{'pattern': r.pattern, 'match_type': r.match_type.value, 'normalized': r.normalized, 'is_exclusion': r.is_exclusion, 'specificity_score': r.specificity_score} for r in ps.domain_rules],
                            'ip_rules': [{'network': str(r.network), 'original_str': r.original_str, 'is_exclusion': r.is_exclusion} for r in ps.ip_rules],
                            'timestamp': ps.timestamp, 'content_hash': ps.content_hash
                        }}
                    return ps, None, to_store
                return None, "no valid rules", None
            except Exception as e:
                return None, str(e)[:50], None
        except TransientError:
            src_retry += 1
            if src_retry <= MAX_DOWNLOAD_RETRIES:
                time.sleep(min(2 ** src_retry, MAX_BACKOFF_SECONDS))
                continue
            return None, f"transient error after {MAX_DOWNLOAD_RETRIES} retries", None
        finally:
            if tmp_path and tmp_path.exists():
                tmp_path.unlink(missing_ok=True)

    return None, f"download failed after {MAX_DOWNLOAD_RETRIES + 1} attempts", None


class FlatDomainMerger:
    __slots__ = ('rules',)

    def __init__(self) -> None:
        self.rules: dict[tuple[str, MatchType, bool], tuple[float, DomainRule, int]] = {}

    def add_rule(self, rule: DomainRule, weight: float, config: MergeConfig, rule_index: int) -> None:
        key = (rule.normalized, rule.match_type, rule.is_exclusion)
        existing = self.rules.get(key)
        if existing:
            existing_weight, existing_rule, existing_idx = existing
            if weight > existing_weight or (weight == existing_weight and config.conflict_resolution == 'specificity' and rule.specificity_score > existing_rule.specificity_score):
                self.rules[key] = (weight, rule, rule_index)
        else:
            self.rules[key] = (weight, rule, rule_index)

    def collect_rules(self) -> tuple[list[tuple[DomainRule, float]], list[tuple[DomainRule, float]]]:
        allow, deny = [], []
        for (_, _, is_excl), (weight, rule, _) in self.rules.items():
            (deny if is_excl else allow).append((rule, weight))
        allow.sort(key=lambda x: (-x[1], -x[0].specificity_score, x[0].normalized, int(x[0].is_exclusion)))
        deny.sort(key=lambda x: (-x[1], -x[0].specificity_score, x[0].normalized, int(x[0].is_exclusion)))
        return allow, deny


class WeightedCIDRMerger:
    __slots__ = ('config', 'groups')

    def __init__(self, config: MergeConfig) -> None:
        self.config = config
        self.groups: dict[float, list[tuple[IPNetworkType, bool]]] = defaultdict(list)

    def add_rule(self, net: IPNetworkType, is_allow: bool, weight: float) -> None:
        self.groups[weight].append((net, is_allow))

    def get_result(self) -> tuple[list[tuple[IPCIDRRule, float]], list[tuple[IPCIDRRule, float]]]:
        weights = sorted(self.groups.keys(), reverse=True)
        final_allow_dict: dict[IPNetworkType, float] = {}
        final_deny_dict: dict[IPNetworkType, float] = {}

        for w in weights:
            allow_this, deny_this = [], []
            for net, is_allow in self.groups[w]:
                (allow_this if is_allow else deny_this).append(net)

            temp_allow_dict, temp_deny_dict = {}, {}

            if deny_this:
                try:
                    for net in SweepLineCIDRManager.subtract(deny_this, itertools.chain(final_allow_dict.keys(), final_deny_dict.keys()), self.config.max_cidr_fragmentation, self.config.enable_cidr_approximation, self.config.cidr_approximation_max_loss_rate, self.config.strict_zero_loss):
                        if net not in temp_deny_dict: temp_deny_dict[net] = w
                except CIDRFragmentationError as e:
                    if self.config.strict_zero_loss: raise
                    if self.config.enable_cidr_approximation and e.cidrs:
                        for net in SweepLineCIDRManager.approximate_collapse(e.cidrs, self.config.max_cidr_fragmentation)[0]:
                            if net not in temp_deny_dict: temp_deny_dict[net] = w

            if allow_this:
                try:
                    for net in SweepLineCIDRManager.subtract(allow_this, itertools.chain(final_allow_dict.keys(), final_deny_dict.keys(), temp_deny_dict.keys()), self.config.max_cidr_fragmentation, self.config.enable_cidr_approximation, self.config.cidr_approximation_max_loss_rate, self.config.strict_zero_loss):
                        if net not in temp_allow_dict: temp_allow_dict[net] = w
                except CIDRFragmentationError as e:
                    if self.config.strict_zero_loss: raise
                    if self.config.enable_cidr_approximation and e.cidrs:
                        for net in SweepLineCIDRManager.approximate_collapse(e.cidrs, self.config.max_cidr_fragmentation)[0]:
                            if net not in temp_allow_dict: temp_allow_dict[net] = w

            final_deny_dict.update({k: v for k, v in temp_deny_dict.items() if k not in final_deny_dict})
            final_allow_dict.update({k: v for k, v in temp_allow_dict.items() if k not in final_allow_dict})

        def _group_by_weight(rule_dict: dict[IPNetworkType, float], is_deny: bool) -> list[tuple[IPCIDRRule, float]]:
            by_weight: dict[float, list[IPNetworkType]] = defaultdict(list)
            for net, w in rule_dict.items(): by_weight[w].append(net)
            results = []
            for w in sorted(by_weight.keys(), reverse=True):
                if nets := by_weight[w]:
                    for cnet in ipaddress.collapse_addresses(nets):
                        results.append((IPCIDRRule(cnet, str(cnet), is_deny), w))
            return results

        allow_results = _group_by_weight(final_allow_dict, False)
        deny_results = _group_by_weight(final_deny_dict, True)
        allow_results.sort(key=lambda x: (-x[1], x[0].version, -x[0].prefixlen, x[0].start_int))
        deny_results.sort(key=lambda x: (-x[1], x[0].version, -x[0].prefixlen, x[0].start_int))
        return allow_results, deny_results


def merge_ip_rules(parsed_sets: list[ParsedRuleSet], config: MergeConfig) -> tuple[list[tuple[IPCIDRRule, float]], list[tuple[IPCIDRRule, float]]]:
    merger = WeightedCIDRMerger(config)
    for src in sorted(parsed_sets, key=lambda x: -x.weight):
        for r in src.ip_rules: merger.add_rule(r.network, not r.is_exclusion, src.weight)
    return merger.get_result()


def merge_domains(parsed_sets: list[ParsedRuleSet], config: MergeConfig) -> tuple[list[tuple[DomainRule, float]], list[tuple[DomainRule, float]]]:
    merger = FlatDomainMerger()
    idx = 0
    for src in sorted(parsed_sets, key=lambda x: -x.weight):
        for r in src.domain_rules:
            merger.add_rule(r, src.weight, config, idx)
            idx += 1
    return merger.collect_rules()


def _verify_rule_group(
    group_name: str, bdd_verifier: Optional[BDDRuleVerifier], smt_verifier: Optional[SMTVerifier],
    coverage_checker: CoverageChecker, p_dom_allow: list[DomainRule], p_dom_deny: list[DomainRule], c_dom: list[DomainRule],
    p_ip_allow: list[IPCIDRRule], p_ip_deny: list[IPCIDRRule], c_ip: list[IPCIDRRule], parent_digest: int,
    source_url: str, is_deny: bool, results: dict[str, Any]
) -> tuple[bool, float]:

    if not c_dom and not c_ip: return True, 1.0

    if bdd_verifier and not c_dom:
        try:
            ok, conf = bdd_verifier.verify_deny_subset(p_ip_deny, c_ip) if is_deny else bdd_verifier.verify_subset_strict(p_ip_allow, p_ip_deny, c_ip)
            # 直接使用 group_name，避免叠字冗余
            if not ok: results['issues'].append({'source': source_url, 'verifier': 'BDD', 'type': f"{group_name}_not_subset", 'confidence': conf})
            return ok, conf
        except Exception as e:
            logger.debug(f"BDD {group_name} verification failed, falling back to SMT: {e}")

    if smt_verifier and smt_verifier.enabled:
        try:
            if is_deny: ok, conf, msg = smt_verifier.verify_deny_subset(p_dom_deny, c_dom, p_ip_deny, c_ip, parent_digest)
            else: ok, conf, msg = smt_verifier.verify_allow_subset(p_dom_allow, p_dom_deny, c_dom, p_ip_allow, p_ip_deny, c_ip, parent_digest)
            if not ok: results['issues'].append({'source': source_url, 'verifier': 'SMT', 'type': f"{group_name}_not_subset", 'confidence': conf, 'message': msg})
            return ok, conf
        except Exception as e:
            results['issues'].append({'source': source_url, 'verifier': 'SMT', 'type': 'error', 'message': f"{group_name} verification error: {str(e)[:100]}"})
            return False, 0.0

    ok = True
    conf = coverage_checker.calculate(itertools.chain(c_dom, c_ip))
    if conf < 1.0:
        ok = False
        results['issues'].append({'source': source_url, 'verifier': 'none', 'type': f"{group_name}_not_covered", 'confidence': conf})
    return ok, conf


def run_verifications(
    parsed_sets: list[ParsedRuleSet], p_dom_allow: list[DomainRule], p_dom_deny: list[DomainRule],
    p_ip_allow: list[IPCIDRRule], p_ip_deny: list[IPCIDRRule], bdd_verifier: Optional[BDDRuleVerifier], 
    smt_verifier: Optional[SMTVerifier], config: MergeConfig
) -> dict[str, Any]:
    results: dict[str, Any] = {
        'bdd_enabled': bool(bdd_verifier and config.enable_bdd_verification),
        'smt_enabled': bool(smt_verifier and smt_verifier.enabled and config.enable_smt_verification),
        'issues': [], 'stats': {}
    }

    parent_digest = rules_digest(itertools.chain(p_dom_allow, p_ip_allow, p_dom_deny, p_ip_deny))
    coverage_checker = CoverageChecker(itertools.chain(p_dom_allow, p_ip_allow, p_dom_deny, p_ip_deny))
    total_sources, passed, coverages = 0, 0, []

    for src in sorted(parsed_sets, key=lambda x: -x.weight)[:config.max_verification_sources]:
        c_dom_allow = [r for r in src.domain_rules if not r.is_exclusion]
        c_ip_allow = [r for r in src.ip_rules if not r.is_exclusion]
        c_dom_deny = [r for r in src.domain_rules if r.is_exclusion]
        c_ip_deny = [r for r in src.ip_rules if r.is_exclusion]

        if not (c_dom_allow or c_ip_allow or c_dom_deny or c_ip_deny): continue
        total_sources += 1
        src_passed, cov_components = True, []

        def check(name: str, is_deny: bool, c_d: list[DomainRule], c_i: list[IPCIDRRule]) -> None:
            nonlocal src_passed
            if c_d or c_i:
                ok, conf = _verify_rule_group(name, bdd_verifier, smt_verifier, coverage_checker,
                                               p_dom_allow, p_dom_deny, c_d,
                                               p_ip_allow, p_ip_deny, c_i,
                                               parent_digest, src.url, is_deny, results)
                src_passed = src_passed and ok
                cov_components.append(conf)

        check('domain_allow', False, c_dom_allow, [])
        check('ip_allow', False, [], c_ip_allow)
        check('domain_deny', True, c_dom_deny, [])
        check('ip_deny', True, [], c_ip_deny)

        if src_passed: passed += 1
        coverages.append(min(cov_components) if cov_components else 1.0)

    if total_sources > 0:
        results['stats'] = {
            'total_sources': total_sources, 'passed': passed,
            'pass_rate': passed / total_sources, 'avg_coverage': sum(coverages) / len(coverages)
        }
    return results


def write_output(name: str, sorted_rules: list[tuple[RuleType, float]], out_path: Path, config: MergeConfig) -> tuple[str, str]:
    is_surge = config.output_format == 'surge'
    is_clash = config.output_format == 'clash'
    out_srs = None

    if is_surge or is_clash:
        prefix = "  - " if is_clash else ""
        with open(out_path, 'w', encoding='utf-8') as f:
            if is_clash: f.write("payload:\n")
            for rule, _ in sorted_rules:
                policy = config.deny_policy if rule.is_exclusion else config.allow_policy
                if isinstance(rule, DomainRule):
                    if rule.match_type == MatchType.EXACT: typ, val = 'DOMAIN', rule.normalized
                    elif rule.match_type == MatchType.SUFFIX: typ, val = 'DOMAIN-SUFFIX', rule.normalized
                    elif rule.match_type == MatchType.WILDCARD: typ, val = 'DOMAIN-WILDCARD', f"*.{rule.normalized}"
                    else: continue
                else:
                    typ, val = ('IP-CIDR6' if rule.version == 6 else 'IP-CIDR'), rule.original_str
                f.write(f"{prefix}{typ},{val}{',' + policy if policy else ''}\n")
    else:
        json_rules = []
        for rule, _ in sorted_rules:
            if isinstance(rule, DomainRule):
                if rule.match_type == MatchType.EXACT: typ, val = 'domain', rule.normalized
                elif rule.match_type in (MatchType.SUFFIX, MatchType.WILDCARD): typ, val = 'domain_suffix', rule.normalized
                else: continue
            else:
                typ, val = 'ip_cidr', rule.original_str

            entry: dict[str, Any] = {typ: val}
            if rule.is_exclusion: entry['invert'] = True
            json_rules.append(entry)

        final_data = {"version": 1, "rules": json_rules}

        if USE_ORJSON:
            with open(out_path, 'wb') as f_bin:
                f_bin.write(orjson.dumps(final_data, option=orjson.OPT_INDENT_2 | getattr(orjson, 'OPT_SORT_KEYS', 0)))
        else:
            with open(out_path, 'w', encoding='utf-8') as f_txt:
                json.dump(final_data, f_txt, indent=2, ensure_ascii=False, sort_keys=True)

    if config.core_bin_path and config.core_bin_path.strip():
        core_path = Path(config.core_bin_path).expanduser()
        out_srs = out_path.with_suffix('.srs')
        if core_path.exists() and os.access(str(core_path), os.X_OK):
            try:
                proc = subprocess.run(
                    [str(core_path), "rule-set", "compile", "--output", str(out_srs), str(out_path)],
                    capture_output=True, text=True, timeout=config.compile_timeout_seconds
                )
                if proc.returncode != 0: raise RuntimeError(f"Compile failed: {proc.stderr}")
            except subprocess.TimeoutExpired:
                raise RuntimeError("Compile timeout")
            except Exception as e:
                raise RuntimeError(f"Compile error: {e}")

    try:
        target_path = out_srs if out_srs and out_srs.exists() else out_path
        sz_val = f"{target_path.stat().st_size / 1024:.1f}KB"
    except OSError:
        sz_val = "0KB"
    return sz_val, f"Merged {len(sorted_rules)} rules"

def _sort_rules(item: tuple[RuleType, float]) -> tuple[float, int, int, Union[str, int], int]:
    rule, weight = item
    if isinstance(rule, DomainRule):
        return (-weight, 0, -rule.specificity_score, rule.normalized, int(rule.is_exclusion))
    return (-weight, 1, rule.version, -rule.prefixlen, rule.start_int)

def worker(task: dict[str, Any], global_config: MergeConfig, smt_verifier: Optional[SMTVerifier] = None) -> tuple[str, str, str, str]:
    name = task.get('name', '')
    if not name or not RE_TASK_NAME.match(name) or len(name) > MAX_TASK_NAME_LENGTH:
        raise ValueError(f"Invalid task name: {name}")

    temp_dir: Optional[Path] = None
    bdd_verifier: Optional[BDDRuleVerifier] = None
    cache: Optional[WALBackend] = None

    try:
        temp_dir = Path(tempfile.mkdtemp(prefix=f"sb_merge_{name}_"))
        task_cfg = MergeConfig.from_dict(task.get('config', {}), global_config)

        if task_cfg.core_bin_path and not task_cfg.validate_core_path():
            raise SecurityViolationError(f"Core path validation failed: {task_cfg.core_bin_path}")
        if task_cfg.core_bin_path and task_cfg.output_format != 'json':
            raise SecurityViolationError("core compilation requires output_format='json'")

        out_path = task_cfg.output_dir / f"merged-{task_cfg.output_format}" / f"{name}.{'list' if task_cfg.output_format == 'surge' else 'yaml' if task_cfg.output_format == 'clash' else 'json'}"
        out_path.parent.mkdir(parents=True, exist_ok=True)

        if task_cfg.enable_cache:
            cache_dir = Path.cwd() / ".cache" / "rule_merger" / name
            try:
                cache_dir.mkdir(parents=True, exist_ok=True)
                cache = WALBackend(cache_dir / "source_cache", task_cfg)
            except OSError as e:
                logger.warning(f"Failed to create cache directory {cache_dir}: {e}, caching disabled")

        sources, parse_errors = download_sources(task_cfg, task.get('sources', []), temp_dir, cache)

        if not sources: return (name, "⚠️", f"No valid sources ({len(parse_errors)} errors)" if parse_errors else "No valid sources", "0KB")
        if parse_errors: logger.warning(f"[{name}] Parse errors: {'; '.join(parse_errors[:3])}")

        allow_rules_weights, deny_rules_weights = merge_domains(sources, task_cfg)
        allow_ip_weights, deny_ip_weights = merge_ip_rules(sources, task_cfg)

        p_dom_allow = [r for r, _ in allow_rules_weights]
        p_dom_deny = [r for r, _ in deny_rules_weights]
        p_ip_allow = [r for r, _ in allow_ip_weights]
        p_ip_deny = [r for r, _ in deny_ip_weights]

        all_rules = list(itertools.chain(allow_rules_weights, deny_rules_weights, allow_ip_weights, deny_ip_weights))
        all_rules.sort(key=_sort_rules)

        if task_cfg.enable_bdd_verification:
            engine = BDDEngine(node_cache_max=task_cfg.bdd_node_limit, op_cache_max=task_cfg.bdd_lru_cache_size)
            bdd_verifier = BDDRuleVerifier(engine, max_cache_size=task_cfg.max_bdd_var_cache_size)

        verify_results = run_verifications(sources, p_dom_allow, p_dom_deny, p_ip_allow, p_ip_deny, bdd_verifier, smt_verifier, task_cfg)
        stats, issues = verify_results.get('stats', {}), verify_results.get('issues', [])
        if stats: logger.info(f"[{name}] Verification: {stats.get('passed', 0)}/{stats.get('total_sources', 0)} passed, avg coverage {stats.get('avg_coverage', 0):.2%}")
        for issue in issues: logger.warning(f"[{name}] Verification issue: {issue}")

        sz, summary = write_output(name, all_rules, out_path, task_cfg)
        return (name, "⚠️" if issues else "✅", summary, sz)

    except (SecurityViolationError, KeyboardInterrupt, SystemExit):
        raise
    except Exception as e:
        logger.exception(f"[{name}] Error")
        return (name, "❌", str(e)[:100], "0KB")
    finally:
        if bdd_verifier:
            try: bdd_verifier.clear()
            except Exception: pass
        if smt_verifier:
            try: smt_verifier.clear_thread_state()
            except Exception: pass
        if temp_dir and temp_dir.exists():
            shutil.rmtree(temp_dir, ignore_errors=True)

def _check_module_version(mod_name: str, module: Any, min_ver: tuple[int, int, int]) -> None:
    if module is None: return
    try:
        if mod_name == "z3": v_str = ".".join(map(str, module.get_version()[:3]))
        else:
            v_str = getattr(module, '__version__', getattr(module, 'version', '0.0.0'))
            if isinstance(v_str, tuple): v_str = ".".join(map(str, v_str))
        if parse_version(v_str) < min_ver:
            logger.warning(f"{mod_name} version < {'.'.join(map(str, min_ver))} may have compatibility issues")
    except Exception as e:
        logger.warning(f"Failed to check version for {mod_name}: {e}")

_SMT_WARNING_SHOWN = False

def main() -> int:
    sys.setrecursionlimit(2000)

    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    _check_module_version("orjson", orjson if USE_ORJSON else None, (3, 0, 0))
    _check_module_version("msgpack", msgpack if USE_MSGPACK else None, (1, 0, 0))
    _check_module_version("z3", z3 if HAS_Z3 else None, (4, 8, 0))
    _check_module_version("requests", requests, (2, 25, 0))

    logger.info("Rule Merger v9.0 starting")
    logger.info("Verification capabilities: BDD and SMT both support domain and IP rules.")
    if not USE_ORJSON: logger.info("orjson not available, using standard json (slower)")
    if not USE_MSGPACK: logger.info("msgpack not available, using json for cache (slower)")

    cfg, cfg_path, tasks = DEFAULT_CONFIG, Path(DEFAULT_CONFIG.config_file), []
    if not cfg_path.exists():
        logger.warning(f"Config file not found: {cfg_path}, using default configuration (no tasks)")
    else:
        try:
            with open(cfg_path, 'rb') as f:
                data = orjson.loads(f.read()) if USE_ORJSON else json.loads(f.read().decode('utf-8'))
            if not isinstance(data, dict):
                logger.error(f"Config file is not a JSON object: {type(data).__name__}, using default configuration")
                data = {}
            cfg = MergeConfig.from_dict(data.get('global', {}), cfg)
            tasks = data.get('merge_tasks', [])
        except Exception as e:
            logger.error(f"Failed to load config: {e}, using default configuration")

    if not tasks:
        logger.warning("No merge tasks in config, exiting")
        return 0

    task_names = [t.get('name') for t in tasks if isinstance(t, dict)]
    if len(task_names) != len(set(task_names)):
        logger.error("Duplicate task names found in configuration. Task names must be unique.")
        return 1

    global _SMT_WARNING_SHOWN
    if not HAS_Z3 and cfg.enable_smt_verification:
        logger.warning("z3 not installed, SMT verification disabled")
    elif cfg.enable_smt_verification and HAS_Z3 and not _SMT_WARNING_SHOWN:
        logger.warning("SMT verification with domain strings can be extremely slow. Consider disabling or adjusting smt_progressive_timeout.")
        _SMT_WARNING_SHOWN = True

    smt_verifier = SMTVerifier(cfg) if (cfg.enable_smt_verification and HAS_Z3) else None

    executor = None
    futures = []
    interrupted = False
    try:
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=min(cfg.max_workers, len(tasks)), thread_name_prefix="Worker")
        futures = [executor.submit(worker, t, cfg, smt_verifier) for t in tasks]
        for f in concurrent.futures.as_completed(futures):
            try:
                r = f.result()
                logger.info(f"[{r[0]}] {r[1]} {r[2]} ({r[3]})")
            except Exception as e:
                logger.error(f"Task error: {e}", exc_info=True)
    except KeyboardInterrupt:
        interrupted = True
        logger.info("Interrupted")
        for fu in futures: fu.cancel()
        if executor: executor.shutdown(wait=False, cancel_futures=True)
        return 130
    finally:
        if executor and not interrupted:
            executor.shutdown(wait=True)

    return 0

if __name__ == '__main__':
    sys.exit(main())
