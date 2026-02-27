#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import concurrent.futures
import hashlib
import ipaddress
import json
import logging
import math
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
import bisect
import zlib
import uuid
from collections import defaultdict, Counter, OrderedDict
from enum import IntEnum
from pathlib import Path
from typing import Any, Iterable, Optional, Union, List, Tuple, Dict
from urllib.parse import urljoin, urlparse

import requests
import urllib3
import urllib3.util.connection
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

if sys.version_info < (3, 9): sys.exit("Error: Python 3.9+ is required")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

_orig_create_connection = urllib3.util.connection.create_connection
_dns_context = threading.local()

def _patched_create_connection(address: tuple[str, int], *args: Any, **kwargs: Any) -> socket.socket:
    host, port = address
    forced_ip = getattr(_dns_context, 'forced_ip', None)
    forced_host = getattr(_dns_context, 'forced_host', None)
    if forced_ip and forced_host == host: address = (forced_ip, port)
    return _orig_create_connection(address, *args, **kwargs)

urllib3.util.connection.create_connection = _patched_create_connection
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try: import orjson; USE_ORJSON = True
except ImportError: USE_ORJSON = False
try: import msgpack; USE_MSGPACK = True
except ImportError: USE_MSGPACK = False

CACHE_VERSION = 317
TARGET_FORMAT_VERSION = 4
MAX_DOWNLOAD_RETRIES = 4
MAX_DNS_CACHE = 1024

RE_HASH_LIKE = re.compile(r'\b[a-f0-9]{32,64}\b', re.IGNORECASE)
RE_DOMAIN_LABEL = re.compile(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$', re.IGNORECASE)
RE_TASK_NAME = re.compile(r'^[a-zA-Z0-9_-]+$')
RE_HTML_STRICT = re.compile(rb'(?:^[\s]*<(?:!DOCTYPE\s+html|html|head|body))', re.IGNORECASE | re.MULTILINE)
RE_IPV4_MAPPED_IPV6 = re.compile(r'^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:/(\d+))?$', re.IGNORECASE)

_DNS_CACHE: OrderedDict[str, Tuple[float, List[str]]] = OrderedDict()
_DNS_PENDING: Dict[str, threading.Event] = {}
_DNS_LOCK = threading.Lock()

class TransientError(Exception): pass
class SizeLimitError(Exception): pass
class CIDRFragmentationError(Exception): pass

class MatchType(IntEnum):
    EXACT = 1; SUFFIX = 2; WILDCARD = 3; KEYWORD = 4; REGEX = 5

class EntropyLevel(IntEnum):
    SAFE = 1; SUSPICIOUS = 2; DGA_CONFIRMED = 3

class EntropyAssessor:
    @staticmethod
    def assess(domain: str) -> EntropyLevel:
        length = len(domain)
        if length < 12: return EntropyLevel.SAFE
        if RE_HASH_LIKE.search(domain): return EntropyLevel.DGA_CONFIRMED
        parts = domain.split('.')
        if len(parts) == 1 and len(parts[0]) < 2: return EntropyLevel.DGA_CONFIRMED
        
        max_ent, max_dig, min_vow = 0.0, 0.0, 1.0
        vowels = set('aeiou')
        for p in parts:
            p_len = len(p)
            if p_len < 8: continue
            freq = Counter(p)
            ent = -sum((c / p_len) * math.log2(c / p_len) for c in freq.values())
            n_ent = ent / math.log2(len(freq)) if len(freq) > 1 else 0
            max_ent = max(max_ent, n_ent)
            max_dig = max(max_dig, sum(c.isdigit() for c in p) / p_len)
            min_vow = min(min_vow, sum(1 for c in p if c in vowels) / p_len)
            
        if max_ent > 0.95 and max_dig > 0.3 and min_vow < 0.1: return EntropyLevel.DGA_CONFIRMED
        if max_ent > 0.90 and max_dig > 0.2 and min_vow < 0.15: return EntropyLevel.SUSPICIOUS
        return EntropyLevel.SAFE

class MergeConfig:
    __slots__ = (
        'output_dir', 'core_bin_path', 'max_workers', 'max_concurrent_downloads',
        'download_timeout_connect', 'download_timeout_read', 'enable_ipv6',
        'compile_timeout_seconds', 'output_format', 'allow_policy', 'deny_policy',
        'max_domain_length', 'enable_cache', 'max_cache_entries', 'max_source_age_days',
        'max_download_size', 'enable_dga_filter', 'max_cidr_fragmentation', 'strict_cidr_limit',
        'critical_domains', 'canary_whitelist_ips', 'critical_ips', 
        'dangerous_ipv4_prefix', 'dangerous_ipv6_prefix', 'protect_private_ips',
        'same_tier_conflict_resolution', 'policy_merge_strategy', 'match_type_sort_order', 
        'generic_priority', 'keyword_chunk_size', 'frag_toxic_count', 'frag_toxic_ratio'
    )
    def __init__(self, **kwargs: Any):
        self.output_dir = Path(kwargs.get('output_dir', 'rules'))
        self.core_bin_path = kwargs.get('core_bin_path', shutil.which("sing-box") or os.getenv("SB_CORE_PATH", "./sb-core"))
        self.max_workers = int(kwargs.get('max_workers', 0)) or min(max(1, (os.cpu_count() or 4) * 2), 16)
        self.max_concurrent_downloads = max(10, int(kwargs.get('max_concurrent_downloads', 0)) or self.max_workers)
        self.download_timeout_connect = int(kwargs.get('download_timeout_connect', 15))
        self.download_timeout_read = int(kwargs.get('download_timeout_read', 60))
        self.enable_ipv6 = bool(kwargs.get('enable_ipv6', True))
        self.enable_cache = bool(kwargs.get('enable_cache', True))
        self.max_cache_entries = int(kwargs.get('max_cache_entries', 500))
        self.max_source_age_days = int(kwargs.get('max_source_age_days', 30))
        self.compile_timeout_seconds = int(kwargs.get('compile_timeout_seconds', 180))
        self.output_format = str(kwargs.get('output_format', 'json')).lower()
        self.allow_policy = str(kwargs.get('allow_policy', 'PROXY'))
        self.deny_policy = str(kwargs.get('deny_policy', 'REJECT'))
        self.max_domain_length = int(kwargs.get('max_domain_length', 253))
        self.max_download_size = int(kwargs.get('max_download_size', 150 * 1024 * 1024))
        self.enable_dga_filter = bool(kwargs.get('enable_dga_filter', True))
        
        self.same_tier_conflict_resolution = str(kwargs.get('same_tier_conflict_resolution', 'allow_wins')).lower()
        self.policy_merge_strategy = str(kwargs.get('policy_merge_strategy', 'reject_wins')).lower()
        self.match_type_sort_order = kwargs.get('match_type_sort_order', {MatchType.EXACT: 1, MatchType.SUFFIX: 2, MatchType.WILDCARD: 3, MatchType.KEYWORD: 4, MatchType.REGEX: 5})
        self.generic_priority = kwargs.get('generic_priority', {"process_name": 90, "user": 91, "package_name": 92, "geosite": 93})
        
        self.max_cidr_fragmentation = int(kwargs.get('max_cidr_fragmentation', 10000))
        self.strict_cidr_limit = bool(kwargs.get('strict_cidr_limit', True))
        
        self.keyword_chunk_size = int(kwargs.get('keyword_chunk_size', 500))
        self.frag_toxic_count = int(kwargs.get('frag_toxic_count', 5000))
        self.frag_toxic_ratio = float(kwargs.get('frag_toxic_ratio', 0.8))
        
        self.critical_domains = set(kwargs.get('critical_domains', ["com", "org", "net", "github.com", "apple.com", "google.com", "microsoft.com"]))
        self.canary_whitelist_ips = []
        for x in kwargs.get('canary_whitelist_ips', []):
            try: self.canary_whitelist_ips.append(ipaddress.ip_network(x))
            except ValueError: pass
            
        self.critical_ips = []
        for x in kwargs.get('critical_ips', ["1.1.1.1", "8.8.8.8", "2001:4860:4860::8888"]):
            try: self.critical_ips.append(ipaddress.ip_address(x))
            except ValueError: pass
        
        self.dangerous_ipv4_prefix = int(kwargs.get('dangerous_ipv4_prefix', 8))
        self.dangerous_ipv6_prefix = int(kwargs.get('dangerous_ipv6_prefix', 32))
        self.protect_private_ips = bool(kwargs.get('protect_private_ips', True))

        if self.output_format not in ('json', 'surge', 'clash'): self.output_format = 'json'

    @classmethod
    def from_dict(cls, d: Dict[str, Any], base: 'MergeConfig') -> 'MergeConfig':
        kwargs = {k: getattr(base, k) for k in cls.__slots__}
        for k, v in d.items():
            if k in cls.__slots__ and v is not None:
                kwargs[k] = Path(v) if k == 'output_dir' else v
        return cls(**kwargs)

    def validate_core_path(self) -> bool:
        if not self.core_bin_path: return False
        p = Path(self.core_bin_path).expanduser().absolute()
        if not p.is_file(): return False
        try: os.chmod(p, p.stat().st_mode | 0o111)
        except OSError: pass
        return os.access(str(p), os.X_OK)

class TaskContext:
    __slots__ = ('str_pool', '_lock')
    def __init__(self):
        self.str_pool = {}
        self._lock = threading.Lock()
        
    def intern(self, s: str) -> str:
        if not s: return ""
        res = self.str_pool.get(s)
        if res is not None: return res
        with self._lock: return self.str_pool.setdefault(s, s)

class DomainRule:
    __slots__ = ('match_type', 'normalized', 'is_exclusion', 'attrs', 'tier', 'specificity_score')
    def __init__(self, mt: MatchType, norm: str, is_excl: bool, attrs: int, tier: int):
        self.match_type, self.normalized, self.is_exclusion, self.attrs, self.tier = mt, norm, is_excl, attrs, tier
        score = self.normalized.count('.') * 10
        if mt == MatchType.EXACT: score += 8
        elif mt == MatchType.WILDCARD: score += 5
        elif mt == MatchType.SUFFIX: score += 3
        self.specificity_score = score

class IPCIDRRule:
    __slots__ = ('version', 'start_int', 'end_int', 'prefixlen', 'is_exclusion', 'attrs')
    def __init__(self, start: int, end: int, plen: int, ver: int, is_excl: bool, attrs: int):
        self.version, self.start_int, self.end_int, self.prefixlen, self.is_exclusion, self.attrs = ver, start, end, plen, is_excl, attrs

class GenericRule:
    __slots__ = ('type', 'val', 'is_exclusion', 'attrs', 'tier')
    def __init__(self, typ: str, val: str, is_excl: bool, attrs: int, tier: int):
        self.type, self.val, self.is_exclusion, self.attrs, self.tier = typ, val, is_excl, attrs, tier

class ParsedRuleSet:
    __slots__ = ('domain_rules', 'ip_rules', 'generic_rules', 'url', 'dga_count', 'rule_count')
    def __init__(self, d: List[DomainRule], i: List[IPCIDRRule], g: List[GenericRule], u: str = "", dga: int = 0):
        self.domain_rules, self.ip_rules, self.generic_rules = d, i, g
        self.url, self.dga_count = u, dga
        self.rule_count = len(d) + len(i) + len(g)

class AttributePool:
    def __init__(self, config: MergeConfig):
        self.str_to_id = {"": 0}
        self.id_to_str = {0: ""}
        self._counter = 1
        self._merge_cache = {}
        self.config = config
        self._lock = threading.Lock()

    def get_id(self, attr_str: str) -> int:
        if not attr_str: return 0
        res = self.str_to_id.get(attr_str)
        if res is not None: return res
        with self._lock:
            if attr_str not in self.str_to_id:
                self.str_to_id[attr_str] = self._counter
                self.id_to_str[self._counter] = attr_str
                self._counter += 1
            return self.str_to_id[attr_str]

    def _safe_list_dedup_merge(self, base_list: list, new_list: list) -> list:
        try:
            seen = set(base_list)
            res = list(base_list)
            for item in new_list:
                if item not in seen:
                    seen.add(item)
                    res.append(item)
            return res
        except TypeError:
            res = list(base_list)
            seen_json = {json.dumps(x, sort_keys=True) for x in res}
            for item in new_list:
                item_json = json.dumps(item, sort_keys=True)
                if item_json not in seen_json:
                    seen_json.add(item_json)
                    res.append(item)
            return res

    def _deep_merge(self, base: dict, nxt: dict):
        for k, v in nxt.items():
            if k in base:
                if isinstance(base[k], dict) and isinstance(v, dict):
                    self._deep_merge(base[k], v)
                elif isinstance(base[k], list) and isinstance(v, list):
                    base[k] = self._safe_list_dedup_merge(base[k], v)
                else:
                    if k.lower() == 'policy':
                        pol_b, pol_n = str(base[k]).upper(), str(v).upper()
                        if self.config.policy_merge_strategy == 'reject_wins' and pol_n == self.config.deny_policy.upper():
                            base[k] = v
                        elif self.config.policy_merge_strategy == 'allow_wins' and pol_n == self.config.allow_policy.upper():
                            base[k] = v
            else:
                base[k] = v

    def merge_ids_with_tier(self, items: List[Tuple[int, int]]) -> int:
        valid_items = [(t, aid) for t, aid in items if aid != 0]
        if not valid_items: return 0
        if len(valid_items) == 1: return valid_items[0][1]
        
        valid_items.sort(key=lambda x: x[0])
        cache_key = tuple(valid_items)
        
        with self._lock:
            if cache_key in self._merge_cache: return self._merge_cache[cache_key]

        merged = {}
        for i, (tier, aid) in enumerate(valid_items):
            j_str = self.id_to_str[aid]
            if not j_str: continue
            try:
                parsed = json.loads(j_str)
                if i == 0: merged = parsed.copy()
                else: self._deep_merge(merged, parsed)
            except Exception: pass
            
        final_str = json.dumps(merged, sort_keys=True, ensure_ascii=False) if merged else ""
        new_id = self.get_id(final_str)
        with self._lock: self._merge_cache[cache_key] = new_id
        return new_id

class CanaryDetector:
    @staticmethod
    def _is_dangerous_subnet(r: IPCIDRRule, config: MergeConfig) -> bool:
        if r.version == 4 and r.prefixlen <= config.dangerous_ipv4_prefix: return True
        if r.version == 6 and r.prefixlen <= config.dangerous_ipv6_prefix: return True
        return False

    @classmethod
    def is_poisoned(cls, dom_rules: List[DomainRule], ip_rules: List[IPCIDRRule], tier: int, attr_pool: AttributePool, config: MergeConfig) -> bool:
        if tier == 0: return False
        
        def _is_reject(is_excl, attrs_id):
            if is_excl: return True
            try:
                attrs_dict = json.loads(attr_pool.id_to_str[attrs_id])
                return attrs_dict.get('policy', '').upper() in ('REJECT', 'DROP')
            except Exception: return False

        for r in dom_rules:
            if not _is_reject(r.is_exclusion, r.attrs): continue
            for critical in config.critical_domains:
                if r.match_type == MatchType.EXACT and r.normalized == critical: return True
                elif r.match_type in (MatchType.SUFFIX, MatchType.WILDCARD):
                    if critical == r.normalized or critical.endswith('.' + r.normalized): return True
                elif r.match_type == MatchType.KEYWORD and r.normalized in critical: return True
                elif r.match_type == MatchType.REGEX:
                    try:
                        if re.search(r.normalized, critical, re.IGNORECASE): return True
                    except re.error: pass
            
        for r in ip_rules:
            if not _is_reject(r.is_exclusion, r.attrs): continue
            try:
                net_cls = ipaddress.IPv4Network if r.version == 4 else ipaddress.IPv6Network
                net = net_cls((r.start_int, r.prefixlen), strict=False)
            except ValueError: continue
            
            is_broad_danger = cls._is_dangerous_subnet(r, config)
            hits_critical_ip = any((ip.version == net.version and ip in net) for ip in config.critical_ips)
            
            if is_broad_danger or hits_critical_ip:
                if config.protect_private_ips and net.is_private: continue
                if any(wl.supernet_of(net) for wl in config.canary_whitelist_ips): continue
                logger.error(f"Canary Alert: Dangerous subnet or Critical IP blocked {net}")
                return True
        return False

class RuleAdjudicator:
    def __init__(self, config: MergeConfig, attr_pool: AttributePool):
        self.config = config
        self.attr_pool = attr_pool
        self.rule_observations = defaultdict(int)

    def observe(self, rule: Union[DomainRule, IPCIDRRule]):
        if isinstance(rule, DomainRule):
            k = ('D', rule.match_type.value, rule.normalized, rule.is_exclusion)
        else:
            k = ('I', rule.version, rule.start_int, rule.prefixlen, rule.is_exclusion)
        self.rule_observations[k] += 1

    def _assess_domain_risk(self, rule: DomainRule) -> float:
        norm = rule.normalized
        length = len(norm)
        risk = 0.0
        if rule.match_type in (MatchType.KEYWORD, MatchType.REGEX):
            if length <= 3: risk += 0.9
            elif length <= 5: risk += 0.6
            else: risk += 0.2
        elif rule.match_type in (MatchType.SUFFIX, MatchType.WILDCARD):
            if '.' not in norm: risk += 0.8
            else:
                parts = norm.split('.')
                if len(parts) == 2 and len(parts[0]) <= 3: risk += 0.5
        
        if self.config.enable_dga_filter:
            entropy_lvl = EntropyAssessor.assess(norm)
            if entropy_lvl == EntropyLevel.DGA_CONFIRMED: risk += 0.5
            elif entropy_lvl == EntropyLevel.SUSPICIOUS: risk += 0.2
        return min(risk, 1.0)

    def adjudicate(self, rule: Union[DomainRule, IPCIDRRule], tier: int, total_sources: int) -> bool:
        if tier <= 1: return True
        
        if isinstance(rule, DomainRule):
            k = ('D', rule.match_type.value, rule.normalized, rule.is_exclusion)
            risk = self._assess_domain_risk(rule)
        else:
            k = ('I', rule.version, rule.start_int, rule.prefixlen, rule.is_exclusion)
            max_p = 32 if rule.version == 4 else 128
            risk = math.pow((max_p - rule.prefixlen) / max_p, 2)
            
        observations = self.rule_observations[k]
        base_trust = 1.0 / (tier + 1)
        consensus_bonus = min(0.6, observations / max(1, total_sources))
        
        is_reject_behavior = rule.is_exclusion
        if not is_reject_behavior and hasattr(rule, 'attrs'):
            attr_str = self.attr_pool.id_to_str.get(rule.attrs, "").upper()
            if '"REJECT"' in attr_str or '"DROP"' in attr_str:
                is_reject_behavior = True
                
        if is_reject_behavior: risk *= 1.5
        
        return (base_trust + consensus_bonus - risk) > 0.0

def is_source_ip_fragmentation_toxic(ip_rules: List[IPCIDRRule], total_rules: int, config: MergeConfig) -> bool:
    if not ip_rules: return False
    
    v4_nets = [ipaddress.IPv4Network((r.start_int, r.prefixlen), strict=False) for r in ip_rules if r.version == 4]
    v6_nets = [ipaddress.IPv6Network((r.start_int, r.prefixlen), strict=False) for r in ip_rules if r.version == 6]
    
    frag_count = len(list(ipaddress.collapse_addresses(v4_nets))) + len(list(ipaddress.collapse_addresses(v6_nets)))
    if total_rules == len(ip_rules) and frag_count > config.max_cidr_fragmentation: return False
    if frag_count > config.frag_toxic_count and (frag_count / max(1, total_rules)) > config.frag_toxic_ratio: return True
    return False

class LightweightDomainNode:
    __slots__ = ('children', 'e_tier', 'e_excl', 'e_id', 's_tier', 's_excl', 's_id', 'w_tier', 'w_excl', 'w_id')
    def __init__(self):
        self.children = None
        self.e_tier = self.s_tier = self.w_tier = 255  
        self.e_excl = self.s_excl = self.w_excl = False
        self.e_id = self.s_id = self.w_id = 0

    def update_policy(self, mt: MatchType, tier: int, excl: bool, attr_id: int, pool: AttributePool):
        if mt == MatchType.EXACT:     curr_t, curr_e, curr_id = self.e_tier, self.e_excl, self.e_id
        elif mt == MatchType.SUFFIX:  curr_t, curr_e, curr_id = self.s_tier, self.s_excl, self.s_id
        elif mt == MatchType.WILDCARD:curr_t, curr_e, curr_id = self.w_tier, self.w_excl, self.w_id
        else: return

        if curr_t == 255 or tier < curr_t:
            final_t, final_e, final_id = tier, excl, attr_id
        elif tier == curr_t:
            allow_wins = (pool.config.same_tier_conflict_resolution == 'allow_wins')
            if excl == curr_e: 
                final_t, final_e = tier, excl
                final_id = pool.merge_ids_with_tier([(tier, curr_id), (tier, attr_id)])
            elif (not excl and allow_wins) or (excl and not allow_wins):
                final_t, final_e, final_id = tier, excl, attr_id
            else: return 
        else: return 

        if mt == MatchType.EXACT:     self.e_tier, self.e_excl, self.e_id = final_t, final_e, final_id
        elif mt == MatchType.SUFFIX:  self.s_tier, self.s_excl, self.s_id = final_t, final_e, final_id
        elif mt == MatchType.WILDCARD:self.w_tier, self.w_excl, self.w_id = final_t, final_e, final_id

class TieredDomainTrie:
    def __init__(self, attr_pool: AttributePool):
        self.root = LightweightDomainNode()
        self.attr_pool = attr_pool

    def insert(self, parts: List[str], match_type: MatchType, tier: int, is_excl: bool, attr_id: int):
        node = self.root
        for part in reversed(parts):
            if node.children is None: node.children = {}
            if part not in node.children: node.children[part] = LightweightDomainNode()
            node = node.children[part]
        node.update_policy(match_type, tier, is_excl, attr_id, self.attr_pool)

    def optimize_and_extract(self) -> List[Tuple[MatchType, str, bool, int, int]]:
        res = []
        def _prune(node: LightweightDomainNode, path: List[str], p_tier: int, p_excl: bool, p_id: int):
            emit_suffix = False
            if node.s_tier != 255:
                if node.s_tier < p_tier or (node.s_tier == p_tier and (node.s_excl != p_excl or node.s_id != p_id)):
                    emit_suffix = True
            if emit_suffix:
                res.append((MatchType.SUFFIX, '.'.join(reversed(path)), node.s_excl, node.s_id, node.s_tier))
                eff_tier, eff_excl, eff_id = node.s_tier, node.s_excl, node.s_id
            else:
                eff_tier, eff_excl, eff_id = p_tier, p_excl, p_id

            emit_wildcard = False
            if node.w_tier != 255:
                if node.w_tier < eff_tier or (node.w_tier == eff_tier and (node.w_excl != eff_excl or node.w_id != eff_id)):
                    emit_wildcard = True
            if emit_wildcard:
                res.append((MatchType.WILDCARD, '.'.join(reversed(path)), node.w_excl, node.w_id, node.w_tier))

            emit_exact = False
            if node.e_tier != 255:
                if node.e_tier < eff_tier or (node.e_tier == eff_tier and (node.e_excl != eff_excl or node.e_id != eff_id)):
                    emit_exact = True
            if emit_exact:
                res.append((MatchType.EXACT, '.'.join(reversed(path)), node.e_excl, node.e_id, node.e_tier))

            if node.children:
                for part, child in node.children.items():
                    path.append(part)
                    _prune(child, path, eff_tier, eff_excl, eff_id)
                    path.pop() 
                    
        for k, child in (self.root.children or {}).items():
            _prune(child, [k], 255, False, 0)
        return res

class TieredIPSweepLine:
    def __init__(self, width: int):
        self.width = width
        self.events = []

    def add(self, start: int, end: int, tier: int, is_excl: bool, attr_id: int):
        self.events.append((start, 1, tier, is_excl, attr_id))
        self.events.append((end + 1, -1, tier, is_excl, attr_id))

    def process(self, attr_pool: AttributePool, config: MergeConfig) -> Tuple[List[Tuple[str, int]], List[Tuple[str, int]]]:
        if not self.events: return [], []
        self.events.sort(key=lambda x: (x[0], x[1], x[2], 0 if x[3] else 1))
        
        active_states = defaultdict(int)
        raw_a, raw_d = defaultdict(list), defaultdict(list)
        prev_x, prev_state = -1, None
        conflict_allow_wins = (config.same_tier_conflict_resolution == 'allow_wins')

        def _get_winning_state():
            if not active_states: return None
            valid = [k for k, v in active_states.items() if v > 0]
            if not valid: return None
            valid.sort(key=lambda x: (x[0], 1 if x[1] == conflict_allow_wins else 0))
            best_tier, is_excl = valid[0][0], valid[0][1]
            merged_id = attr_pool.merge_ids_with_tier([(s[0], s[2]) for s in valid if s[0] == best_tier and s[1] == is_excl])
            return (is_excl, merged_id)

        i, n = 0, len(self.events)
        while i < n:
            x = self.events[i][0]
            if prev_x != -1 and x > prev_x and prev_state is not None:
                is_excl, attr_id = prev_state
                target_dict = raw_d if is_excl else raw_a
                target_dict[attr_id].append((prev_x, x - 1))
            
            while i < n and self.events[i][0] == x:
                _, op, tier, is_excl, attr_id = self.events[i]
                target_state = (tier, is_excl, attr_id)
                active_states[target_state] += op
                if active_states[target_state] <= 0: del active_states[target_state]
                i += 1
                
            prev_state = _get_winning_state()
            prev_x = x

        def _cidr_split(start: int, end: int):
            cur = start
            while cur <= end:
                max_sz = (cur & -cur) if cur != 0 else (1 << self.width)
                rem = end - cur + 1
                if max_sz > rem: max_sz = 1 << (rem.bit_length() - 1)
                yield (cur, self.width - (max_sz.bit_length() - 1))
                cur += max_sz

        def _precise_compact(raw_dict):
            res = []
            net_cls = ipaddress.IPv4Network if self.width == 32 else ipaddress.IPv6Network
            for attr_id, ivs in raw_dict.items():
                nets = []
                for s, e in ivs:
                    for c, p in _cidr_split(s, e):
                        nets.append(net_cls((c, p), strict=False))
                
                nets = list(ipaddress.collapse_addresses(nets))
                if config.max_cidr_fragmentation > 0 and len(nets) > config.max_cidr_fragmentation:
                    if config.strict_cidr_limit:
                        raise CIDRFragmentationError(f"CIDR limit exceeded ({len(nets)})")
                        
                for net in nets: res.append((str(net), attr_id))
            return res

        return _precise_compact(raw_a), _precise_compact(raw_d)

class RuleParser:
    __slots__ = ('_cfg', '_ctx', '_attr_pool', '_exclude_keys', '_logical_keys')
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
        'RULE-SET': 'rule_set', 'USER-AGENT': 'user_agent',
        'GEOSITE': 'geosite', 'SOURCE-GEOIP': 'source_geoip',
        'NETWORK': 'network', 'PROTOCOL': 'protocol', 'INBOUND': 'inbound',
        'AUTH-USER': 'auth_user', 'RULE-SET-IP-CIDR': 'rule_set_ip_cidr', 'RULE-SET-DOMAIN': 'rule_set_domain'
    }

    def __init__(self, c: MergeConfig, ctx: TaskContext, attr_pool: AttributePool):
        self._cfg, self._ctx, self._attr_pool = c, ctx, attr_pool
        self._exclude_keys = {'invert', 'version', 'rules'}.union(set(k.lower() for k in self.RMAP.keys())).union(set(self.RMAP.values()))
        self._logical_keys = {'and', 'or', 'not'}

    def parse(self, src: Union[bytes, Path], tier: int, url: str = "") -> ParsedRuleSet:
        dom, ip, gen = [], [], []
        dga_count = [0] 
        
        try:
            if isinstance(src, Path):
                with src.open('rb') as f: header = f.read(1024)
            else: header = src[:1024]
            is_j = header.find(b'{') != -1
        except OSError: return ParsedRuleSet([], [], [])
        
        def _add(typ: Optional[str], val: str, is_excl: bool, attrs: str = ""):
            attr_id = self._attr_pool.get_id(attrs)
            if typ in ('domain', 'domain_suffix', 'domain_wildcard') and val:
                n = val[2:].strip().lower().strip('.') if val.startswith('*.') else val.strip().lower().strip('.')
                if not n.isascii():
                    try: n = n.encode('idna').decode('ascii')
                    except UnicodeError: return
                parts = n.split('.')
                if not n or len(n) > self._cfg.max_domain_length or ' ' in n or len(parts) > 50: return
                
                n = self._ctx.intern(n) 
                
                if tier > 0 and self._cfg.enable_dga_filter and EntropyAssessor.assess(n) == EntropyLevel.DGA_CONFIRMED:
                    dga_count[0] += 1; return 
                    
                mt = MatchType.WILDCARD if typ == 'domain_wildcard' or val.startswith('*.') else (MatchType.SUFFIX if typ == 'domain_suffix' else MatchType.EXACT)
                dom.append(DomainRule(mt, n, is_excl, attr_id, tier))
            elif typ in ('domain_keyword', 'domain_regex'):
                val_to_store = val.lower() if typ == 'domain_keyword' else val
                dom.append(DomainRule(MatchType.KEYWORD if typ == 'domain_keyword' else MatchType.REGEX, self._ctx.intern(val_to_store), is_excl, attr_id, tier))
            elif typ in ('ip_cidr', 'source_ip_cidr'):
                m = RE_IPV4_MAPPED_IPV6.match(val)
                if m:
                    v4_ip, prefix = m.group(1), int(m.group(2)) if m.group(2) else 32
                    if prefix >= 96: prefix -= 96
                    val = f"{v4_ip}/{prefix}"
                try: 
                    net = ipaddress.ip_network(val, strict=False)
                    if net.version == 4 or self._cfg.enable_ipv6: 
                        ip.append(IPCIDRRule(int(net.network_address), int(net.broadcast_address), net.prefixlen, net.version, is_excl, attr_id))
                except ValueError: pass
            elif typ: gen.append(GenericRule(self._ctx.intern(typ), self._ctx.intern(val), is_excl, attr_id, tier))

        if is_j:
            try:
                raw = src.read_bytes() if isinstance(src, Path) else src
                if raw.startswith(b'\xef\xbb\xbf'): raw = raw[3:]
                data = orjson.loads(raw) if USE_ORJSON else json.loads(raw.decode('utf-8', errors='ignore'))
                rules_node = data.get('rules', []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
                
                for r in rules_node:
                    if not isinstance(r, dict): continue
                    if any(lk in r for lk in self._logical_keys): continue
                    is_excl = r.get('invert', False)
                    extra_attrs = {ek: ev for ek, ev in r.items() if ek.lower() not in self._exclude_keys}
                    attr_str = json.dumps(extra_attrs, sort_keys=True, ensure_ascii=False) if extra_attrs else ""
                    
                    for k, v in r.items():
                        kl = k.lower()
                        if kl in self._exclude_keys and kl not in ('invert', 'version', 'rules'):
                            mt = self.RMAP.get(k.upper(), kl)
                            vals = v if isinstance(v, list) else [v]
                            for val in vals:
                                if str(val).strip(): _add(mt, str(val).strip(), is_excl, attr_str)
            except Exception: pass
        else:
            try:
                wrapper = open(src, 'r', encoding='utf-8-sig', errors='ignore') if isinstance(src, Path) else io.TextIOWrapper(io.BytesIO(src), encoding='utf-8-sig', errors='ignore')
                with wrapper as f:
                    for ln in f:
                        ln = ln.strip()
                        if not ln or ln.startswith(('#', '//', ';')): continue
                        is_excl = ln.startswith('!')
                        v = ln[1:].strip() if is_excl else ln
                        p = v.split(',')
                        if len(p) >= 2 and p[0].upper() in self.RMAP: 
                            raw_attrs, attrs_dict = p[2:], {}
                            for attr in raw_attrs:
                                attr = attr.strip()
                                if attr.upper() in ('PROXY', 'REJECT', 'DIRECT'): attrs_dict['policy'] = attr.upper()
                                elif attr.lower() == 'no-resolve': attrs_dict['no-resolve'] = True
                                else: attrs_dict[attr] = True 
                            attr_str = json.dumps(attrs_dict, sort_keys=True, ensure_ascii=False) if attrs_dict else ""
                            _add(self.RMAP[p[0].upper()], p[1].strip(), is_excl, attr_str)
                        else: 
                            _add('domain', v, is_excl, "")
            except OSError: pass
        return ParsedRuleSet(dom, ip, gen, u=url, dga=dga_count[0])

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
                    try: db = zlib.decompress(raw[24:])
                    except zlib.error: db = raw[24:]
                    try:
                        if USE_MSGPACK: self.data = msgpack.unpackb(db, raw=False)
                        elif USE_ORJSON: self.data = orjson.loads(db)
                        else: self.data = json.loads(db.decode('utf-8'))
                    except Exception: pass
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
                else: b = json.dumps(self.data, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
                cb = zlib.compress(b, level=6)
                tp = Path(f"{self.db_path}.{uuid.uuid4().hex}.tmp")
                with open(tp, 'wb') as f:
                    f.write(hashlib.blake2b(cb, digest_size=16).digest())
                    f.write(struct.pack('>d', time.time()))
                    f.write(cb)
                    f.flush()
                    os.fsync(f.fileno())
                tp.replace(self.db_path)
            except Exception: pass

def resolve_hostname(hostname: str) -> List[str]:
    with _DNS_LOCK:
        if hostname in _DNS_CACHE:
            ts, ips = _DNS_CACHE[hostname]
            if time.time() - ts < 300:
                _DNS_CACHE.move_to_end(hostname); return ips
            del _DNS_CACHE[hostname]
        if hostname in _DNS_PENDING: ev, wait = _DNS_PENDING[hostname], True
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

def _dl_single(cfg: MergeConfig, url: str, tier: int, td: Path, cache: Optional[WALBackend], parser: RuleParser, attr_pool: AttributePool) -> Tuple[Optional[ParsedRuleSet], Optional[dict]]:
    ckey = f"p:{CACHE_VERSION}:{url}" 
    if cache:
        l = cache.get(ckey)
        if l and time.time() - l.get('ts', 0) < cfg.max_source_age_days * 86400:
            try:
                doms = [DomainRule(MatchType(r['mt']), parser._ctx.intern(r['n']), r['excl'], attr_pool.get_id(r['a']), tier) for r in l.get('d', [])]
                ips = [IPCIDRRule(r['s'], r['e'], r['p'], r['v'], r['excl'], attr_pool.get_id(r['a'])) for r in l.get('i', [])]
                gens = [GenericRule(parser._ctx.intern(r['t']), parser._ctx.intern(r['v']), r['excl'], attr_pool.get_id(r['a']), tier) for r in l.get('g', [])]
                return ParsedRuleSet(doms, ips, gens, u=url, dga=l.get('dga', 0)), None
            except Exception: pass

    for rc in range(MAX_DOWNLOAD_RETRIES):
        curl, vis, tmp, ok = url, set(), None, False
        try:
            while len(vis) < 5:
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
                            with s.get(curl, stream=True, timeout=(cfg.download_timeout_connect, cfg.download_timeout_read), allow_redirects=False, headers={"User-Agent": "StrictRuleMerger/Omni"}) as resp:
                                if resp.status_code in (301, 302, 303, 307, 308):
                                    curl = urljoin(curl, resp.headers.get('Location', ''))
                                    redir = True
                                    break
                                resp.raise_for_status()
                                
                                html_check, is_html, bytes_downloaded = 0, False, 0
                                with tempfile.NamedTemporaryFile(suffix='.tmp', dir=str(td), delete=False) as f:
                                    tmp = Path(f.name)
                                    for chunk in resp.iter_content(131072):
                                        if not chunk: continue
                                        bytes_downloaded += len(chunk)
                                        if bytes_downloaded > cfg.max_download_size: raise SizeLimitError()
                                        if not curl.endswith('.srs') and html_check < 3:
                                            if RE_HTML_STRICT.search(chunk) and not curl.endswith('.html'):
                                                is_html = True; break
                                            html_check += 1
                                        f.write(chunk)
                                if is_html: 
                                    tmp.unlink(missing_ok=True); tmp = None
                                    raise TransientError()
                                ok = True; break
                    except SizeLimitError:
                        if tmp and tmp.exists(): tmp.unlink(missing_ok=True); tmp = None
                        break 
                    except Exception:
                        if tmp and tmp.exists(): tmp.unlink(missing_ok=True); tmp = None
                    finally:
                        if hasattr(_dns_context, 'forced_host'): delattr(_dns_context, 'forced_host')
                        if hasattr(_dns_context, 'forced_ip'): delattr(_dns_context, 'forced_ip')
                if redir or ok: break
        finally: pass
        if ok and tmp: break
        if not ok and rc < MAX_DOWNLOAD_RETRIES - 1: time.sleep((2 ** rc))
        
    if not ok or not tmp: return None, None
    
    srs = None
    if url.endswith('.srs') and cfg.validate_core_path():
        srs = tmp
        json_f = tmp.with_suffix('.json')
        try:
            subprocess.run([str(Path(cfg.core_bin_path).expanduser().absolute()), "rule-set", "decompile", "--output", str(json_f), str(srs)], check=True, capture_output=True, timeout=cfg.compile_timeout_seconds)
            tmp = json_f
        except Exception: 
            if srs.exists(): srs.unlink(missing_ok=True)
            return None, None
        finally: 
            if srs.exists(): srs.unlink(missing_ok=True)
            
    try: 
        ps = parser.parse(tmp, tier, url)
        ts_update = None
        if cache and ps and (ps.domain_rules or ps.ip_rules or ps.generic_rules):
            d_rules = [{'mt': r.match_type.value, 'n': r.normalized, 'excl': r.is_exclusion, 'a': attr_pool.id_to_str[r.attrs]} for r in ps.domain_rules]
            i_rules = [{'s': r.start_int, 'e': r.end_int, 'p': r.prefixlen, 'v': r.version, 'excl': r.is_exclusion, 'a': attr_pool.id_to_str[r.attrs]} for r in ps.ip_rules]
            g_rules = [{'t': r.type, 'v': r.val, 'excl': r.is_exclusion, 'a': attr_pool.id_to_str[r.attrs]} for r in ps.generic_rules]
            ts_update = {ckey: {'ts': time.time(), 'dga': ps.dga_count, 'd': d_rules, 'i': i_rules, 'g': g_rules}}
        return ps, ts_update
    finally: tmp.unlink(missing_ok=True)

def _format_policy(attrs: str, default_pol: str) -> str:
    if not attrs: return default_pol
    try:
        d = json.loads(attrs)
        res = d.get('policy', default_pol)
        if d.get('no_resolve') or d.get('no-resolve'): res += ",no-resolve"
        return res
    except Exception: return default_pol

def generate_final_rules(trie: TieredDomainTrie, kr_dict: dict, gen_dict: dict, config: MergeConfig) -> List[Union[DomainRule, GenericRule]]:
    all_d = []
    tier_keywords = defaultdict(list)
    tier_regexes = defaultdict(list)

    for (mt, norm), (tier, is_excl, attr_id) in kr_dict.items():
        all_d.append(DomainRule(mt, norm, is_excl, attr_id, tier))
        if mt == MatchType.KEYWORD:
            tier_keywords[tier].append(norm)
        elif mt == MatchType.REGEX:
            try: tier_regexes[tier].append(re.compile(norm, re.IGNORECASE))
            except re.error: pass

    tier_kw_automata = {}
    for t, kws in tier_keywords.items():
        chunk_size = config.keyword_chunk_size
        tier_kw_automata[t] = [re.compile('|'.join(map(re.escape, kws[i:i+chunk_size])), re.IGNORECASE) for i in range(0, len(kws), chunk_size)]

    for mt, norm, is_excl, attr_id, tier in trie.optimize_and_extract():
        is_shadowed = False
        for higher_tier in range(0, tier):
            if any(rgx.search(norm) for rgx in tier_kw_automata.get(higher_tier, [])):
                is_shadowed = True; break
            if any(rgx.search(norm) for rgx in tier_regexes.get(higher_tier, [])):
                is_shadowed = True; break
                
        if not is_shadowed:
            all_d.append(DomainRule(mt, norm, is_excl, attr_id, tier))

    for (typ, val), (tier, is_excl, attr_id) in gen_dict.items():
        all_d.append(GenericRule(typ, val, is_excl, attr_id, tier))

    def get_sort_priority(r: Union[DomainRule, GenericRule]) -> int:
        if isinstance(r, DomainRule): return config.match_type_sort_order.get(r.match_type, r.match_type.value)
        return config.generic_priority.get(r.type, 100) 

    def get_specificity(r: Union[DomainRule, GenericRule]) -> int:
        return getattr(r, 'specificity_score', 0)

    def get_normalized_val(r: Union[DomainRule, GenericRule]) -> str:
        return getattr(r, 'normalized', getattr(r, 'val', ''))

    all_d.sort(key=lambda r: (
        r.tier,                                 
        0 if not getattr(r, 'is_exclusion', False) else 1,         
        -get_specificity(r),                    
        get_sort_priority(r),                   
        get_normalized_val(r),
        r.attrs
    ))
    return all_d

def worker(task: Dict[str, Any], global_cfg: MergeConfig) -> Tuple[str, str, str, str, float]:
    start_time = time.time()
    name = task.get('name', '')
    if not name or not RE_TASK_NAME.match(name): return (name, "❌", "Invalid name", "0KB", 0.0)
    
    td, cache = None, None
    try:
        td = Path(tempfile.mkdtemp(prefix=f"sb_merge_{name}_"))
        cfg = MergeConfig.from_dict(task.get('config', {}), global_cfg)
        out_p = cfg.output_dir / f"merged-{cfg.output_format}" / f"{name}.{'list' if cfg.output_format == 'surge' else 'yaml' if cfg.output_format == 'clash' else 'json'}"
        out_p.parent.mkdir(parents=True, exist_ok=True)

        if cfg.enable_cache:
            cache_root = Path.cwd() / ".cache"
            cdir = cache_root / "rule_merger" / name
            try:
                cdir.mkdir(parents=True, exist_ok=True)
                ignore_file = cache_root / ".gitignore"
                if not ignore_file.exists(): ignore_file.write_text("*\n")
                cache = WALBackend(cdir / "source_cache", cfg)
            except OSError: pass
        
        ctx = TaskContext()
        attr_pool = AttributePool(cfg)
        parser = RuleParser(cfg, ctx, attr_pool)
        
        sources_info = []
        for idx, s in enumerate(task.get('sources', [])):
            s_url = s if isinstance(s, str) else s.get('url')
            if not s_url: continue
            tier = int(s.get('tier', idx)) if isinstance(s, dict) and 'tier' in s else idx
            sources_info.append((s_url, tier))

        valid_sources, upd = [], {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=cfg.max_concurrent_downloads) as ex:
            futs = {ex.submit(_dl_single, cfg, url, tier, td, cache, parser, attr_pool): (url, tier) for url, tier in sources_info}
            for fu in concurrent.futures.as_completed(futs):
                url, tier = futs[fu]
                result, u = fu.result() 
                if result and result.rule_count > 0:
                    valid_sources.append((tier, url, result))
                if u: upd.update(u)
                    
        if cache and upd: cache.put_batch(upd)
        if not valid_sources: return (name, "⚠️", "No valid sources", "0KB", time.time() - start_time)

        adjudicator = RuleAdjudicator(cfg, attr_pool)
        for tier, url, result in valid_sources:
            for r in result.domain_rules + result.ip_rules + result.generic_rules:
                adjudicator.observe(r)

        safe_sources = []
        for tier, url, result in valid_sources:
            if is_source_ip_fragmentation_toxic(result.ip_rules, result.rule_count, cfg):
                logger.warning(f"Source {url} IP fragmentation storm detected, dropped.")
                continue

            dga_ratio = result.dga_count / result.rule_count if result.rule_count > 0 else 0
            if dga_ratio > 0.3: continue
            
            if CanaryDetector.is_poisoned(result.domain_rules, result.ip_rules, tier, attr_pool, cfg): 
                logger.error(f"Canary triggered for {url}, dropped.")
                continue 

            new_doms = [r for r in result.domain_rules if adjudicator.adjudicate(r, tier, len(valid_sources))]
            new_ips = [r for r in result.ip_rules if adjudicator.adjudicate(r, tier, len(valid_sources))]
            new_gens = [r for r in result.generic_rules if adjudicator.adjudicate(r, tier, len(valid_sources))]
            
            if new_doms or new_ips or new_gens:
                safe_sources.append((tier, new_doms, new_ips, new_gens))

        v4_engine = TieredIPSweepLine(32)
        v6_engine = TieredIPSweepLine(128)
        dom_trie = TieredDomainTrie(attr_pool)
        kr_dict, gen_dict = {}, {} 

        for tier, doms, ips, gens in safe_sources:
            for r in ips:
                target_engine = v4_engine if r.version == 4 else v6_engine
                target_engine.add(r.start_int, r.end_int, tier, r.is_exclusion, r.attrs)
                
            for r in doms:
                if r.match_type in (MatchType.KEYWORD, MatchType.REGEX):
                    k = (r.match_type, r.normalized)
                    if k not in kr_dict:
                        kr_dict[k] = (tier, r.is_exclusion, r.attrs)
                    else:
                        o_tier, o_excl, o_id = kr_dict[k]
                        if tier < o_tier or (tier == o_tier and r.is_exclusion and not o_excl):
                            kr_dict[k] = (tier, r.is_exclusion, r.attrs)
                        elif tier == o_tier and r.is_exclusion == o_excl:
                            kr_dict[k] = (tier, r.is_exclusion, attr_pool.merge_ids_with_tier([(o_tier, o_id), (tier, r.attrs)]))
                else:
                    dom_trie.insert(r.normalized.split('.'), r.match_type, tier, r.is_exclusion, r.attrs)
                    
            for r in gens:
                k = (r.type, r.val)
                if k not in gen_dict:
                    gen_dict[k] = (tier, r.is_exclusion, r.attrs)
                else:
                    o_tier, o_excl, o_id = gen_dict[k]
                    if tier < o_tier or (tier == o_tier and r.is_exclusion and not o_excl):
                        gen_dict[k] = (tier, r.is_exclusion, r.attrs)
                    elif tier == o_tier and r.is_exclusion == o_excl:
                        gen_dict[k] = (tier, r.is_exclusion, attr_pool.merge_ids_with_tier([(o_tier, o_id), (tier, r.attrs)]))

        f_a_ip_strs, f_d_ip_strs = [], []
        a4, d4 = v4_engine.process(attr_pool, cfg)
        a6, d6 = v6_engine.process(attr_pool, cfg)
        f_a_ip_strs.extend(a4); f_a_ip_strs.extend(a6)
        f_d_ip_strs.extend(d4); f_d_ip_strs.extend(d6)

        all_d = generate_final_rules(dom_trie, kr_dict, gen_dict, cfg)

        is_sg, is_cl = cfg.output_format == 'surge', cfg.output_format == 'clash'
        if is_sg or is_cl:
            pf = "  - " if is_cl else ""
            with open(out_p, 'w', encoding='utf-8') as f:
                if is_cl: f.write("payload:\n")
                for r in all_d:
                    pol = _format_policy(attr_pool.id_to_str[r.attrs], cfg.allow_policy if not getattr(r, 'is_exclusion', False) else cfg.deny_policy)
                    if isinstance(r, GenericRule):
                        f.write(f"{pf}{r.type.replace('_', '-').upper()},{r.val},{pol}\n")
                        continue
                    typ = 'DOMAIN' if r.match_type == MatchType.EXACT else 'DOMAIN-SUFFIX' if r.match_type in (MatchType.SUFFIX, MatchType.WILDCARD) else 'DOMAIN-KEYWORD' if r.match_type == MatchType.KEYWORD else 'DOMAIN-REGEX'
                    val = f"*.{r.normalized}" if r.match_type == MatchType.WILDCARD else r.normalized
                    f.write(f"{pf}{typ},{val},{pol}\n")
                    
                for cidr, attr_id in f_a_ip_strs: f.write(f"{pf}IP-CIDR{'6' if ':' in cidr else ''},{cidr},{_format_policy(attr_pool.id_to_str[attr_id], cfg.allow_policy)}\n")
                for cidr, attr_id in f_d_ip_strs: f.write(f"{pf}IP-CIDR{'6' if ':' in cidr else ''},{cidr},{_format_policy(attr_pool.id_to_str[attr_id], cfg.deny_policy)}\n")
        else:
            rbt = defaultdict(list)
            for r in all_d:
                if isinstance(r, GenericRule): rbt[(r.type, r.is_exclusion, r.attrs)].append(r.val)
                else:
                    typ = 'domain' if r.match_type == MatchType.EXACT else 'domain_suffix' if r.match_type in (MatchType.SUFFIX, MatchType.WILDCARD) else 'domain_keyword' if r.match_type == MatchType.KEYWORD else 'domain_regex'
                    rbt[(typ, r.is_exclusion, r.attrs)].append(r.normalized)
            for cidr, attr_id in f_a_ip_strs: rbt[('ip_cidr', False, attr_id)].append(cidr)
            for cidr, attr_id in f_d_ip_strs: rbt[('ip_cidr', True, attr_id)].append(cidr)
            
            jr = []
            for (t, is_excl, attr_id), vals in rbt.items():
                rule_dict = {'invert': True} if is_excl else {}
                attrs_str = attr_pool.id_to_str[attr_id]
                if attrs_str:
                    try: rule_dict.update(json.loads(attrs_str))
                    except Exception: pass
                rule_dict[t] = vals[0] if len(vals) == 1 else vals
                jr.append(rule_dict)
                
            fd = {"version": TARGET_FORMAT_VERSION, "rules": jr}
            if USE_ORJSON: out_p.write_bytes(orjson.dumps(fd, option=orjson.OPT_INDENT_2))
            else: out_p.write_text(json.dumps(fd, indent=2, ensure_ascii=False), encoding='utf-8')

        out_srs = None
        if cfg.core_bin_path and cfg.validate_core_path() and cfg.output_format == 'json':
            out_srs = cfg.output_dir / "merged-srs" / f"{name}.srs"
            out_srs.parent.mkdir(parents=True, exist_ok=True)
            try: subprocess.run([str(Path(cfg.core_bin_path).expanduser().absolute()), "rule-set", "compile", "--output", str(out_srs), str(out_p)], check=True, capture_output=True)
            except Exception: pass

        sz = f"{(out_srs if out_srs and out_srs.exists() else out_p).stat().st_size / 1024:.1f}KB"
        rcnt = len(all_d) + len(f_a_ip_strs) + len(f_d_ip_strs)
        return (name, "✅", f"Ultimate Configurable: {rcnt} rules", sz, time.time() - start_time)

    except Exception as e:
        logger.exception(f"[{name}] Task Error")
        return (name, "❌", f"Crash: {str(e)[:50]}", "0KB", time.time() - start_time)
    finally:
        if td and td.exists(): shutil.rmtree(td, ignore_errors=True)

def main() -> int:
    cfg, cfg_path, tasks = MergeConfig(), Path('custom_merge.json'), []
    if not cfg_path.exists(): cfg_path = Path('scripts/custom_merge.json')
    if cfg_path.exists():
        try:
            data = orjson.loads(cfg_path.read_bytes()) if USE_ORJSON else json.loads(cfg_path.read_text('utf-8'))
            cfg = MergeConfig.from_dict(data.get('global', {}), cfg)
            tasks = data.get('merge_tasks', [])
        except Exception: pass

    if not tasks: return 0
    res, exe, intr = [], None, False
    try:
        exe = concurrent.futures.ThreadPoolExecutor(max_workers=min(cfg.max_workers, len(tasks)))
        futs = {exe.submit(worker, t, cfg): t for t in tasks}
        for f in concurrent.futures.as_completed(futs):
            try: res.append(f.result())
            except Exception as e: res.append((futs[f].get('name', 'Unknown'), "❌", f"Crash: {str(e)[:50]}", "0KB", 0.0))
                
        if smf := os.getenv('GITHUB_STEP_SUMMARY'):
            try:
                with open(smf, 'a', encoding='utf-8') as f:
                    f.write("## Ultimate Precision Merge Report\n| Task | Status | Details | Size | Time |\n|---|---|---|---|---|\n")
                    for r in sorted(res, key=lambda x: x[0]): f.write(f"| {r[0]} | {r[1]} | {r[2]} | {r[3]} | {r[4]:.1f}s |\n")
            except OSError: pass
    except KeyboardInterrupt:
        intr = True
        for fu in futs: fu.cancel()
        if exe: exe.shutdown(wait=False, cancel_futures=True)
        return 130
    finally:
        if exe and not intr: exe.shutdown(wait=True)
    return 1 if any(r[1] == "❌" for r in res) else 0

if __name__ == '__main__':
    sys.exit(main())
