"""
PhishGuard-X — Layer 7: Attack Graph Intelligence
NetworkX-based phishing infrastructure graph (Neo4j-ready schema)
Graph-based cluster detection and campaign correlation
"""

import json, hashlib, time
from datetime import datetime
from urllib.parse import urlparse
from collections import defaultdict
import numpy as np

try:
    import networkx as nx
    HAS_NX = True
except ImportError:
    HAS_NX = False

class PhishingKnowledgeGraph:
    """
    In-memory phishing knowledge graph (NetworkX).
    Schema mirrors Neo4j production design.
    Node types: URL, Domain, IP, Brand, Campaign
    """

    def __init__(self):
        self.G = nx.DiGraph() if HAS_NX else None
        self._url_index:    dict = {}   # url_hash -> node_id
        self._domain_index: dict = {}   # domain   -> node_id
        self._campaigns:    dict = defaultdict(set)  # campaign_id -> {url_hashes}
        self._node_count    = 0

    def _node_id(self) -> str:
        self._node_count += 1
        return f"N{self._node_count:08d}"

    def _url_hash(self, url: str) -> str:
        return hashlib.sha256(url.encode()).hexdigest()[:16]

    def add_url(self, url: str, features: dict, label: int = -1) -> str:
        """Add URL node to graph. Returns node_id."""
        if not self.G: return ''
        h = self._url_hash(url)
        if h in self._url_index:
            return self._url_index[h]
        nid = self._node_id()
        self._url_index[h] = nid
        try:
            domain = urlparse(url).netloc.lower()
        except Exception:
            domain = ''
        self.G.add_node(nid, type='URL', url_hash=h, domain=domain,
                        label=label, timestamp=time.time(),
                        risk_score=features.get('heuristic_risk_score', 0),
                        features=features)
        # Auto-link to domain node
        if domain:
            self.link_url_to_domain(nid, domain)
        return nid

    def add_domain(self, domain: str, metadata: dict = None) -> str:
        if not self.G: return ''
        if domain in self._domain_index:
            return self._domain_index[domain]
        nid = self._node_id()
        self._domain_index[domain] = nid
        self.G.add_node(nid, type='Domain', domain=domain,
                        timestamp=time.time(), **(metadata or {}))
        return nid

    def link_url_to_domain(self, url_nid: str, domain: str):
        if not self.G: return
        dnid = self.add_domain(domain)
        if not self.G.has_edge(url_nid, dnid):
            self.G.add_edge(url_nid, dnid, rel='RESOLVES_TO', weight=1.0)

    def link_redirect(self, src_url: str, dst_url: str, src_features: dict, dst_features: dict):
        if not self.G: return
        snid = self.add_url(src_url, src_features)
        dnid = self.add_url(dst_url, dst_features)
        self.G.add_edge(snid, dnid, rel='REDIRECTS_TO', weight=1.0,
                        timestamp=time.time())

    def assign_campaign(self, url: str, campaign_id: str):
        h = self._url_hash(url)
        self._campaigns[campaign_id].add(h)

    def detect_clusters(self) -> list:
        """Find connected components of phishing URLs sharing infrastructure."""
        if not self.G: return []
        undirected = self.G.to_undirected()
        clusters = []
        for component in nx.connected_components(undirected):
            url_nodes = [n for n in component
                         if self.G.nodes[n].get('type') == 'URL']
            if len(url_nodes) >= 2:
                clusters.append({
                    'size':     len(url_nodes),
                    'nodes':    url_nodes[:10],
                    'risk_avg': np.mean([self.G.nodes[n].get('risk_score',0)
                                         for n in url_nodes]),
                })
        return sorted(clusters, key=lambda c: c['size'], reverse=True)

    def get_url_graph_features(self, url: str) -> dict:
        """Graph-derived features for a URL node."""
        h = self._url_hash(url)
        nid = self._url_index.get(h)
        default = {
            'graph_degree_in':   0, 'graph_degree_out':  0,
            'graph_cluster_size':0, 'graph_campaign_overlap': 0,
            'graph_neighbor_risk_avg': 0.0, 'graph_is_hub': 0,
            'graph_betweenness': 0.0, 'graph_known_node': 0,
        }
        if not self.G or not nid:
            return default

        in_deg  = self.G.in_degree(nid)
        out_deg = self.G.out_degree(nid)

        # Cluster size
        undirected = self.G.to_undirected()
        try:
            component = nx.node_connected_component(undirected, nid)
            cluster_size = len([n for n in component
                                 if self.G.nodes[n].get('type') == 'URL'])
        except Exception:
            cluster_size = 1

        # Neighbor risk
        neighbors = list(self.G.successors(nid)) + list(self.G.predecessors(nid))
        neighbor_risks = [self.G.nodes[n].get('risk_score', 0) for n in neighbors]
        neighbor_risk_avg = float(np.mean(neighbor_risks)) if neighbor_risks else 0.0

        # Campaign overlap
        campaign_overlap = sum(1 for cid, members in self._campaigns.items()
                               if h in members)

        return {
            'graph_degree_in':         in_deg,
            'graph_degree_out':        out_deg,
            'graph_cluster_size':      cluster_size,
            'graph_campaign_overlap':  campaign_overlap,
            'graph_neighbor_risk_avg': round(neighbor_risk_avg, 3),
            'graph_is_hub':            int(in_deg + out_deg > 5),
            'graph_betweenness':       0.0,  # computed on-demand for large graphs
            'graph_known_node':        1,
        }

    def stats(self) -> dict:
        if not self.G: return {'nodes':0,'edges':0,'clusters':0}
        clusters = self.detect_clusters()
        return {
            'nodes':    self.G.number_of_nodes(),
            'edges':    self.G.number_of_edges(),
            'url_nodes':len(self._url_index),
            'domains':  len(self._domain_index),
            'clusters': len(clusters),
            'campaigns':len(self._campaigns),
        }

# Global graph instance
_graph = PhishingKnowledgeGraph()

def get_graph() -> PhishingKnowledgeGraph:
    return _graph

def get_graph_feature_names() -> list:
    return [
        'graph_degree_in','graph_degree_out','graph_cluster_size',
        'graph_campaign_overlap','graph_neighbor_risk_avg',
        'graph_is_hub','graph_betweenness','graph_known_node',
    ]
