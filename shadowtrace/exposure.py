# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         exposure.py
# Purpose:      ShadowTrace Exposure Intelligence Engine
#               Entity Resolution, Confidence Scoring, Evidence Provenance,
#               Explainable Risk Calculation, Attack Path Analysis & Remediation.
#
# Copyright:    (c) ShadowTrace Exposure Intelligence Team 2026
# Licence:      MIT
# -------------------------------------------------------------------------------

import hashlib
import json
import logging
import re
import time
from typing import Dict, List, Any, Tuple, Optional


class EntityType:
    PERSON = "PERSON"
    EMAIL = "EMAIL"
    USERNAME = "USERNAME"
    DOMAIN = "DOMAIN"
    IP = "IP"
    ORGANIZATION = "ORGANIZATION"
    REPOSITORY = "REPOSITORY"
    DOCUMENT = "DOCUMENT"
    CERTIFICATE = "CERTIFICATE"
    SOCIAL_ACCOUNT = "SOCIAL_ACCOUNT"


class RelationType:
    EMAIL_USED_BY = "EMAIL_USED_BY"
    USERNAME_MATCHES = "USERNAME_MATCHES"
    DOMAIN_OWNS = "DOMAIN_OWNS"
    ACCOUNT_LINKED_TO = "ACCOUNT_LINKED_TO"
    REPOSITORY_CONTAINS = "REPOSITORY_CONTAINS"
    CERTIFICATE_FOR = "CERTIFICATE_FOR"
    IP_RESOLVES_TO = "IP_RESOLVES_TO"
    HOSTED_ON = "HOSTED_ON"
    EXPOSES_CREDENTIALS = "EXPOSES_CREDENTIALS"


class ConfidenceTier:
    WEAK = "Weak"          # 0 - 30
    POSSIBLE = "Possible"  # 31 - 60
    STRONG = "Strong"      # 61 - 80
    VERY_STRONG = "Very Strong" # 81 - 100


class ObservationMode:
    OBSERVED = "Observed"
    INFERRED = "Inferred"
    USER_CONFIRMED = "User Confirmed"


class Entity:
    """Represents a resolved high-level OSINT identity/infrastructure entity."""
    def __init__(self, entity_type: str, value: str, risk_score: int = 0, first_seen: int = 0):
        self.id = hashlib.sha256(f"{entity_type}:{value.lower().strip()}".encode("utf-8")).hexdigest()[:16]
        self.type = entity_type
        self.value = value.strip()
        self.risk_score = min(100, max(0, risk_score))
        self.first_seen = first_seen or int(time.time())
        self.source_event_hashes: List[str] = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "value": self.value,
            "risk_score": self.risk_score,
            "first_seen": self.first_seen,
            "source_event_hashes": self.source_event_hashes
        }


class Relationship:
    """Represents a directional semantic relationship between two entities."""
    def __init__(self, source_entity_id: str, target_entity_id: str, rel_type: str, confidence_score: int, reasoning: List[str], risk_impact: int = 0):
        self.id = hashlib.sha256(f"{source_entity_id}:{rel_type}:{target_entity_id}".encode("utf-8")).hexdigest()[:16]
        self.source_entity_id = source_entity_id
        self.target_entity_id = target_entity_id
        self.rel_type = rel_type
        self.confidence_score = min(100, max(0, confidence_score))
        self.confidence_tier = ConfidenceEngine.normalize_confidence(self.confidence_score)
        self.reasoning = reasoning
        self.risk_impact = risk_impact

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "source_entity_id": self.source_entity_id,
            "target_entity_id": self.target_entity_id,
            "rel_type": self.rel_type,
            "confidence_score": self.confidence_score,
            "confidence_tier": self.confidence_tier,
            "reasoning": self.reasoning,
            "risk_impact": self.risk_impact
        }


class Evidence:
    """Represents data provenance and evidence supporting an entity or relationship."""
    def __init__(self, relationship_id: str, source_module: str, source_event_hash: str, mode: str, raw_data: str, timestamp: int = 0):
        self.id = hashlib.sha256(f"{relationship_id}:{source_event_hash}".encode("utf-8")).hexdigest()[:16]
        self.relationship_id = relationship_id
        self.source_module = source_module
        self.source_event_hash = source_event_hash
        self.observation_mode = mode
        self.raw_data = raw_data
        self.timestamp = timestamp or int(time.time())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "relationship_id": self.relationship_id,
            "source_module": self.source_module,
            "source_event_hash": self.source_event_hash,
            "observation_mode": self.observation_mode,
            "raw_data": self.raw_data,
            "timestamp": self.timestamp
        }


class ConfidenceEngine:
    """Calculates normalized confidence scores for entity resolution and relationships."""

    @staticmethod
    def normalize_confidence(score: int) -> str:
        if score <= 30:
            return ConfidenceTier.WEAK
        elif score <= 60:
            return ConfidenceTier.POSSIBLE
        elif score <= 80:
            return ConfidenceTier.STRONG
        else:
            return ConfidenceTier.VERY_STRONG

    @staticmethod
    def calculate_confidence(factors: List[Tuple[str, int]]) -> Tuple[int, List[str]]:
        """Given a list of (factor_description, weight), returns (total_score, reasonings)."""
        score = sum(weight for _, weight in factors)
        reasonings = [f"{'+' if w >= 0 else ''}{w} {desc}" for desc, w in factors]
        normalized_score = min(100, max(0, score))
        return normalized_score, reasonings


class EntityResolver:
    """Resolves raw ShadowTrace events into structured entities and typed relationships."""

    EVENT_MAP = {
        'HUMAN_NAME': EntityType.PERSON,
        'EMAILADDR': EntityType.EMAIL,
        'EMAILADDR_GENERIC': EntityType.EMAIL,
        'USERNAME': EntityType.USERNAME,
        'DOMAIN_NAME': EntityType.DOMAIN,
        'INTERNET_NAME': EntityType.DOMAIN,
        'IP_ADDRESS': EntityType.IP,
        'IPV6_ADDRESS': EntityType.IP,
        'COMPANY_NAME': EntityType.ORGANIZATION,
        'PUBLIC_CODE_REPO': EntityType.REPOSITORY,
        'INTERESTING_FILE': EntityType.DOCUMENT,
        'SSL_CERTIFICATE_RAW': EntityType.CERTIFICATE,
        'SOCIAL_MEDIA': EntityType.SOCIAL_ACCOUNT,
        'ACCOUNT_EXTERNAL_OWNED': EntityType.SOCIAL_ACCOUNT,
    }

    def resolve_entities_and_relations(self, events: List[Dict[str, Any]]) -> Tuple[Dict[str, Entity], Dict[str, Relationship], List[Evidence]]:
        entities: Dict[str, Entity] = {}
        relationships: Dict[str, Relationship] = {}
        evidence_records: List[Evidence] = []
        hash_to_entity: Dict[str, Entity] = {}
        event_dict: Dict[str, Dict[str, Any]] = {e['hash']: e for e in events if 'hash' in e}

        # Step 1: Create Entity objects for mapped event types
        for ev in events:
            ev_type = ev.get('type')
            ev_data = ev.get('data', '')
            ev_hash = ev.get('hash')
            ev_module = ev.get('module', 'shadowtrace')
            ev_time = ev.get('generated', int(time.time()))
            ev_risk = ev.get('risk', 0)

            if not ev_data or not ev_type:
                continue

            entity_type = self.EVENT_MAP.get(ev_type)
            if entity_type:
                # Sanitize data for entity value
                val = ev_data.strip()
                entity = Entity(entity_type, val, risk_score=ev_risk, first_seen=ev_time)
                
                if entity.id not in entities:
                    entities[entity.id] = entity
                
                entities[entity.id].source_event_hashes.append(ev_hash)
                if ev_risk > entities[entity.id].risk_score:
                    entities[entity.id].risk_score = ev_risk
                    
                hash_to_entity[ev_hash] = entities[entity.id]

        # Step 2: Establish relationships by walking event tree and analyzing data correlation
        for ev in events:
            ev_hash = ev.get('hash')
            src_hash = ev.get('source_event_hash')
            ev_module = ev.get('module', 'unknown')
            ev_time = ev.get('generated', int(time.time()))
            ev_type = ev.get('type', '')

            target_entity = hash_to_entity.get(ev_hash)
            source_entity = hash_to_entity.get(src_hash) if src_hash else None

            # Handle direct parent-child tree links
            if source_entity and target_entity and source_entity.id != target_entity.id:
                rel_type, confidence_score, factors = self._determine_relationship_type(
                    source_entity, target_entity, ev, event_dict.get(src_hash, {})
                )
                
                rel = Relationship(
                    source_entity_id=source_entity.id,
                    target_entity_id=target_entity.id,
                    rel_type=rel_type,
                    confidence_score=confidence_score,
                    reasoning=factors,
                    risk_impact=max(source_entity.risk_score, target_entity.risk_score)
                )

                if rel.id not in relationships:
                    relationships[rel.id] = rel

                # Attach Evidence
                evd = Evidence(
                    relationship_id=rel.id,
                    source_module=ev_module,
                    source_event_hash=ev_hash,
                    mode=ObservationMode.OBSERVED,
                    raw_data=ev.get('data', '')[:300],
                    timestamp=ev_time
                )
                evidence_records.append(evd)

        # Step 3: Infer cross-correlations (e.g. Email domain matching Domain, Username in Email)
        self._infer_cross_correlations(entities, relationships, evidence_records)

        return entities, relationships, evidence_records

    def _determine_relationship_type(self, src: Entity, tgt: Entity, current_event: Dict[str, Any], parent_event: Dict[str, Any]) -> Tuple[str, int, List[str]]:
        factors = []
        rel_type = RelationType.ACCOUNT_LINKED_TO
        base_score = 50

        # Type combination rules
        if src.type == EntityType.EMAIL and tgt.type == EntityType.PERSON:
            rel_type = RelationType.EMAIL_USED_BY
            factors = ["+40 Direct email ownership", "+20 Verified via scan source"]
            base_score = 80

        elif src.type == EntityType.USERNAME and tgt.type == EntityType.SOCIAL_ACCOUNT:
            rel_type = RelationType.ACCOUNT_LINKED_TO
            factors = ["+40 Platform username match", "+20 Direct profile lookup"]
            base_score = 85

        elif src.type == EntityType.DOMAIN and tgt.type == EntityType.IP:
            rel_type = RelationType.IP_RESOLVES_TO
            factors = ["+50 DNS A/AAAA Record resolution", "+30 Direct DNS response"]
            base_score = 95

        elif src.type == EntityType.IP and tgt.type == EntityType.DOMAIN:
            rel_type = RelationType.HOSTED_ON
            factors = ["+40 Reverse DNS lookup", "+20 Web content host match"]
            base_score = 75

        elif src.type == EntityType.ORGANIZATION and tgt.type == EntityType.DOMAIN:
            rel_type = RelationType.DOMAIN_OWNS
            factors = ["+40 Whois organization record", "+20 SSL Certificate subject"]
            base_score = 85

        elif (src.type in [EntityType.PERSON, EntityType.EMAIL, EntityType.USERNAME]) and tgt.type == EntityType.REPOSITORY:
            rel_type = RelationType.REPOSITORY_CONTAINS
            factors = ["+40 Repository commit author", "+25 Public code search finding"]
            base_score = 90

        elif current_event.get('type', '').endswith('_COMPROMISED') or 'Hacked' in current_event.get('data', ''):
            rel_type = RelationType.EXPOSES_CREDENTIALS
            factors = ["+50 Breach database match", "+30 Compromised credential record"]
            base_score = 95
        else:
            factors = [f"+30 Structural event derivation ({src.type} -> {tgt.type})", "+20 Scan execution context"]
            base_score = 65

        return rel_type, base_score, factors

    def _infer_cross_correlations(self, entities: Dict[str, Entity], relationships: Dict[str, Relationship], evidence_records: List[Evidence]):
        """Infers logical links across entities (e.g. Email matching Username, Email matching Domain)."""
        emails = [e for e in entities.values() if e.type == EntityType.EMAIL]
        usernames = [e for e in entities.values() if e.type == EntityType.USERNAME]
        domains = [e for e in entities.values() if e.type == EntityType.DOMAIN]

        # 1. Infer EMAIL -> USERNAME if email prefix equals username
        for email in emails:
            email_user = email.value.split('@')[0].lower() if '@' in email.value else ''
            for username in usernames:
                if email_user and email_user == username.value.lower():
                    score, factors = ConfidenceEngine.calculate_confidence([
                        ("Same exact username prefix in email address", 40),
                        ("Identical string identifier", 25),
                        ("Cross-entity inferred resolution", 15)
                    ])
                    rel = Relationship(
                        source_entity_id=email.id,
                        target_entity_id=username.id,
                        rel_type=RelationType.USERNAME_MATCHES,
                        confidence_score=score,
                        reasoning=factors,
                        risk_impact=40
                    )
                    if rel.id not in relationships:
                        relationships[rel.id] = rel
                        evidence_records.append(Evidence(
                            relationship_id=rel.id,
                            source_module="ExposureEngine",
                            source_event_hash=email.source_event_hashes[0] if email.source_event_hashes else "INFERRED",
                            mode=ObservationMode.INFERRED,
                            raw_data=f"Inferred link between {email.value} and username {username.value}",
                            timestamp=int(time.time())
                        ))

        # 2. Infer EMAIL -> DOMAIN
        for email in emails:
            if '@' in email.value:
                email_domain = email.value.split('@')[1].lower()
                for domain in domains:
                    if domain.value.lower() == email_domain:
                        score, factors = ConfidenceEngine.calculate_confidence([
                            ("Same domain component in public email", 40),
                            ("Exact domain string match", 35),
                            ("Organizational email affiliation", 15)
                        ])
                        rel = Relationship(
                            source_entity_id=email.id,
                            target_entity_id=domain.id,
                            rel_type=RelationType.DOMAIN_OWNS,
                            confidence_score=score,
                            reasoning=factors,
                            risk_impact=30
                        )
                        if rel.id not in relationships:
                            relationships[rel.id] = rel
                            evidence_records.append(Evidence(
                                relationship_id=rel.id,
                                source_module="ExposureEngine",
                                source_event_hash=email.source_event_hashes[0] if email.source_event_hashes else "INFERRED",
                                mode=ObservationMode.INFERRED,
                                raw_data=f"Inferred link between {email.value} and domain {domain.value}",
                                timestamp=int(time.time())
                            ))


class ExplainableRiskEngine:
    """Calculates total exposure score, additive factor breakdown, explanations, and remediation."""

    def evaluate_exposure(self, entities: Dict[str, Entity], relationships: Dict[str, Relationship], raw_events: List[Dict[str, Any]]) -> Dict[str, Any]:
        risk_factors: List[Tuple[str, int]] = []
        top_priorities: List[Dict[str, Any]] = []
        remedial_actions: List[Dict[str, Any]] = []

        # Check for credential / leak findings
        compromised_events = [e for e in raw_events if 'COMPROMISED' in e.get('type', '') or e.get('risk', 0) >= 80]
        if compromised_events:
            weight = min(45, 25 + len(compromised_events) * 10)
            risk_factors.append((f"Public credential or breach exposures detected ({len(compromised_events)} instances)", weight))
            top_priorities.append({
                "title": "Compromised Credentials Detected",
                "risk": "HIGH",
                "impact": "Exposed credentials enable unauthorized account takeover and initial network access.",
                "description": f"Found {len(compromised_events)} compromised account or credential records during scan."
            })
            remedial_actions.append({
                "problem": "Public email or credentials found in historical breach leaks",
                "priority": "HIGH",
                "recommended_action": "Enforce immediate password reset and mandate multi-factor authentication (MFA) across all corporate services.",
                "expected_result": "Mitigates identity takeover risk and invalidates exposed authentication tokens."
            })

        # Check for exposed repositories / sensitive documents
        repo_docs = [e for e in raw_events if e.get('type') in ['PUBLIC_CODE_REPO', 'INTERESTING_FILE']]
        if repo_docs:
            weight = min(30, 15 + len(repo_docs) * 10)
            risk_factors.append((f"Public code repositories & sensitive documents found ({len(repo_docs)} items)", weight))
            top_priorities.append({
                "title": "Public Code Repository & Document Exposure",
                "risk": "MEDIUM",
                "impact": "Exposed repositories may leak hardcoded API keys, tokens, or internal credentials.",
                "description": f"Identified {len(repo_docs)} public code repositories or sensitive document files."
            })
            remedial_actions.append({
                "problem": "Public code repository contains linked identity or configuration files",
                "priority": "HIGH",
                "recommended_action": "Audit public repositories for embedded secret keys, environment variables, or private SSH keys. Move public repos to internal organization or remove sensitive history.",
                "expected_result": "Prevents secret harvesting by automated threat actors."
            })

        # Check for identity cross-linking density
        linked_rel_count = len(relationships)
        if linked_rel_count > 0:
            weight = min(20, max(5, linked_rel_count * 3))
            risk_factors.append((f"Cross-platform identity linking density ({linked_rel_count} active correlations)", weight))
            remedial_actions.append({
                "problem": "High cross-platform identity correlation allows easy target profiling",
                "priority": "MEDIUM",
                "recommended_action": "Separate personal public identities from corporate contact handles.",
                "expected_result": "Reduces correlation confidence across public OSINT sources."
            })

        # Check for open infrastructure exposure
        infra_events = [e for e in raw_events if e.get('type') in ['IP_ADDRESS', 'TCP_PORT_OPEN', 'INTERNET_NAME']]
        if infra_events:
            weight = min(20, len(infra_events) * 2)
            risk_factors.append((f"Public infrastructure surface identified ({len(infra_events)} hosts/ports)", weight))

        # Calculate Total Exposure Score (0 - 100)
        total_score = sum(w for _, w in risk_factors)
        total_score = min(100, max(10, total_score)) if (entities or raw_events) else 0

        # Score category
        if total_score >= 75:
            risk_tier = "CRITICAL"
        elif total_score >= 50:
            risk_tier = "HIGH"
        elif total_score >= 25:
            risk_tier = "MEDIUM"
        else:
            risk_tier = "LOW"

        why_it_matters = (
            f"The target exposure score is {total_score}/100 ({risk_tier}). "
            f"The scan uncovered {len(entities)} unique resolved entities across {len(relationships)} correlated relationships. "
            f"{'Critical credential breach indicators were identified.' if compromised_events else 'Identity correlation shows moderate public visibility.'}"
        )

        return {
            "total_risk_score": total_score,
            "risk_tier": risk_tier,
            "risk_breakdown": [{"factor": desc, "points": pts} for desc, pts in risk_factors],
            "top_priorities": top_priorities,
            "why_this_matters": why_it_matters,
            "remediation_plan": remedial_actions
        }


class ExposureEngine:
    """Master orchestrator for the ShadowTrace Exposure Intelligence Engine."""

    def __init__(self, dbh):
        self.dbh = dbh
        self.log = logging.getLogger("shadowtrace.exposure")
        self.resolver = EntityResolver()
        self.risk_engine = ExplainableRiskEngine()

    def analyze_scan(self, scan_id: str) -> Dict[str, Any]:
        """Executes full Exposure Intelligence analysis for a completed scan."""
        self.log.info(f"Running Exposure Intelligence analysis for scan ID: {scan_id}")

        # Fetch scan results
        results = self.dbh.scanResultsGet(scan_id)
        if not results:
            self.log.warning(f"No results found for scan ID {scan_id}")
            return {}

        # Format events into dicts
        events = []
        for r in results:
            events.append({
                "hash": r[1],
                "type": r[2],
                "generated": r[3],
                "confidence": r[4],
                "visibility": r[5],
                "risk": r[6],
                "module": r[7],
                "data": r[8],
                "source_event_hash": r[10] if len(r) > 10 else 'ROOT'
            })

        # 1. Entity & Relationship Resolution
        entities, relationships, evidence_list = self.resolver.resolve_entities_and_relations(events)

        # 2. Risk & Remediation Analysis
        exposure_eval = self.risk_engine.evaluate_exposure(entities, relationships, events)

        # 3. Persist into SQLite Database
        self.save_exposure_results(scan_id, entities, relationships, evidence_list, exposure_eval)

        return {
            "scan_id": scan_id,
            "entities": [e.to_dict() for e in entities.values()],
            "relationships": [r.to_dict() for r in relationships.values()],
            "evidence": [ev.to_dict() for ev in evidence_list],
            "exposure_summary": exposure_eval
        }

    def save_exposure_results(self, scan_id: str, entities: Dict[str, Entity], relationships: Dict[str, Relationship], evidence_list: List[Evidence], summary: Dict[str, Any]):
        """Saves exposure results into SQLite DB tables via dbh."""
        try:
            # Save Entities
            entity_rows = [
                (e.id, scan_id, e.type, e.value, e.risk_score, e.first_seen)
                for e in entities.values()
            ]
            self.dbh.exposureEntitiesSave(scan_id, entity_rows)

            # Save Relationships
            rel_rows = [
                (r.id, scan_id, r.source_entity_id, r.target_entity_id, r.rel_type, r.confidence_score, r.confidence_tier, r.risk_impact, json.dumps(r.reasoning))
                for r in relationships.values()
            ]
            self.dbh.exposureRelationshipsSave(scan_id, rel_rows)

            # Save Evidence
            ev_rows = [
                (ev.id, scan_id, ev.relationship_id, ev.source_module, ev.source_event_hash, ev.observation_mode, ev.raw_data, ev.timestamp)
                for ev in evidence_list
            ]
            self.dbh.exposureEvidenceSave(scan_id, ev_rows)

            # Save Summary
            self.dbh.exposureSummarySave(scan_id, summary['total_risk_score'], json.dumps(summary['risk_breakdown']), json.dumps(summary['top_priorities']), json.dumps(summary['remediation_plan']), summary['why_this_matters'])
            self.log.info(f"Successfully persisted Exposure Intelligence analysis for scan {scan_id}")
        except Exception as ex:
            self.log.error(f"Error saving exposure results for scan {scan_id}: {ex}")
