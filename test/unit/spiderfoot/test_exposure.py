# -*- coding: utf-8 -*-
import json
import unittest
from unittest.mock import MagicMock
from spiderfoot.exposure import (
    Entity,
    Relationship,
    Evidence,
    ConfidenceEngine,
    ConfidenceTier,
    EntityType,
    RelationType,
    ObservationMode,
    EntityResolver,
    ExplainableRiskEngine,
    ExposureEngine
)


class TestExposureIntelligenceEngine(unittest.TestCase):

    def setUp(self):
        self.raw_events = [
            {
                "hash": "hash_domain_1",
                "type": "DOMAIN_NAME",
                "data": "example.com",
                "generated": 1700000000,
                "risk": 10,
                "module": "sfp_dns",
                "source_event_hash": "ROOT"
            },
            {
                "hash": "hash_email_1",
                "type": "EMAILADDR",
                "data": "admin@example.com",
                "generated": 1700000005,
                "risk": 30,
                "module": "sfp_email",
                "source_event_hash": "hash_domain_1"
            },
            {
                "hash": "hash_user_1",
                "type": "USERNAME",
                "data": "admin",
                "generated": 1700000010,
                "risk": 20,
                "module": "sfp_accounts",
                "source_event_hash": "hash_email_1"
            },
            {
                "hash": "hash_leak_1",
                "type": "EMAILADDR_COMPROMISED",
                "data": "Hacked email admin@example.com found in breach",
                "generated": 1700000015,
                "risk": 90,
                "module": "sfp_hibp",
                "source_event_hash": "hash_email_1"
            },
            {
                "hash": "hash_repo_1",
                "type": "PUBLIC_CODE_REPO",
                "data": "https://github.com/admin/sec-config",
                "generated": 1700000020,
                "risk": 70,
                "module": "sfp_github",
                "source_event_hash": "hash_user_1"
            }
        ]

    def test_confidence_normalization(self):
        self.assertEqual(ConfidenceEngine.normalize_confidence(20), ConfidenceTier.WEAK)
        self.assertEqual(ConfidenceEngine.normalize_confidence(50), ConfidenceTier.POSSIBLE)
        self.assertEqual(ConfidenceEngine.normalize_confidence(75), ConfidenceTier.STRONG)
        self.assertEqual(ConfidenceEngine.normalize_confidence(95), ConfidenceTier.VERY_STRONG)

    def test_entity_resolver(self):
        resolver = EntityResolver()
        entities, relationships, evidence_list = resolver.resolve_entities_and_relations(self.raw_events)

        self.assertGreater(len(entities), 0)
        self.assertGreater(len(relationships), 0)
        self.assertGreater(len(evidence_list), 0)

        # Check entity values resolved
        entity_values = [e.value for e in entities.values()]
        self.assertIn("example.com", entity_values)
        self.assertIn("admin@example.com", entity_values)
        self.assertIn("admin", entity_values)

        # Check inferred cross correlation (admin@example.com -> username admin)
        rel_types = [r.rel_type for r in relationships.values()]
        self.assertIn(RelationType.USERNAME_MATCHES, rel_types)
        self.assertIn(RelationType.DOMAIN_OWNS, rel_types)

    def test_explainable_risk_engine(self):
        resolver = EntityResolver()
        entities, relationships, evidence_list = resolver.resolve_entities_and_relations(self.raw_events)
        
        risk_engine = ExplainableRiskEngine()
        summary = risk_engine.evaluate_exposure(entities, relationships, self.raw_events)

        self.assertIn("total_risk_score", summary)
        self.assertIn("risk_breakdown", summary)
        self.assertIn("remediation_plan", summary)
        self.assertIn("why_this_matters", summary)

        # Score should be high due to breach and repo leaks
        self.assertGreaterEqual(summary["total_risk_score"], 50)
        self.assertIn(summary["risk_tier"], ["HIGH", "CRITICAL"])
        self.assertGreater(len(summary["remediation_plan"]), 0)

    def test_exposure_engine_end_to_end(self):
        mock_dbh = MagicMock()
        mock_dbh.scanResultsGet.return_value = [
            (None, "hash_domain_1", "DOMAIN_NAME", 1700000000, 100, 100, 10, "sfp_dns", "example.com", 0, "ROOT"),
            (None, "hash_email_1", "EMAILADDR", 1700000005, 100, 100, 30, "sfp_email", "admin@example.com", 0, "hash_domain_1"),
        ]

        engine = ExposureEngine(mock_dbh)
        res = engine.analyze_scan("test_scan_123")

        self.assertEqual(res["scan_id"], "test_scan_123")
        self.assertIn("entities", res)
        self.assertIn("relationships", res)
        self.assertIn("exposure_summary", res)

        mock_dbh.exposureEntitiesSave.assert_called_once()
        mock_dbh.exposureRelationshipsSave.assert_called_once()
        mock_dbh.exposureSummarySave.assert_called_once()


if __name__ == '__main__':
    unittest.main()
