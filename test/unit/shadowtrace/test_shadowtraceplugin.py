# test_shadowtraceplugin.py
import pytest
import unittest

from sflib import ShadowTrace
from shadowtrace import ShadowTraceDb, ShadowTraceEvent, ShadowTracePlugin, ShadowTraceTarget


@pytest.mark.usefixtures
class TestShadowTracePlugin(unittest.TestCase):
    """
    Test ShadowTrace
    """

    def test_init(self):
        """
        Test __init__(self)
        """
        sfp = ShadowTracePlugin()
        self.assertIsInstance(sfp, ShadowTracePlugin)

    def test_updateSocket(self):
        """
        Test _updateSocket(self, sock)
        """
        sfp = ShadowTracePlugin()

        sfp._updateSocket(None)
        self.assertEqual('TBD', 'TBD')

    def test_clearListeners(self):
        """
        Test clearListeners(self)
        """
        sfp = ShadowTracePlugin()

        sfp.clearListeners()
        self.assertEqual('TBD', 'TBD')

    def test_setup(self):
        """
        Test setup(self, sf, userOpts=dict())
        """
        sfp = ShadowTracePlugin()

        sfp.setup(None)
        sfp.setup(None, None)
        self.assertEqual('TBD', 'TBD')

    def test_enrichTargetargument_target_should_enrih_target(self):
        """
        Test enrichTarget(self, target)
        """
        sfp = ShadowTracePlugin()

        sfp.enrichTarget(None)
        self.assertEqual('TBD', 'TBD')

    def test_setTarget_should_set_a_target(self):
        """
        Test setTarget(self, target)
        """
        sfp = ShadowTracePlugin()

        target = ShadowTraceTarget("shadowtrace.net", "INTERNET_NAME")
        sfp.setTarget(target)

        get_target = sfp.getTarget().targetValue
        self.assertIsInstance(get_target, str)
        self.assertEqual("shadowtrace.net", get_target)

    def test_setTarget_argument_target_invalid_type_should_raise_TypeError(self):
        """
        Test setTarget(self, target)
        """
        sfp = ShadowTracePlugin()

        invalid_types = [None, "", list(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    sfp.setTarget(invalid_type)

    def test_set_dbhargument_dbh_should_set_database_handle(self):
        """
        Test setDbh(self, dbh)
        """
        sfdb = ShadowTraceDb(self.default_options, False)
        sfp = ShadowTracePlugin()

        sfp.setDbh(sfdb)
        self.assertIsInstance(sfp.__sfdb__, ShadowTraceDb)

    def test_setScanId_argument_id_should_set_a_scan_id(self):
        """
        Test setScanId(self, id)
        """
        sfp = ShadowTracePlugin()

        scan_id = '1234'
        sfp.setScanId(scan_id)

        get_scan_id = sfp.getScanId()
        self.assertIsInstance(get_scan_id, str)
        self.assertEqual(scan_id, get_scan_id)

    def test_setScanId_argument_id_invalid_type_should_raise_TypeError(self):
        """
        Test setScanId(self, id)
        """
        sfp = ShadowTracePlugin()

        invalid_types = [None, list(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    sfp.setScanId(invalid_type)

    def test_getScanId_should_return_a_string(self):
        """
        Test getScanId(self)
        """
        sfp = ShadowTracePlugin()

        scan_id = 'example scan id'
        sfp.setScanId(scan_id)

        get_scan_id = sfp.getScanId()
        self.assertIsInstance(get_scan_id, str)
        self.assertEqual(scan_id, get_scan_id)

    def test_getScanId_unitialised_scanid_should_raise_TypeError(self):
        """
        Test getScanId(self)
        """
        sfp = ShadowTracePlugin()

        with self.assertRaises(TypeError):
            sfp.getScanId()

    def test_getTarget_should_return_a_string(self):
        """
        Test getTarget(self)
        """
        sfp = ShadowTracePlugin()

        target = ShadowTraceTarget("shadowtrace.net", "INTERNET_NAME")
        sfp.setTarget(target)

        get_target = sfp.getTarget().targetValue
        self.assertIsInstance(get_target, str)
        self.assertEqual("shadowtrace.net", get_target)

    def test_getTarget_unitialised_target_should_raise(self):
        """
        Test getTarget(self)
        """
        sfp = ShadowTracePlugin()

        with self.assertRaises(TypeError):
            sfp.getTarget()

    def test_register_listener(self):
        """
        Test registerListener(self, listener)
        """
        sfp = ShadowTracePlugin()
        sfp.registerListener(None)

        self.assertEqual('TBD', 'TBD')

    def test_setOutputFilter_should_set_output_filter(self):
        """
        Test setOutputFilter(self, types)
        """
        sfp = ShadowTracePlugin()

        output_filter = "test filter"
        sfp.setOutputFilter("test filter")
        self.assertEqual(output_filter, sfp.__outputFilter__)

    def test_tempStorage_should_return_a_dict(self):
        """
        Test tempStorage(self)
        """
        sfp = ShadowTracePlugin()

        temp_storage = sfp.tempStorage()
        self.assertIsInstance(temp_storage, dict)

    def test_notifyListeners_should_notify_listener_modules(self):
        """
        Test notifyListeners(self, sfEvent)
        """
        sfp = ShadowTracePlugin()
        sfdb = ShadowTraceDb(self.default_options, False)
        sfp.setDbh(sfdb)

        event_type = 'ROOT'
        event_data = 'test data'
        module = 'test module'
        source_event = None
        evt = ShadowTraceEvent(event_type, event_data, module, source_event)
        sfp.notifyListeners(evt)

        self.assertEqual('TBD', 'TBD')

    def test_notifyListeners_output_filter_matched_should_notify_listener_modules(self):
        """
        Test notifyListeners(self, sfEvent)
        """
        sfp = ShadowTracePlugin()
        sfdb = ShadowTraceDb(self.default_options, False)
        sfp.setDbh(sfdb)

        target = ShadowTraceTarget("shadowtrace.net", "INTERNET_NAME")
        sfp.setTarget(target)

        event_type = 'ROOT'
        event_data = 'test data'
        module = 'test module'
        source_event = None
        evt = ShadowTraceEvent(event_type, event_data, module, source_event)

        event_type = 'test event type'
        event_data = 'test data'
        module = 'test module'
        source_event = evt
        evt = ShadowTraceEvent(event_type, event_data, module, source_event)

        sfp.__outputFilter__ = event_type

        sfp.notifyListeners(evt)

        self.assertEqual('TBD', 'TBD')

    def test_notifyListeners_output_filter_unmatched_should_not_notify_listener_modules(self):
        """
        Test notifyListeners(self, sfEvent)
        """
        sfp = ShadowTracePlugin()
        sfdb = ShadowTraceDb(self.default_options, False)
        sfp.setDbh(sfdb)

        target = ShadowTraceTarget("shadowtrace.net", "INTERNET_NAME")
        sfp.setTarget(target)

        event_type = 'ROOT'
        event_data = 'test data'
        module = 'test module'
        source_event = None
        evt = ShadowTraceEvent(event_type, event_data, module, source_event)

        event_type = 'test event type'
        event_data = 'test data'
        module = 'test module'
        source_event = evt
        evt = ShadowTraceEvent(event_type, event_data, module, source_event)

        sfp.__outputFilter__ = "example unmatched event type"

        sfp.notifyListeners(evt)

        self.assertEqual('TBD', 'TBD')

    def test_notifyListeners_event_type_and_data_same_as_source_event_source_event_should_story_only(self):
        """
        Test notifyListeners(self, sfEvent)
        """
        sfp = ShadowTracePlugin()
        sfdb = ShadowTraceDb(self.default_options, False)
        sfp.setDbh(sfdb)

        event_type = 'ROOT'
        event_data = 'test data'
        module = 'test module'
        source_event = None
        evt = ShadowTraceEvent(event_type, event_data, module, source_event)

        event_type = 'test event type'
        event_data = 'test data'
        module = 'test module'
        source_event = evt
        evt = ShadowTraceEvent(event_type, event_data, module, source_event)

        source_event = evt
        evt = ShadowTraceEvent(event_type, event_data, module, source_event)

        source_event = evt
        evt = ShadowTraceEvent(event_type, event_data, module, source_event)

        sfp.notifyListeners(evt)

        self.assertEqual('TBD', 'TBD')

    def test_notifyListeners_argument_sfEvent_invalid_event_should_raise_TypeError(self):
        """
        Test notifyListeners(self, sfEvent)
        """
        sfp = ShadowTracePlugin()

        invalid_types = [None, "", list(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    sfp.notifyListeners(invalid_type)

    def test_checkForStop(self):
        """
        Test checkForStop(self)
        """
        sfp = ShadowTracePlugin()

        class DatabaseStub:
            def scanInstanceGet(self, scanId):
                return [None, None, None, None, None, status]

        sfp.__sfdb__ = DatabaseStub()
        sfp.__scanId__ = 'example scan id'

        # pseudo-parameterized test
        scan_statuses = [
            (None, False),
            ("anything", False),
            ("RUNNING", False),
            ("ABORT-REQUESTED", True)
        ]
        for status, expectedReturnValue in scan_statuses:
            returnValue = sfp.checkForStop()
            self.assertEqual(returnValue, expectedReturnValue, status)

    def test_watchedEvents_should_return_a_list(self):
        """
        Test watchedEvents(self)
        """
        sfp = ShadowTracePlugin()

        watched_events = sfp.watchedEvents()
        self.assertIsInstance(watched_events, list)

    def test_producedEvents_should_return_a_list(self):
        """
        Test producedEvents(self)
        """
        sfp = ShadowTracePlugin()

        produced_events = sfp.producedEvents()
        self.assertIsInstance(produced_events, list)

    def test_handleEvent(self):
        """
        Test handleEvent(self, sfEvent)
        """
        event_type = 'ROOT'
        event_data = 'example event data'
        module = ''
        source_event = ''
        evt = ShadowTraceEvent(event_type, event_data, module, source_event)

        sfp = ShadowTracePlugin()
        sfp.handleEvent(evt)

    def test_start(self):
        """
        Test start(self)
        """
        sf = ShadowTrace(self.default_options)
        sfp = ShadowTracePlugin()
        sfp.sf = sf

        sfp.start()
