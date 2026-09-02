import pytest
import unittest

from modules.sfp_searchcode import sfp_searchcode
from sflib import ShadowTrace
from shadowtrace import ShadowTraceEvent, ShadowTraceTarget


@pytest.mark.usefixtures
class TestModuleIntegrationCodesearch(unittest.TestCase):

    @unittest.skip("todo")
    def test_handleEvent(self):
        sf = ShadowTrace(self.default_options)

        module = sfp_searchcode()
        module.setup(sf, dict())

        target_value = 'shadowtrace.net'
        target_type = 'DOMAIN_NAME'
        target = ShadowTraceTarget(target_value, target_type)
        module.setTarget(target)

        event_type = 'ROOT'
        event_data = 'example data'
        event_module = ''
        source_event = ''
        evt = ShadowTraceEvent(event_type, event_data, event_module, source_event)

        result = module.handleEvent(evt)

        self.assertIsNone(result)
