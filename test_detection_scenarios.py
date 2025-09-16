#!/usr/bin/env python3
"""
Test detection scenarios based on analys.md insights
This simulates different response patterns to test our detection logic
"""

import unittest
from unittest.mock import MagicMock
import sys
import os

# Add the current directory to the path to import cp.py functions
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cp import detect_tfa_requirement, extract_session_id

class TestDetectionLogic(unittest.TestCase):
    
    def test_tfa_detection_from_analysis(self):
        """Test TFA detection based on patterns from analys.md"""
        
        # Rumahweb TFA scenario from analysis
        rumahweb_response = '''
        <form action="https://lawu.iixcp.rumahweb.net:2083/cpsess0847709084/" method="post">
        <input type="text" name="tfatoken" id="tfatoken" class="std_textbox" placeholder="Security code">
        <p>Enter the security code for 'smkc7882'</p>
        '''
        
        self.assertTrue(detect_tfa_requirement(rumahweb_response, 200))
        
        # Regular login page (should not detect TFA)
        regular_response = '''
        <form action="/login/" method="post">
        <input type="text" name="user" placeholder="Username">
        <input type="password" name="pass" placeholder="Password">
        '''
        
        self.assertFalse(detect_tfa_requirement(regular_response, 200))
        
        # TFA with different wording
        tfa_response2 = '''
        <div>Security Code Required</div>
        <input type="text" placeholder="Enter verification code">
        '''
        
        self.assertTrue(detect_tfa_requirement(tfa_response2, 200))
    
    def test_session_id_extraction_from_analysis(self):
        """Test session ID extraction based on examples from analys.md"""
        
        # o2switch success example
        o2switch_url = "https://clean.o2switch.net:2083/cpsess7396142433/frontend/o2switch/index.html?=undefined&login=1&post_login=63681220858992"
        o2switch_response = "cPanel - Espace Technique"
        
        session_id = extract_session_id(o2switch_response, o2switch_url)
        self.assertEqual(session_id, "cpsess7396142433")
        
        # Kemenag government success example
        kemenag_url = "https://panel.kemenag.go.id:2083/cpsess4141401380/frontend/jupiter/index.html?login=1&post_login=4566716616417"
        kemenag_response = "cPanel - Tools"
        
        session_id = extract_session_id(kemenag_response, kemenag_url)
        self.assertEqual(session_id, "cpsess4141401380")
        
        # Rumahweb TFA example
        rumahweb_url = "https://lawu.iixcp.rumahweb.net:2083/cpsess0847709084/?=undefined&login=1&post_login=10214741844387"
        rumahweb_response = "Enter the security code"
        
        session_id = extract_session_id(rumahweb_response, rumahweb_url)
        self.assertEqual(session_id, "cpsess0847709084")
        
        # No session ID
        no_session_url = "https://example.com/login"
        no_session_response = "Login failed"
        
        session_id = extract_session_id(no_session_response, no_session_url)
        self.assertIsNone(session_id)

if __name__ == '__main__':
    unittest.main()