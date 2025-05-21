import unittest
from unittest.mock import patch, MagicMock, call
import socket
import time
import datetime

# Add project root to Python path
import os
import sys
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from src.fix_client import FixClient
import simplefix # Used for creating messages to be "received"

# Pre-mock datetime for consistent SendingTime (52)
MOCK_SENDING_TIME = "20230101-12:00:00.000"

@patch('src.fix_client.datetime', new_callable=MagicMock) # Mock entire datetime module used in fix_client
class TestFixClient(unittest.TestCase):

    def setUp(self, mock_datetime_module):
        # Configure the mock datetime.datetime.utcnow().strftime() to return a fixed string
        mock_dt_object = MagicMock()
        mock_dt_object.strftime.return_value = MOCK_SENDING_TIME
        mock_datetime_module.datetime.utcnow.return_value = mock_dt_object
        
        self.host = 'localhost'
        self.port = 5001
        self.sender_comp_id = 'TESTSENDER'
        self.target_comp_id = 'TESTTARGET'
        self.heartbeat_interval = 30

        self.client = FixClient(
            self.host, self.port, self.sender_comp_id, self.target_comp_id, self.heartbeat_interval
        )
        # Mock logger to suppress log output during tests unless specifically testing logging
        self.mock_logger = MagicMock()
        # To use this, you'd need to patch 'src.fix_client.logger'
        # For now, assuming fix_client.py's logger is not directly part of its public interface for testing.
        # If logging is critical to test, patch it: @patch('src.fix_client.logger', new_callable=MagicMock) in test method

    def _get_mock_socket(self):
        mock_sock = MagicMock(spec=socket.socket)
        return mock_sock

    @patch('src.fix_client.socket.socket')
    def test_connect_successful(self, mock_socket_constructor, mock_datetime_module):
        mock_sock_instance = self._get_mock_socket()
        mock_socket_constructor.return_value = mock_sock_instance

        self.assertTrue(self.client.connect())
        mock_socket_constructor.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
        mock_sock_instance.connect.assert_called_once_with((self.host, self.port))
        self.assertIsNotNone(self.client.sock)
        self.assertEqual(self.client.sock, mock_sock_instance)

    @patch('src.fix_client.socket.socket')
    def test_connect_failure(self, mock_socket_constructor, mock_datetime_module):
        mock_sock_instance = self._get_mock_socket()
        mock_sock_instance.connect.side_effect = socket.error("Connection refused")
        mock_socket_constructor.return_value = mock_sock_instance

        self.assertFalse(self.client.connect())
        mock_sock_instance.connect.assert_called_once_with((self.host, self.port))
        self.assertIsNone(self.client.sock)

    @patch('src.fix_client.FixClient._send_raw_message') # Mock the lowest level send
    def test_logon_message_construction_and_send(self, mock_send_raw, mock_datetime_module):
        self.client.sock = self._get_mock_socket() # Simulate connected state
        mock_send_raw.return_value = True # Assume send is successful

        self.client.logon()

        mock_send_raw.assert_called_once()
        sent_bytes = mock_send_raw.call_args[0][0]
        
        # Decode and verify parts of the message
        # Note: simplefix.FixParser can also be used to parse this if preferred
        sent_msg_str = sent_bytes.decode()
        self.assertIn("8=FIX.4.4", sent_msg_str)
        self.assertIn(f"49={self.sender_comp_id}", sent_msg_str)
        self.assertIn(f"56={self.target_comp_id}", sent_msg_str)
        self.assertIn("35=A", sent_msg_str) # Logon
        self.assertIn(f"108={self.heartbeat_interval}", sent_msg_str) # HeartBtInt
        self.assertIn("34=1", sent_msg_str) # Initial sequence number
        self.assertIn(f"52={MOCK_SENDING_TIME}", sent_msg_str) # SendingTime
        self.assertEqual(self.client.outgoing_seq_num, 2) # Incremented after send

    @patch('src.fix_client.FixClient._send_raw_message')
    def test_logout_message_when_active(self, mock_send_raw, mock_datetime_module):
        self.client.sock = self._get_mock_socket()
        self.client.session_active = True # Must be active to send logout
        mock_send_raw.return_value = True
        initial_seq_num = self.client.outgoing_seq_num

        self.client.logout()

        mock_send_raw.assert_called_once()
        sent_bytes = mock_send_raw.call_args[0][0]
        sent_msg_str = sent_bytes.decode()

        self.assertIn("35=5", sent_msg_str) # Logout
        self.assertIn(f"34={initial_seq_num}", sent_msg_str)
        self.assertEqual(self.client.outgoing_seq_num, initial_seq_num + 1)
        # self.assertFalse(self.client.session_active) # Logout *sending* doesn't make session inactive immediately

    @patch('src.fix_client.FixClient._send_raw_message')
    def test_logout_not_sent_when_inactive(self, mock_send_raw, mock_datetime_module):
        self.client.sock = self._get_mock_socket()
        self.client.session_active = False # Ensure inactive

        self.client.logout()
        mock_send_raw.assert_not_called()

    @patch('src.fix_client.FixClient._send_raw_message')
    def test_send_message_increments_sequence_and_header(self, mock_send_raw, mock_datetime_module):
        self.client.sock = self._get_mock_socket()
        mock_send_raw.return_value = True
        
        msg = simplefix.FixMessage()
        msg.append_pair(35, "D") # NewOrderSingle

        # Send first message
        self.client.send_message(msg)
        mock_send_raw.assert_called_once()
        sent_bytes1 = mock_send_raw.call_args[0][0]
        self.assertIn(f"34=1", sent_bytes1.decode())
        self.assertIn(f"52={MOCK_SENDING_TIME}", sent_bytes1.decode())
        self.assertEqual(self.client.outgoing_seq_num, 2)

        # Send second message
        msg2 = simplefix.FixMessage()
        msg2.append_pair(35, "0") # Heartbeat
        self.client.send_message(msg2)
        self.assertEqual(mock_send_raw.call_count, 2)
        sent_bytes2 = mock_send_raw.call_args[0][0]
        self.assertIn(f"34=2", sent_bytes2.decode())
        self.assertEqual(self.client.outgoing_seq_num, 3)

    def test_receive_message_decoding_and_handling(self, mock_datetime_module):
        self.client.sock = self._get_mock_socket()
        
        # Simulate receiving a Heartbeat message
        hb_msg = simplefix.FixMessage()
        hb_msg.append_pair(8, "FIX.4.4")
        hb_msg.append_pair(35, "0") # Heartbeat
        hb_msg.append_pair(49, self.target_comp_id) # Server is sender
        hb_msg.append_pair(56, self.sender_comp_id) # We are target
        hb_msg.append_pair(34, 1) # Server's sequence number
        hb_msg.append_pair(52, MOCK_SENDING_TIME)
        encoded_hb = hb_msg.encode()

        self.client.sock.recv.return_value = encoded_hb
        self.client.incoming_seq_num = 1 # Expecting 1

        # Patch _handle_incoming_message to verify it's called
        with patch.object(self.client, '_handle_incoming_message') as mock_handle_incoming:
            received_message = self.client.receive_message()
            
            self.assertIsNotNone(received_message)
            self.assertEqual(received_message.get_value(35), "0")
            mock_handle_incoming.assert_called_once_with(received_message)
            self.client.sock.recv.assert_called_once()

    def test_handle_incoming_logon_confirmation(self, mock_datetime_module):
        logon_confirm_msg = simplefix.FixMessage()
        logon_confirm_msg.append_pair(35, "A") # Logon
        logon_confirm_msg.append_pair(34, 1)
        logon_confirm_msg.append_pair(108, "45") # Server proposes new heartbeat interval
        
        self.client.incoming_seq_num = 1
        self.client._handle_incoming_message(logon_confirm_msg)
        
        self.assertTrue(self.client.session_active)
        self.assertEqual(self.client.heartbeat_interval, 45)
        self.assertEqual(self.client.incoming_seq_num, 2)

    @patch('src.fix_client.FixClient.send_heartbeat')
    def test_handle_incoming_test_request(self, mock_send_hb, mock_datetime_module):
        test_req_msg = simplefix.FixMessage()
        test_req_msg.append_pair(35, "1") # TestRequest
        test_req_msg.append_pair(34, 1)
        test_req_msg.append_pair(112, "TestReqID123") # TestReqID
        
        self.client.incoming_seq_num = 1
        self.client._handle_incoming_message(test_req_msg)
        
        mock_send_hb.assert_called_once_with(test_req_id="TestReqID123")
        self.assertEqual(self.client.incoming_seq_num, 2)

    def test_handle_incoming_sequence_reset_reset(self, mock_datetime_module):
        seq_reset_msg = simplefix.FixMessage()
        seq_reset_msg.append_pair(35, "4") # SequenceReset
        seq_reset_msg.append_pair(34, 1) # This message's sequence number
        seq_reset_msg.append_pair(36, "5") # NewSeqNo - reset to 5
        seq_reset_msg.append_pair(123, "N") # GapFillFlag = N (or not present for Reset)

        self.client.incoming_seq_num = 1
        self.client._handle_incoming_message(seq_reset_msg)
        self.assertEqual(self.client.incoming_seq_num, 5) # Should be reset to NewSeqNo

    def test_handle_incoming_sequence_reset_gapfill(self, mock_datetime_module):
        seq_reset_msg = simplefix.FixMessage()
        seq_reset_msg.append_pair(35, "4") # SequenceReset
        seq_reset_msg.append_pair(34, 1) # This message's sequence number
        seq_reset_msg.append_pair(36, "5") # NewSeqNo - next expected is 5
        seq_reset_msg.append_pair(123, "Y") # GapFillFlag = Y

        self.client.incoming_seq_num = 1
        self.client._handle_incoming_message(seq_reset_msg)
        self.assertEqual(self.client.incoming_seq_num, 5) # Should be reset to NewSeqNo

    @patch('src.fix_client.time.time')
    @patch('src.fix_client.FixClient.send_heartbeat')
    def test_maintain_session_sends_heartbeat(self, mock_send_hb, mock_time, mock_datetime_module):
        self.client.sock = self._get_mock_socket()
        self.client.session_active = True
        
        # Simulate time passing to trigger heartbeat
        mock_time.return_value = self.client.last_sent_time + self.heartbeat_interval + 1
        
        self.client.maintain_session()
        mock_send_hb.assert_called_once()

    @patch('src.fix_client.time.time')
    @patch('src.fix_client.FixClient.send_test_request')
    def test_maintain_session_sends_test_request_on_timeout(self, mock_send_test_req, mock_time, mock_datetime_module):
        self.client.sock = self._get_mock_socket()
        self.client.session_active = True
        
        # Simulate time passing to trigger server timeout
        mock_time.return_value = self.client.last_received_time + (self.heartbeat_interval * 2.5) + 1
        
        self.client.maintain_session()
        mock_send_test_req.assert_called_once()

    @patch('src.fix_client.FixClient.send_logout')
    @patch('src.fix_client.FixClient.disconnect')
    def test_sequence_number_too_low_no_possdup(self, mock_disconnect, mock_send_logout, mock_datetime_module):
        low_seq_msg = simplefix.FixMessage()
        low_seq_msg.append_pair(35, "0") # Heartbeat
        low_seq_msg.append_pair(34, 1)   # Seq num 1
        # PossDupFlag(43) is NOT set to "Y"
        
        self.client.incoming_seq_num = 5 # Expecting 5
        self.client._handle_incoming_message(low_seq_msg)
        
        mock_send_logout.assert_called_once()
        mock_disconnect.assert_called_once()

    @patch('src.fix_client.FixClient.send_resend_request')
    def test_sequence_number_gap_sends_resend_request(self, mock_send_resend_req, mock_datetime_module):
        gap_msg = simplefix.FixMessage()
        gap_msg.append_pair(35, "0") # Heartbeat
        gap_msg.append_pair(34, 5)   # Received seq num 5
        
        self.client.incoming_seq_num = 2 # Expecting 2
        self.client._handle_incoming_message(gap_msg)
        
        # Should request messages from 2 (expected) up to 4 (one before received)
        mock_send_resend_req.assert_called_once_with(2, 4) 
        self.assertEqual(self.client.incoming_seq_num, 2) # Seq num should not advance yet


    @patch('src.fix_client.FixClient._send_raw_message')
    def test_send_reject_for_missing_required_tag(self, mock_send_raw, mock_datetime_module):
        # This test is more about a potential send_reject_message method, which is not fully implemented
        # in the provided FixClient. If it were, we'd test it here.
        # For now, this serves as a placeholder for future functionality.
        pass

    def tearDown(self):
        # Ensure client socket is cleaned up if not None to prevent ResourceWarnings in tests
        if self.client and self.client.sock:
            try:
                # If the socket is a MagicMock, it might not have a real close method
                # or it might be desirable not to call it.
                # However, if it's a real socket that somehow wasn't closed, this would be important.
                if hasattr(self.client.sock, 'close') and callable(self.client.sock.close):
                    self.client.sock.close()
            except Exception:
                pass # Ignore errors during test teardown socket closure
        self.client = None


if __name__ == '__main__':
    unittest.main()
