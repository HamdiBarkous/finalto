import unittest
from unittest.mock import patch, MagicMock, call, ANY # Ensure ANY is imported
import socket
import time
import datetime
import ssl # For SSL tests
import os  # For os.path.exists mock

# Add project root to Python path
# import os # This is redundant, but fine
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
        self.seq_num_file_path = "test_sequence_numbers.dat" # Default for most tests

        # Default client for non-SSL tests or tests that will override SSL settings
        self.client = FixClient(
            self.host, self.port, self.sender_comp_id, self.target_comp_id, 
            self.heartbeat_interval, use_ssl=False, # Explicitly False for default client
            seq_num_file_path=self.seq_num_file_path
        )
        # Mock logger to suppress log output during tests
        patcher = patch('src.fix_client.logger', MagicMock()) # Ensure logger is patched correctly
        self.addCleanup(patcher.stop)
        self.mock_fix_client_logger = patcher.start()


    def _get_mock_socket(self):
        mock_sock = MagicMock(spec=socket.socket)
        mock_sock.fileno.return_value = 123 
        return mock_sock

    # --- Non-SSL Connection Tests ---
    @patch('src.fix_client.socket.socket')
    def test_connect_successful_no_ssl(self, mock_socket_constructor, mock_datetime_module):
        mock_sock_instance = self._get_mock_socket()
        mock_socket_constructor.return_value = mock_sock_instance

        self.assertTrue(self.client.connect()) # self.client is non-SSL from setUp
        mock_socket_constructor.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
        mock_sock_instance.connect.assert_called_once_with((self.host, self.port))
        self.assertIsNotNone(self.client.sock)
        self.assertEqual(self.client.sock, mock_sock_instance)
        self.assertFalse(isinstance(self.client.sock, ssl.SSLSocket))

    @patch('src.fix_client.socket.socket')
    def test_connect_failure_no_ssl(self, mock_socket_constructor, mock_datetime_module):
        mock_sock_instance = self._get_mock_socket()
        mock_sock_instance.connect.side_effect = socket.error("Connection refused")
        mock_socket_constructor.return_value = mock_sock_instance
        
        self.assertFalse(self.client.connect()) # self.client is non-SSL
        mock_sock_instance.connect.assert_called_once_with((self.host, self.port))
        self.assertIsNone(self.client.sock)

    # --- SSL Connection Tests ---
    @patch('src.fix_client.os.path.exists')
    @patch('src.fix_client.ssl.SSLContext') # Patch within the module where it's used
    @patch('src.fix_client.socket.socket')
    def test_connect_ssl_enabled_basic(self, mock_socket_constructor, mock_SSLContext, mock_os_exists, mock_datetime_module):
        mock_plain_socket = self._get_mock_socket()
        mock_socket_constructor.return_value = mock_plain_socket
        
        mock_ssl_context_instance = MagicMock(spec=ssl.SSLContext)
        mock_SSLContext.return_value = mock_ssl_context_instance
        
        mock_secure_socket = MagicMock(spec=ssl.SSLSocket)
        mock_ssl_context_instance.wrap_socket.return_value = mock_secure_socket
        mock_secure_socket.cipher.return_value = ("AES256-GCM-SHA384", "TLSv1.3", 256)
        mock_secure_socket.version.return_value = "TLSv1.3"

        mock_os_exists.return_value = False # Assume no optional cert files exist for this basic test

        client_ssl = FixClient(self.host, self.port, self.sender_comp_id, self.target_comp_id, 
                               self.heartbeat_interval, use_ssl=True, seq_num_file_path=self.seq_num_file_path)
        
        self.assertTrue(client_ssl.connect())
        
        mock_socket_constructor.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
        mock_plain_socket.connect.assert_called_once_with((self.host, self.port))
        
        mock_SSLContext.assert_called_once_with(ssl.PROTOCOL_TLS_CLIENT)
        # Default: check_hostname is False, verify_mode is CERT_NONE if no CA certs
        self.assertFalse(mock_ssl_context_instance.check_hostname)
        self.assertEqual(mock_ssl_context_instance.verify_mode, ssl.CERT_NONE)
        mock_ssl_context_instance.wrap_socket.assert_called_once_with(mock_plain_socket, server_hostname=None)
        self.assertEqual(client_ssl.sock, mock_secure_socket)
        self.assertTrue(client_ssl.use_ssl)

    @patch('src.fix_client.os.path.exists')
    @patch('src.fix_client.ssl.SSLContext')
    @patch('src.fix_client.socket.socket')
    def test_connect_ssl_with_ca_verification(self, mock_socket_constructor, mock_SSLContext, mock_os_exists, mock_datetime_module):
        mock_plain_socket = self._get_mock_socket()
        mock_socket_constructor.return_value = mock_plain_socket
        mock_ssl_context_instance = mock_SSLContext.return_value # This is the MagicMock for the context instance
        mock_secure_socket = MagicMock(spec=ssl.SSLSocket)
        mock_ssl_context_instance.wrap_socket.return_value = mock_secure_socket
        mock_secure_socket.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_secure_socket.version.return_value = "TLSv1.3"

        ca_file_path = "/path/to/ca.pem"
        mock_os_exists.side_effect = lambda path: path == ca_file_path

        client_ssl_ca = FixClient(self.host, self.port, self.sender_comp_id, self.target_comp_id,
                                  self.heartbeat_interval, use_ssl=True, ssl_ca_certs=ca_file_path, 
                                  seq_num_file_path=self.seq_num_file_path)
        
        self.assertTrue(client_ssl_ca.connect())
        
        mock_SSLContext.assert_called_once_with(ssl.PROTOCOL_TLS_CLIENT)
        mock_ssl_context_instance.load_verify_locations.assert_called_once_with(cafile=ca_file_path)
        self.assertEqual(mock_ssl_context_instance.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(mock_ssl_context_instance.check_hostname)
        mock_ssl_context_instance.wrap_socket.assert_called_once_with(mock_plain_socket, server_hostname=self.host)

    @patch('src.fix_client.os.path.exists')
    @patch('src.fix_client.ssl.SSLContext')
    @patch('src.fix_client.socket.socket')
    def test_connect_ssl_with_client_certificate(self, mock_socket_constructor, mock_SSLContext, mock_os_exists, mock_datetime_module):
        mock_plain_socket = self._get_mock_socket()
        mock_socket_constructor.return_value = mock_plain_socket
        mock_ssl_context_instance = mock_SSLContext.return_value
        mock_secure_socket = MagicMock(spec=ssl.SSLSocket) 
        mock_ssl_context_instance.wrap_socket.return_value = mock_secure_socket
        mock_secure_socket.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_secure_socket.version.return_value = "TLSv1.3"

        client_cert_path = "/path/to/client.crt"
        client_key_path = "/path/to/client.key"
        
        mock_os_exists.side_effect = lambda path: path in [client_cert_path, client_key_path]

        client_ssl_client_cert = FixClient(self.host, self.port, self.sender_comp_id, self.target_comp_id,
                                           self.heartbeat_interval, use_ssl=True, 
                                           ssl_client_cert=client_cert_path, ssl_client_key=client_key_path,
                                           seq_num_file_path=self.seq_num_file_path)
        
        self.assertTrue(client_ssl_client_cert.connect())
        
        mock_SSLContext.assert_called_once_with(ssl.PROTOCOL_TLS_CLIENT)
        mock_ssl_context_instance.load_cert_chain.assert_called_once_with(certfile=client_cert_path, keyfile=client_key_path)
        # Default check_hostname is False if no CA certs, so server_hostname=None
        self.assertFalse(mock_ssl_context_instance.check_hostname) 
        mock_ssl_context_instance.wrap_socket.assert_called_once_with(mock_plain_socket, server_hostname=None) 

    @patch('src.fix_client.os.path.exists')
    @patch('src.fix_client.ssl.SSLContext')
    @patch('src.fix_client.socket.socket')
    def test_connect_ssl_ca_cert_file_not_found(self, mock_socket_constructor, mock_SSLContext, mock_os_exists, mock_datetime_module):
        mock_socket_constructor.return_value = self._get_mock_socket() 
        
        ca_file_path = "/path/to/non_existent_ca.pem"
        mock_os_exists.return_value = False # Simulate CA file does not exist

        client_ssl_file_missing = FixClient(self.host, self.port, self.sender_comp_id, self.target_comp_id,
                                            self.heartbeat_interval, use_ssl=True, ssl_ca_certs=ca_file_path,
                                            seq_num_file_path=self.seq_num_file_path)
        
        self.assertFalse(client_ssl_file_missing.connect()) 
        mock_SSLContext.assert_called_once_with(ssl.PROTOCOL_TLS_CLIENT)
        # Verify that load_verify_locations is NOT called because os.path.exists for it returns False
        mock_SSLContext.return_value.load_verify_locations.assert_not_called()
        # Check that the logger was called with a warning/error about the missing file
        self.mock_fix_client_logger.error.assert_any_call(f"SSL Error: CA certificate file '{ca_file_path}' not found.")


    @patch('src.fix_client.os.path.exists')
    @patch('src.fix_client.ssl.SSLContext')
    @patch('src.fix_client.socket.socket')
    def test_connect_ssl_client_cert_file_not_found(self, mock_socket_constructor, mock_SSLContext, mock_os_exists, mock_datetime_module):
        mock_socket_constructor.return_value = self._get_mock_socket()
        client_cert_path = "/path/to/client.crt"
        client_key_path = "/path/to/client.key"

        # Simulate only client cert exists, key does not
        mock_os_exists.side_effect = lambda path: path == client_cert_path 

        client_ssl_key_missing = FixClient(self.host, self.port, self.sender_comp_id, self.target_comp_id,
                                           self.heartbeat_interval, use_ssl=True, 
                                           ssl_client_cert=client_cert_path, ssl_client_key=client_key_path,
                                           seq_num_file_path=self.seq_num_file_path)
        
        self.assertFalse(client_ssl_key_missing.connect())
        mock_SSLContext.assert_called_once_with(ssl.PROTOCOL_TLS_CLIENT)
        mock_SSLContext.return_value.load_cert_chain.assert_not_called()
        self.mock_fix_client_logger.error.assert_any_call(f"SSL Error: Client certificate '{client_cert_path}' or key '{client_key_path}' not found.")


    @patch('src.fix_client.ssl.SSLContext')
    @patch('src.fix_client.socket.socket')
    def test_connect_ssl_handshake_failure(self, mock_socket_constructor, mock_SSLContext, mock_datetime_module):
        mock_plain_socket = self._get_mock_socket()
        mock_socket_constructor.return_value = mock_plain_socket
        
        mock_ssl_context_instance = mock_SSLContext.return_value
        mock_ssl_context_instance.wrap_socket.side_effect = ssl.SSLError("Mocked Handshake failed")

        client_ssl_handshake_fail = FixClient(self.host, self.port, self.sender_comp_id, self.target_comp_id,
                                              self.heartbeat_interval, use_ssl=True,
                                              seq_num_file_path=self.seq_num_file_path)
        
        self.assertFalse(client_ssl_handshake_fail.connect())
        self.assertIsNone(client_ssl_handshake_fail.sock) 
        self.mock_fix_client_logger.error.assert_any_call(
            f"SSL handshake failed when connecting to {self.host}:{self.port}: Mocked Handshake failed", exc_info=True
        )

    # --- Remaining tests should use self.client (non-SSL by default) ---
    @patch('src.fix_client.FixClient._send_raw_message') 
    def test_logon_message_construction_and_send(self, mock_send_raw, mock_datetime_module):
        # Uses self.client which is non-SSL by default from setUp
        self.client.sock = self._get_mock_socket() 
        mock_send_raw.return_value = True 

        self.client.logon() # Test logon without reset

        mock_send_raw.assert_called_once()
        sent_bytes = mock_send_raw.call_args[0][0]
        
        sent_msg_str = sent_bytes.decode()
        self.assertIn("8=FIX.4.4", sent_msg_str)
        self.assertIn(f"49={self.sender_comp_id}", sent_msg_str)
        self.assertIn(f"56={self.target_comp_id}", sent_msg_str)
        self.assertIn("35=A", sent_msg_str) 
        self.assertIn(f"108={self.heartbeat_interval}", sent_msg_str) 
        self.assertIn("34=1", sent_msg_str) 
        self.assertNotIn("141=", sent_msg_str) # Ensure ResetSeqNumFlag is NOT set by default
        self.assertIn(f"52={MOCK_SENDING_TIME}", sent_msg_str) 
        self.assertEqual(self.client.outgoing_seq_num, 2)

    @patch('src.fix_client.FixClient._send_raw_message')
    @patch('src.fix_client.FixClient._save_sequence_numbers')
    def test_logon_with_reset_seq_num_flag(self, mock_save_seq, mock_send_raw, mock_datetime_module):
        self.client.sock = self._get_mock_socket()
        mock_send_raw.return_value = True
        self.client.outgoing_seq_num = 10 # Set to non-default to verify reset
        self.client.incoming_seq_num = 15 # Set to non-default

        self.client.logon(reset_seq_num_flag=True)

        mock_send_raw.assert_called_once()
        sent_bytes = mock_send_raw.call_args[0][0]
        sent_msg_str = sent_bytes.decode()
        self.assertIn("141=Y", sent_msg_str) # ResetSeqNumFlag must be Y
        
        # Sequence numbers should be reset AFTER sending the logon with 141=Y
        self.assertEqual(self.client.outgoing_seq_num, 1) 
        self.assertEqual(self.client.incoming_seq_num, 1)
        mock_save_seq.assert_called_once() # Ensure reset numbers are persisted

    @patch('src.fix_client.FixClient._send_raw_message')
    @patch('src.fix_client.FixClient._save_sequence_numbers') # Mock saving for this test too
    def test_logout_message_when_active_saves_seq_nums_on_disconnect(self, mock_save_seq, mock_send_raw, mock_datetime_module):
        self.client.sock = self._get_mock_socket()
        self.client.session_active = True 
        mock_send_raw.return_value = True
        initial_seq_num = self.client.outgoing_seq_num

        self.client.logout() 
        # Simulate server confirming logout which calls disconnect
        self.client.session_active = False # This would be set by _handle_incoming_message typically
        self.client.disconnect()


        mock_send_raw.assert_called_once() # For logout message
        sent_bytes = mock_send_raw.call_args[0][0]
        sent_msg_str = sent_bytes.decode()

        self.assertIn("35=5", sent_msg_str) 
        self.assertIn(f"34={initial_seq_num}", sent_msg_str)
        self.assertEqual(self.client.outgoing_seq_num, initial_seq_num + 1)
        mock_save_seq.assert_called_once() # Saved on disconnect

    @patch('src.fix_client.FixClient._send_raw_message')
    def test_logout_not_sent_when_inactive(self, mock_send_raw, mock_datetime_module):
        self.client.sock = self._get_mock_socket()
        self.client.session_active = False 

        self.client.logout()
        mock_send_raw.assert_not_called()

    @patch('src.fix_client.FixClient._send_raw_message')
    def test_send_message_increments_sequence_and_header(self, mock_send_raw, mock_datetime_module):
        self.client.sock = self._get_mock_socket()
        mock_send_raw.return_value = True
        
        msg = simplefix.FixMessage()
        msg.append_pair(35, "D") 

        self.client.send_message(msg)
        mock_send_raw.assert_called_once()
        sent_bytes1 = mock_send_raw.call_args[0][0]
        self.assertIn(f"34=1", sent_bytes1.decode())
        self.assertIn(f"52={MOCK_SENDING_TIME}", sent_bytes1.decode())
        self.assertEqual(self.client.outgoing_seq_num, 2)

        msg2 = simplefix.FixMessage()
        msg2.append_pair(35, "0") 
        self.client.send_message(msg2)
        self.assertEqual(mock_send_raw.call_count, 2)
        sent_bytes2 = mock_send_raw.call_args[0][0]
        self.assertIn(f"34=2", sent_bytes2.decode())
        self.assertEqual(self.client.outgoing_seq_num, 3)

    @patch('src.fix_client.FixClient._save_sequence_numbers')
    def test_receive_message_decoding_and_handling(self, mock_save_seq, mock_datetime_module):
        self.client.sock = self._get_mock_socket()
        
        hb_msg = simplefix.FixMessage()
        hb_msg.append_pair(8, "FIX.4.4")
        hb_msg.append_pair(35, "0") # Heartbeat
        hb_msg.append_pair(49, self.target_comp_id) 
        hb_msg.append_pair(56, self.sender_comp_id) 
        hb_msg.append_pair(34, 1) 
        hb_msg.append_pair(52, MOCK_SENDING_TIME)
        encoded_hb = hb_msg.encode()

        self.client.sock.recv.return_value = encoded_hb
        self.client.incoming_seq_num = 1 

        with patch.object(self.client, '_handle_incoming_message') as mock_handle_incoming:
            received_message = self.client.receive_message()
            
            self.assertIsNotNone(received_message)
            self.assertEqual(received_message.get_value(35), "0")
            mock_handle_incoming.assert_called_once_with(received_message)
            self.client.sock.recv.assert_called_once()
            # mock_save_seq.assert_called_once() # Not called on every message, but on disconnect/reset

    @patch('src.fix_client.FixClient._save_sequence_numbers')
    def test_handle_incoming_logon_confirmation(self, mock_save_seq, mock_datetime_module):
        logon_confirm_msg = simplefix.FixMessage()
        logon_confirm_msg.append_pair(35, "A") 
        logon_confirm_msg.append_pair(34, 1)
        logon_confirm_msg.append_pair(108, "45") 
        
        self.client.incoming_seq_num = 1
        self.client._handle_incoming_message(logon_confirm_msg)
        
        self.assertTrue(self.client.session_active)
        self.assertEqual(self.client.heartbeat_interval, 45)
        self.assertEqual(self.client.incoming_seq_num, 2)
        # mock_save_seq.assert_called_once() # Not necessarily called here

    @patch('src.fix_client.FixClient.send_heartbeat')
    def test_handle_incoming_test_request(self, mock_send_hb, mock_datetime_module):
        test_req_msg = simplefix.FixMessage()
        test_req_msg.append_pair(35, "1") 
        test_req_msg.append_pair(34, 1)
        test_req_msg.append_pair(112, "TestReqID123") 
        
        self.client.incoming_seq_num = 1
        self.client._handle_incoming_message(test_req_msg)
        
        mock_send_hb.assert_called_once_with(test_req_id="TestReqID123")
        self.assertEqual(self.client.incoming_seq_num, 2)

    def test_handle_incoming_sequence_reset_reset(self, mock_datetime_module):
        seq_reset_msg = simplefix.FixMessage()
        seq_reset_msg.append_pair(35, "4") 
        seq_reset_msg.append_pair(34, 1) 
        seq_reset_msg.append_pair(36, "5") 
        seq_reset_msg.append_pair(123, "N") 

        self.client.incoming_seq_num = 1
        self.client._handle_incoming_message(seq_reset_msg)
        self.assertEqual(self.client.incoming_seq_num, 5)

    def test_handle_incoming_sequence_reset_gapfill(self, mock_datetime_module):
        seq_reset_msg = simplefix.FixMessage()
        seq_reset_msg.append_pair(35, "4") 
        seq_reset_msg.append_pair(34, 1) 
        seq_reset_msg.append_pair(36, "5") 
        seq_reset_msg.append_pair(123, "Y") 

        self.client.incoming_seq_num = 1
        self.client._handle_incoming_message(seq_reset_msg)
        self.assertEqual(self.client.incoming_seq_num, 5)

    @patch('src.fix_client.time.time')
    @patch('src.fix_client.FixClient.send_heartbeat')
    def test_maintain_session_sends_heartbeat(self, mock_send_hb, mock_time, mock_datetime_module):
        self.client.sock = self._get_mock_socket()
        self.client.session_active = True
        
        mock_time.return_value = self.client.last_sent_time + self.heartbeat_interval + 1
        
        self.client.maintain_session()
        mock_send_hb.assert_called_once()

    @patch('src.fix_client.time.time')
    @patch('src.fix_client.FixClient.send_test_request')
    def test_maintain_session_sends_test_request_on_timeout(self, mock_send_test_req, mock_time, mock_datetime_module):
        self.client.sock = self._get_mock_socket()
        self.client.session_active = True
        
        mock_time.return_value = self.client.last_received_time + (self.heartbeat_interval * 2.5) + 1
        
        self.client.maintain_session()
        mock_send_test_req.assert_called_once()

    @patch('src.fix_client.FixClient.send_logout')
    @patch('src.fix_client.FixClient.disconnect')
    def test_sequence_number_too_low_no_possdup(self, mock_disconnect, mock_send_logout, mock_datetime_module):
        low_seq_msg = simplefix.FixMessage()
        low_seq_msg.append_pair(35, "0") 
        low_seq_msg.append_pair(34, 1)   
        
        self.client.incoming_seq_num = 5 
        self.client._handle_incoming_message(low_seq_msg)
        
        mock_send_logout.assert_called_once()
        mock_disconnect.assert_called_once()

    @patch('src.fix_client.FixClient.send_resend_request')
    def test_sequence_number_gap_sends_resend_request(self, mock_send_resend_req, mock_datetime_module):
        gap_msg = simplefix.FixMessage()
        gap_msg.append_pair(35, "0") 
        gap_msg.append_pair(34, 5)   
        
        self.client.incoming_seq_num = 2 
        self.client._handle_incoming_message(gap_msg)
        
        mock_send_resend_req.assert_called_once_with(2, 4) 
        self.assertEqual(self.client.incoming_seq_num, 2) 


    # --- Sequence Number Persistence Tests ---
    @patch('src.fix_client.os.path.exists')
    @patch('src.fix_client.open', new_callable=unittest.mock.mock_open, read_data="10,20")
    def test_load_sequence_numbers_file_exists_valid_data(self, mock_file_open, mock_path_exists, mock_datetime_module):
        mock_path_exists.return_value = True
        test_file_path = "test_seq_nums.dat"
        
        # Create client *after* patching open for its __init__ to use the mocked open
        client_with_seq_load = FixClient(self.host, self.port, self.sender_comp_id, self.target_comp_id, 
                                         seq_num_file_path=test_file_path)
        
        mock_path_exists.assert_called_once_with(test_file_path)
        mock_file_open.assert_called_once_with(test_file_path, 'r')
        self.assertEqual(client_with_seq_load.incoming_seq_num, 10)
        self.assertEqual(client_with_seq_load.outgoing_seq_num, 20)

    @patch('src.fix_client.os.path.exists')
    @patch('src.fix_client.open', new_callable=unittest.mock.mock_open, read_data="invalid,data")
    def test_load_sequence_numbers_file_exists_invalid_data(self, mock_file_open, mock_path_exists, mock_datetime_module):
        mock_path_exists.return_value = True
        test_file_path = "test_seq_nums_invalid.dat"
        
        client_invalid_load = FixClient(self.host, self.port, self.sender_comp_id, self.target_comp_id, 
                                        seq_num_file_path=test_file_path)
        
        self.assertEqual(client_invalid_load.incoming_seq_num, 1) # Should default to 1
        self.assertEqual(client_invalid_load.outgoing_seq_num, 1) # Should default to 1
        self.mock_fix_client_logger.error.assert_any_call(
            f"Error loading sequence numbers from '{test_file_path}': Sequence numbers are not valid integers.. " # Note the double dot from original code
            "Starting with default sequence numbers (1,1).", exc_info=True
        )


    @patch('src.fix_client.os.path.exists')
    def test_load_sequence_numbers_file_not_exist(self, mock_path_exists, mock_datetime_module):
        mock_path_exists.return_value = False
        test_file_path = "non_existent_seq_nums.dat"
        
        client_no_file = FixClient(self.host, self.port, self.sender_comp_id, self.target_comp_id, 
                                   seq_num_file_path=test_file_path)
        
        self.assertEqual(client_no_file.incoming_seq_num, 1)
        self.assertEqual(client_no_file.outgoing_seq_num, 1)
        self.mock_fix_client_logger.info.assert_any_call(
            f"Sequence number file '{test_file_path}' not found. "
            "Starting with default sequence numbers (1,1). Will create file on graceful shutdown."
        )

    @patch('src.fix_client.os.makedirs')
    @patch('src.fix_client.open', new_callable=unittest.mock.mock_open)
    @patch('src.fix_client.os.path.exists') # Mock exists for directory check
    def test_save_sequence_numbers_success(self, mock_dir_exists, mock_file_open, mock_makedirs, mock_datetime_module):
        test_file_path = "data/test_save_seq.dat"
        # Simulate directory does not exist to test creation path
        mock_dir_exists.side_effect = lambda path: not (path == os.path.dirname(test_file_path)) 

        client_to_save = FixClient(self.host, self.port, self.sender_comp_id, self.target_comp_id, 
                                   seq_num_file_path=test_file_path)
        client_to_save.incoming_seq_num = 100
        client_to_save.outgoing_seq_num = 200
        
        client_to_save._save_sequence_numbers()
        
        expected_dir = os.path.dirname(test_file_path)
        if expected_dir: # Only assert if there's a directory part
             mock_dir_exists.assert_any_call(expected_dir) # Check if dir exists
             mock_makedirs.assert_called_once_with(expected_dir, exist_ok=True)
        
        mock_file_open.assert_called_once_with(test_file_path, 'w')
        mock_file_open().write.assert_called_once_with("100,200")

    @patch('src.fix_client.open', side_effect=IOError("Disk full"))
    def test_save_sequence_numbers_io_error(self, mock_file_open_io_error, mock_datetime_module):
        test_file_path = "data/test_save_io_error.dat"
        client_io_error = FixClient(self.host, self.port, self.sender_comp_id, self.target_comp_id, 
                                    seq_num_file_path=test_file_path)
        client_io_error.incoming_seq_num = 50
        client_io_error.outgoing_seq_num = 60
        
        client_io_error._save_sequence_numbers() # Call the method that should trigger the error
        
        self.mock_fix_client_logger.error.assert_any_call(
            f"Error saving sequence numbers to '{test_file_path}': Disk full", exc_info=True
        )

    @patch('src.fix_client.FixClient._send_raw_message')
    def test_send_reject_for_missing_required_tag(self, mock_send_raw, mock_datetime_module):
        pass

    def tearDown(self):
        if self.client and self.client.sock:
            try:
                if hasattr(self.client.sock, 'close') and callable(self.client.sock.close):
                    self.client.sock.close()
            except Exception:
                pass 
        self.client = None


if __name__ == '__main__':
    unittest.main()
