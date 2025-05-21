import simplefix
import socket
import datetime
import time
import logging

# Get a logger for this module
logger = logging.getLogger(__name__)

class FixClient:
    def __init__(self, host, port, sender_comp_id, target_comp_id, heartbeat_interval=30):
        self.host = host
        self.port = port
        self.sender_comp_id = sender_comp_id
        self.target_comp_id = target_comp_id
        self.sock = None
        self.parser = simplefix.FixParser()
        self.outgoing_seq_num = 1
        self.incoming_seq_num = 1 # Expected incoming sequence number
        self.session_active = False
        self.heartbeat_interval = heartbeat_interval # Configurable heartbeat interval
        self.last_sent_time = time.time()
        self.last_received_time = time.time()
        self.test_request_id = 0
        self.message_handlers = {} # For registering external handlers
        logger.info(f"FixClient initialized for {sender_comp_id} -> {target_comp_id} on {host}:{port} "
                    f"with Heartbeat: {heartbeat_interval}s")


    def connect(self):
        """Establishes a TCP connection to the FIX server."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.host, self.port))
            logger.info(f"Successfully connected to FIX server at {self.host}:{self.port}")
            self.last_sent_time = time.time()
            self.last_received_time = time.time()
            return True
        except socket.error as e:
            logger.error(f"Error connecting to FIX server {self.host}:{self.port}: {e}", exc_info=True)
            self.sock = None
            return False

    def _send_raw_message(self, message_bytes):
        """Sends raw bytes over the socket and updates last sent time."""
        if not self.sock:
            logger.error("Cannot send raw message: Not connected.")
            return False
        try:
            self.sock.sendall(message_bytes)
            self.last_sent_time = time.time()
            logger.debug(f"RawSent: {message_bytes.decode(errors='replace')}")
            return True
        except socket.error as e:
            logger.error(f"Error sending raw message: {e}", exc_info=True)
            # Consider session disconnect here if send fails critically
            self.disconnect() # Or a more nuanced error handling
            return False

    def send_message(self, message, is_admin=False):
        """Encodes and sends a simplefix.FixMessage object."""
        if not self.sock:
            logger.error("Cannot send FIX message: Not connected.")
            return False

        # Standard Header
        message.append_pair(8, "FIX.4.4", header=True) # BeginString
        message.append_pair(49, self.sender_comp_id, header=True) # SenderCompID
        message.append_pair(56, self.target_comp_id, header=True) # TargetCompID
        message.append_pair(34, self.outgoing_seq_num, header=True) # MsgSeqNum
        message.append_pair(52, datetime.datetime.utcnow().strftime("%Y%m%d-%H:%M:%S.%f")[:-3], header=True) # SendingTime

        # Ensure BodyLength (9) is correctly calculated and placed by simplefix before CheckSum (10)
        # simplefix handles BodyLength and CheckSum automatically on encode().
        encoded_message = message.encode()
        msg_type = message.get_value(35) # Get MsgType for logging
        
        logger.info(f"Sending MsgType {msg_type} (SeqNum {self.outgoing_seq_num})")
        logger.debug(f"Full Sent Msg: {encoded_message.decode(errors='replace').replace(simplefix.SOH, '|')}")

        if self._send_raw_message(encoded_message):
            self.outgoing_seq_num += 1
            return True
        logger.error(f"Failed to send MsgType {msg_type} (SeqNum {self.outgoing_seq_num -1}) due to _send_raw_message failure.")
        return False

    def logon(self):
        """Sends a Logon (35=A) message."""
        if not self.sock:
            logger.warning("Cannot send Logon: Not connected.")
            return False
            
        logon_msg = simplefix.FixMessage()
        logon_msg.append_pair(35, "A") # MsgType: Logon
        logon_msg.append_pair(98, 0)  # EncryptMethod: None
        logon_msg.append_pair(108, self.heartbeat_interval)  # HeartBtInt
        # Optional: ResetSeqNumFlag (141) could be added if needed, e.g., Y to reset sequence numbers
        # logon_msg.append_pair(141, "Y") 

        logger.info(f"Attempting Logon with HeartbeatInterval={self.heartbeat_interval}s")
        if self.send_message(logon_msg, is_admin=True):
            # Session becomes active only after receiving Logon confirmation from server
            # self.session_active = True # Tentatively set to active, confirm with server Logon
            logger.info("Logon message sent successfully.")
            return True
        logger.error("Failed to send Logon message.")
        return False

    def logout(self):
        """Sends a Logout (35=5) message."""
        if not self.session_active:
            logger.warning("Cannot send Logout: Session not active.")
            return False

        logout_msg = simplefix.FixMessage()
        logout_msg.append_pair(35, "5") # MsgType: Logout
        # Optional: Text (58) for reason for logout
        # logout_msg.append_pair(58, "Client requested logout")
        
        logger.info("Attempting Logout.")
        if self.send_message(logout_msg, is_admin=True):
            logger.info("Logout message sent successfully.")
            # self.session_active = False # Mark session as inactive after server confirms or timeout
            return True
        logger.error("Failed to send Logout message.")
        return False

    def disconnect(self):
        """Closes the TCP connection."""
        if self.sock:
            logger.info("Disconnecting from FIX server...")
            try:
                if self.session_active: 
                    logger.info("Session is active, attempting graceful logout before disconnect.")
                    # Note: logout() itself doesn't make session inactive immediately.
                    # Consider sending logout and then proceeding with disconnect regardless of immediate success,
                    # or have a short wait for server logout confirmation if protocol requires.
                    self.logout() # Attempt to send logout
                    # A short delay might be useful here if server confirmation is expected before socket closure
                    # time.sleep(0.1) 

                self.sock.shutdown(socket.SHUT_RDWR)
                self.sock.close()
                logger.info(f"Successfully disconnected from {self.host}:{self.port}.")
            except socket.error as e:
                logger.error(f"Error during disconnect from {self.host}:{self.port}: {e}", exc_info=True)
            except Exception as e: # Catch any other unexpected errors during disconnect
                logger.error(f"Unexpected error during disconnect: {e}", exc_info=True)
            finally:
                self.sock = None
                self.session_active = False # Ensure session is marked inactive
                logger.info(f"Session for {self.sender_comp_id} is now INACTIVE. Outgoing seq num reset to 1, Incoming to 1.")
                self.outgoing_seq_num = 1 # Reset sequence numbers for a new session
                self.incoming_seq_num = 1
        else:
            logger.info("Already disconnected or socket not initialized.")

    def receive_message(self, timeout=0.5):
        """Receives, decodes, and returns a simplefix.FixMessage object. Non-blocking with timeout."""
        if not self.sock:
            # logger.debug("receive_message called but not connected.") # Can be too noisy
            return None

        self.sock.settimeout(timeout)
        try:
            data = self.sock.recv(4096) # Read up to 4096 bytes
            if not data:
                logger.warning("Connection closed by server (received empty data).")
                self.disconnect() # Mark session inactive and cleanup
                return None
            
            self.last_received_time = time.time()
            logger.debug(f"RawRecv: {data.decode(errors='replace')}")
            self.parser.append_buffer(data)
            message = self.parser.get_message()
            
            if message:
                msg_type = message.get_value(35)
                seq_num = message.get_value(34)
                logger.info(f"Received MsgType {msg_type} (SeqNum {seq_num})")
                logger.debug(f"Full Recv Msg: {message.encode().decode(errors='replace').replace(simplefix.SOH, '|')}")
                
                self._handle_incoming_message(message) # Internal handling first
                
                # External callback handling
                if msg_type in self.message_handlers:
                    try:
                        logger.debug(f"Dispatching MsgType {msg_type} to registered handler.")
                        self.message_handlers[msg_type](message)
                    except Exception as e:
                        logger.error(f"Error in external message handler for MsgType {msg_type}: {e}", exc_info=True)
                
                return message
            return None # No complete message yet or only partial data
        except socket.timeout:
            # This is normal for a non-blocking receive, means no data within timeout
            # logger.debug("Socket timeout during receive_message.") # Can be very noisy
            return None
        except simplefix.FixParserError as e:
            logger.error(f"Error decoding FIX message: {e}", exc_info=True)
            # Potentially send a Reject message or handle appropriately
            # Example: self.send_reject_message(ref_seq_num="N/A", reason="Error decoding message")
            return None
        except socket.error as e:
            logger.error(f"Socket error receiving message: {e}", exc_info=True)
            self.disconnect() # Mark session inactive and cleanup
            return None
        except Exception as e: # Catch any other unexpected errors
            logger.error(f"Unexpected error in receive_message: {e}", exc_info=True)
            self.disconnect()
            return None


    def _handle_incoming_message(self, message):
        """Basic dispatcher for incoming messages. Handles session-level FIX messages."""
        msg_type = message.get_value(35)
        msg_seq_num_str = message.get_value(34)
        # Log all fields for DEBUG when a message is being handled internally
        if logger.isEnabledFor(logging.DEBUG):
            fields = []
            for i in range(message.count()):
                tag, value = message.get_pair_at_index(i)
                fields.append(f"{tag}={value}")
            logger.debug(f"Handling incoming message: {' | '.join(fields)}")

        if not msg_seq_num_str:
            logger.error("Received message without MsgSeqNum (34). Cannot process further for sequence checking.")
            # TODO: Send Reject message (Session level) for malformed message
            return
        
        try:
            msg_seq_num = int(msg_seq_num_str)
        except ValueError:
            logger.error(f"Received message with invalid MsgSeqNum (34): '{msg_seq_num_str}'. Cannot process.")
            # TODO: Send Reject message
            return

        # Sequence number check
        if msg_seq_num < self.incoming_seq_num:
            # This could be a retransmission of an already processed message, or an error.
            # FIX spec 7b: "If sequence number is less than expected and PossDupFlag is not set, it indicates a serious error..."
            poss_dup = message.get_value(43) == "Y" # PossDupFlag
            if poss_dup:
                logger.info(f"Received PossDup message with lower sequence number. Expected {self.incoming_seq_num}, got {msg_seq_num}. Ignoring.")
            else:
                logger.error(f"FATAL: Received message with sequence number ({msg_seq_num}) lower than expected ({self.incoming_seq_num}) "
                               f"and PossDupFlag (43) not set. This is a serious error. Disconnecting.")
                self.send_logout(text=f"FATAL: Received out of order sequence number {msg_seq_num}, expected {self.incoming_seq_num}")
                self.disconnect()
            return
        elif msg_seq_num > self.incoming_seq_num:
            logger.warning(f"Sequence gap detected. Expected {self.incoming_seq_num}, got {msg_seq_num}. Sending ResendRequest.")
            self.send_resend_request(self.incoming_seq_num, msg_seq_num -1) # Request from expected to one before received
            # Do not increment self.incoming_seq_num yet, wait for gap fill.
            return 

        # If msg_seq_num == self.incoming_seq_num, process and increment
        self.incoming_seq_num = msg_seq_num + 1
        logger.debug(f"Incoming sequence number now expected: {self.incoming_seq_num}")


        if msg_type == "A": # Logon
            logger.info("Logon (35=A) confirmation received from server.")
            self.session_active = True
            # Extract HeartBtInt from server's logon if provided (tag 108)
            server_hb_int_str = message.get_value(108)
            if server_hb_int_str:
                try:
                    server_hb_int = int(server_hb_int_str)
                    if server_hb_int > 0 and self.heartbeat_interval != server_hb_int:
                        logger.info(f"Server proposed HeartBtInt (108) of {server_hb_int}s. "
                                    f"Client using {self.heartbeat_interval}s. "
                                    "Using server's interval for heartbeat sending.")
                        # Per FIX spec, the Logon response's HeartBtInt dictates the interval for *this* session.
                        self.heartbeat_interval = server_hb_int
                    elif self.heartbeat_interval == server_hb_int:
                        logger.info(f"Server confirmed HeartBtInt (108) of {server_hb_int}s.")
                except ValueError:
                    logger.warning(f"Invalid HeartBtInt (108) received from server: '{server_hb_int_str}'. "
                                   f"Continuing with client's configured interval: {self.heartbeat_interval}s.")
            else:
                logger.info("Server did not specify HeartBtInt (108) in Logon. Using client's interval.")
            
            # TODO: Validate Sender/TargetCompID, etc. from message against expected.

        elif msg_type == "5": # Logout
            text_reason = message.get_value(58)
            logger.info(f"Logout (35=5) confirmation received from server. Reason: '{text_reason if text_reason else 'N/A'}'")
            self.session_active = False # Server confirmed logout
            self.disconnect() # Close connection as server acknowledged logout

        elif msg_type == "0": # Heartbeat
            logger.info("Heartbeat (35=0) received from server.")
            test_req_id = message.get_value(112)
            if test_req_id:
                 logger.info(f"Heartbeat is a response to TestRequestID (112): {test_req_id}")
            # No action needed other than updating last_received_time (done in receive_message)

        elif msg_type == "1": # TestRequest
            test_req_id = message.get_value(112) # TestReqID
            logger.info(f"TestRequest (35=1) received from server. TestReqID (112): '{test_req_id if test_req_id else 'N/A'}'")
            if test_req_id:
                self.send_heartbeat(test_req_id=test_req_id)
            else:
                logger.warning("TestRequest (35=1) received without TestReqID (112). Sending generic Heartbeat.")
                self.send_heartbeat()


        elif msg_type == "2": # ResendRequest
            begin_seq_no = message.get_value(7)
            end_seq_no = message.get_value(16)
            logger.warning(f"ResendRequest (35=2) received from server: BeginSeqNo(7)={begin_seq_no}, EndSeqNo(16)={end_seq_no}.")
            # TODO: Implement full ResendRequest handling (complex).
            # This involves resending messages from a certain sequence number.
            # For now, we might send a SequenceReset-GapFill if we can't resend,
            # or if the range is too large / not possible.
            # Example: If unable to resend, a GapFill could be sent.
            # self.send_sequence_reset_gap_fill(new_seq_num=self.outgoing_seq_num)
            logger.error("Full ResendRequest handling is not yet implemented. Sending SequenceReset-GapFill as placeholder.")
            self.send_sequence_reset_gap_fill(int(begin_seq_no), self.outgoing_seq_num)


        elif msg_type == "4": # SequenceReset
            new_seq_no_str = message.get_value(36) # NewSeqNo
            gap_fill_flag_str = message.get_value(123) # GapFillFlag (Y/N)
            poss_dup_flag_str = message.get_value(43) # PossDupFlag (Y/N)

            logger.info(f"SequenceReset (35=4) received: NewSeqNo(36)={new_seq_no_str}, "
                        f"GapFillFlag(123)={gap_fill_flag_str}, PossDupFlag(43)={poss_dup_flag_str}")
            
            if new_seq_no_str:
                try:
                    new_seq_no = int(new_seq_no_str)
                    if new_seq_no < self.incoming_seq_num and gap_fill_flag_str != 'Y':
                        logger.error(f"SequenceReset NewSeqNo ({new_seq_no}) is less than expected next "
                                     f"({self.incoming_seq_num}) and not GapFill. This is invalid. Disconnecting.")
                        self.send_logout(text="Invalid SequenceReset-Reset received.")
                        self.disconnect()
                        return

                    if gap_fill_flag_str == "Y": # Gap Fill mode
                        logger.info(f"SequenceReset (GapFill) processing. Setting next expected incoming MsgSeqNum to {new_seq_no}.")
                        self.incoming_seq_num = new_seq_no
                    else: # Reset mode (GapFillFlag='N' or not present)
                        logger.info(f"SequenceReset (Reset) processing. Setting next expected incoming AND outgoing MsgSeqNum to {new_seq_no}.")
                        # As per FIX spec: For SequenceReset-Reset, both sides should reset sequence numbers.
                        # This usually means client should also reset its outgoing seq number.
                        # However, this is often followed by a new Logon with ResetSeqNumFlag.
                        # For simplicity here, we only adjust incoming. A full implementation might need more.
                        self.incoming_seq_num = new_seq_no
                        # Potentially: self.outgoing_seq_num = new_seq_no (if client is expected to reset its outgoing too)
                        # logger.warning("SequenceReset-Reset implies client should also reset outgoing sequence. Consider implications.")
                except ValueError:
                    logger.error(f"Invalid NewSeqNo (36) in SequenceReset: '{new_seq_no_str}'.")
            else:
                logger.error("SequenceReset (35=4) received without NewSeqNo (36). Invalid message.")
        
        elif msg_type == "8": # ExecutionReport
            logger.info("ExecutionReport (35=8) received (will be passed to registered handler if any).")
            # Specific processing is delegated to the callback in TradeExecutor
        elif msg_type == "9": # OrderCancelReject
            logger.info("OrderCancelReject (35=9) received (will be passed to registered handler if any).")
            # Specific processing can be delegated
        elif msg_type == "3": # Reject (Session Level)
            ref_seq_num = message.get_value(45) # RefSeqNum - seq num of message being rejected
            ref_tag_id = message.get_value(371) # RefTagID - tag in rejected message causing issue
            ref_msg_type = message.get_value(372) # RefMsgType - type of message being rejected
            session_reject_reason = message.get_value(373) # SessionRejectReason
            text = message.get_value(58) # Text
            logger.error(f"Session Level Reject (35=3) received from server: RefSeqNum(45)={ref_seq_num}, "
                         f"RefTagID(371)={ref_tag_id}, RefMsgType(372)={ref_msg_type}, "
                         f"SessionRejectReason(373)={session_reject_reason}, Text(58)='{text}'")
            # Depending on the reason, might need to disconnect or take other action.
            # E.g., if reject reason is "Invalid MsgType" or "Required tag missing", etc.

        else:
            logger.warning(f"Unhandled FIX message type received: {msg_type}. Full message logged at DEBUG if enabled.")

    def send_heartbeat(self, test_req_id=None):
        """Sends a Heartbeat (35=0) message."""
        if not self.session_active:
            logger.debug("Cannot send Heartbeat: Session not active.") # Debug as this can be frequent
            return False

        heartbeat_msg = simplefix.FixMessage()
        heartbeat_msg.append_pair(35, "0") # MsgType: Heartbeat
        if test_req_id:
            heartbeat_msg.append_pair(112, test_req_id) # TestReqID (if responding to TestRequest)
        
        logger.info(f"Sending Heartbeat (TestReqID: {test_req_id if test_req_id else 'N/A'}).")
        if self.send_message(heartbeat_msg, is_admin=True):
            return True
        logger.error("Failed to send Heartbeat.")
        return False

    def send_test_request(self):
        """Sends a TestRequest (35=1) message to verify connection."""
        if not self.session_active:
            logger.warning("Cannot send TestRequest: Session not active.")
            return False
            
        self.test_request_id += 1
        current_test_req_id = f"TestReq_{self.sender_comp_id}_{self.test_request_id}"
        test_req_msg = simplefix.FixMessage()
        test_req_msg.append_pair(35, "1") # MsgType: TestRequest
        test_req_msg.append_pair(112, current_test_req_id) # TestReqID
        
        logger.info(f"Sending TestRequest (TestReqID(112): {current_test_req_id}).")
        if self.send_message(test_req_msg, is_admin=True):
            return True
        logger.error(f"Failed to send TestRequest (TestReqID(112): {current_test_req_id}).")
        return False

    def send_resend_request(self, begin_seq_num, end_seq_num=0):
        """Sends a ResendRequest (35=2) message."""
        # end_seq_num = 0 means resend all messages from begin_seq_num up to the latest
        if not self.session_active:
            logger.warning("Cannot send ResendRequest: Session not active.")
            return False

        resend_req_msg = simplefix.FixMessage()
        resend_req_msg.append_pair(35, "2") # MsgType: ResendRequest
        resend_req_msg.append_pair(7, begin_seq_num) # BeginSeqNo
        resend_req_msg.append_pair(16, end_seq_num) # EndSeqNo (0 for all subsequent)

        logger.info(f"Sending ResendRequest: BeginSeqNo(7)={begin_seq_num}, EndSeqNo(16)={end_seq_num}.")
        if self.send_message(resend_req_msg, is_admin=True):
            return True
        logger.error(f"Failed to send ResendRequest (BeginSeqNo: {begin_seq_num}, EndSeqNo: {end_seq_num}).")
        return False

    def send_sequence_reset_gap_fill(self, new_seq_num, gap_fill_msg_seq_num=None):
        """
        Sends a SequenceReset (35=4) in GapFill mode.
        This is sent by the sender of messages if they cannot resend requested messages.
        'new_seq_num' (Tag 36) is the sequence number of the *next* message to be sent *after* the gap.
        'gap_fill_msg_seq_num' (Tag 34 for this message) is the sequence number of this SequenceReset message itself,
        which should be the sequence number of the first message in the gap.
        """
        if not self.session_active:
            logger.warning("Cannot send SequenceReset-GapFill: Session not active.")
            return False

        seq_reset_msg = simplefix.FixMessage()
        seq_reset_msg.append_pair(35, "4") # MsgType: SequenceReset
        
        # For GapFill, MsgSeqNum (34) of this message should be the sequence number
        # of the first message being skipped (i.e., where the gap starts).
        # And NewSeqNo (36) is the sequence number of the next message to be transmitted *after* the gap.
        
        # This implementation is simplified: it uses the current outgoing_seq_num for tag 34.
        # A full implementation would need to allow setting tag 34 to 'gap_fill_msg_seq_num' if provided,
        # and then set self.outgoing_seq_num to new_seq_num.
        # If gap_fill_msg_seq_num is not None, it implies we are filling a gap starting at that number.
        # The message itself (SequenceReset) takes the place of the first missed message.
        
        # The current self.outgoing_seq_num will be used for tag 34 of this message.
        # NewSeqNo (36) tells the receiver what the *next* actual application message's sequence number will be.
        seq_reset_msg.append_pair(36, new_seq_num) # NewSeqNo
        seq_reset_msg.append_pair(123, "Y") # GapFillFlag: Yes
        # Optional: PossDupFlag(43)=Y if this SequenceReset itself is a retransmission.
        # seq_reset_msg.append_pair(43, "Y")


        logger.info(f"Sending SequenceReset (GapFill): MsgSeqNum(34) will be {self.outgoing_seq_num}, NewSeqNo(36)={new_seq_num}.")
        if self.send_message(seq_reset_msg, is_admin=True):
            logger.info(f"SequenceReset (GapFill) sent. Next outgoing app message SeqNum will be {new_seq_num}.")
            # Crucially, update our own outgoing_seq_num to match NewSeqNo for subsequent application messages.
            self.outgoing_seq_num = new_seq_num
            return True
        logger.error(f"Failed to send SequenceReset (GapFill) where NewSeqNo(36) would be {new_seq_num}.")
        return False

    def maintain_session(self):
        """Call this periodically to handle heartbeats and check session status."""
        if not self.sock: # If socket is None, we are definitely not connected.
            logger.debug("maintain_session: Socket is not initialized. Cannot maintain session.")
            return
        if not self.session_active:
            logger.debug("maintain_session: Session is not active. Cannot maintain session.")
            return

        now = time.time()
        
        # Check if we need to send a heartbeat
        if (now - self.last_sent_time) >= self.heartbeat_interval:
            logger.info(f"Heartbeat interval ({self.heartbeat_interval}s) reached. Sending Heartbeat.")
            self.send_heartbeat()
        
        # Check for server timeout
        # FIX spec recommends a timeout if no data received for some period (e.g., 2.5 * heartbeat_interval).
        # Some grace period should be allowed on top of heartbeat_interval.
        # For example, if interval is 30s, timeout check could be for 30s * 2.5 = 75s.
        timeout_threshold = self.heartbeat_interval * 2.5 
        if (now - self.last_received_time) > timeout_threshold:
            logger.warning(f"Server timeout suspected: No message received for over {now - self.last_received_time:.2f}s "
                           f"(threshold: {timeout_threshold}s). Sending TestRequest.")
            self.send_test_request()
            
            # Increased timeout check after sending TestRequest
            # If still no response after TestRequest + another grace period, consider it a stale connection.
            extended_timeout_threshold = self.heartbeat_interval * 3.5 
            if (now - self.last_received_time) > extended_timeout_threshold:
                 logger.error(f"FATAL: Still no response after TestRequest (total silence > {now - self.last_received_time:.2f}s). "
                              f"Disconnecting due to inactivity.")
                 self.disconnect() # Or trigger reconnection logic

    # Placeholder for SSL/TLS encryption
    def connect_secure(self):
        """Placeholder for establishing a secure SSL/TLS connection."""
        logger.warning("SSL/TLS connection (connect_secure) not implemented.")
        # This would involve wrapping the socket with ssl.wrap_socket()
        # e.g., self.sock = ssl.wrap_socket(self.sock, certfile=..., keyfile=..., ssl_version=...)
        pass

    # Placeholder for automatic reconnection
    def auto_reconnect(self):
        """Placeholder for automatic reconnection logic."""
        logger.warning("Automatic reconnection (auto_reconnect) not implemented.")
        # This would involve a loop trying to connect, potentially with backoff.
        pass

    # Placeholder for persisting sequence numbers
    def persist_sequence_numbers(self):
        """Placeholder for saving sequence numbers to disk."""
        logger.info("Persisting sequence numbers not implemented. Current outgoing: {self.outgoing_seq_num}, incoming: {self.incoming_seq_num}")
        # Typically, save self.outgoing_seq_num and self.incoming_seq_num to a file or database.
        pass

    def load_sequence_numbers(self):
        """Placeholder for loading sequence numbers from disk."""
        logger.info("Loading sequence numbers not implemented. Using defaults (1,1).")
        # Load sequence numbers and potentially set ResetSeqNumFlag(141)=Y in Logon if numbers are reset.
        pass

    def register_message_handler(self, msg_type, handler_callback):
        """Registers a callback function for a specific message type."""
        logger.info(f"Registering handler for MsgType {msg_type}: {handler_callback.__name__ if hasattr(handler_callback, '__name__') else str(handler_callback)}")
        self.message_handlers[msg_type] = handler_callback

    def unregister_message_handler(self, msg_type):
        """Unregisters a callback function for a specific message type."""
        if msg_type in self.message_handlers:
            logger.info(f"Unregistering handler for MsgType {msg_type}")
            del self.message_handlers[msg_type]
        else:
            logger.warning(f"No handler registered for MsgType {msg_type} to unregister.")

# Example usage (conceptual, for testing within this file if needed)
if __name__ == '__main__':
    # This is a basic self-test, not a full client-server interaction.
    # It requires a FIX echo server listening on localhost:5001
    
    # Setup basic logging for the self-test if not configured elsewhere
    if not logging.getLogger().hasHandlers(): # Check if root logger has handlers
        logging.basicConfig(level=logging.DEBUG, 
                            format='%(asctime)s - %(name)s - %(levelname)s - %(module)s - %(message)s',
                            handlers=[logging.StreamHandler()]) # Log to console for self-test

    logger.info("--- Starting FIX Client self-test ---")
    # Example of using the heartbeat_interval parameter
    client = FixClient(host='localhost', port=5001, sender_comp_id='TESTCLIENT', target_comp_id='TESTSERVER', heartbeat_interval=10) # Short for test
    logger.info(f"Self-test client configured with heartbeat interval: {client.heartbeat_interval}s")

    if client.connect():
        if client.logon():
            logger.info("Self-test: Logon successful. Waiting a bit...")
            
            # Simulate main loop for a short period
            test_duration = 25 # seconds
            loop_start_time = time.time()
            while client.session_active and (time.time() - loop_start_time) < test_duration:
                client.maintain_session()
                msg = client.receive_message(timeout=0.2)
                if msg:
                    logger.info(f"Self-test MainLoop: Received message: Type {msg.get_value(35)}")
                time.sleep(0.5) # Loop interval
            
            logger.info("Self-test: Simulated activity period ended.")

            # Explicitly send a Test Request if session is still up
            if client.session_active:
                logger.info("Self-test: Sending a TestRequest.")
                client.send_test_request()
                time.sleep(1) # Allow time for response
                client.receive_message(timeout=1.0) # Check for heartbeat response

            logger.info("Self-test: Attempting logout...")
            client.logout() # This sends logout, server should confirm
            
            # Wait for logout confirmation or timeout
            logout_confirm_wait_start = time.time()
            while client.session_active and (time.time() - logout_confirm_wait_start < 5): # 5s timeout for server logout
                 logger.debug("Self-test: Waiting for logout confirmation from server...")
                 client.receive_message(timeout=0.2)
                 time.sleep(0.2)
            
            if not client.session_active: # session_active becomes False if server Logout is processed OR if disconnect makes it so
                logger.info("Self-test: Logout appears successful (session no longer active).")
            else:
                logger.warning("Self-test: Session still active after logout attempt and wait period.")
        
        # Disconnect is called implicitly by _handle_incoming_message for server logout,
        # or explicitly if logon fails, or here if logout sequence doesn't fully complete.
        if client.sock: # If socket still exists (e.g. logout didn't lead to server disconnect)
            client.disconnect()
    else:
        logger.error("Self-test: Connection failed.")

    logger.info("--- FIX Client self-test finished ---")
