import simplefix
import uuid
import datetime
import time
import logging

# Get a logger for this module
logger = logging.getLogger(__name__)

# Define order status constants (as per FIX OrdStatus <39>)
ORDER_STATUS_NEW = '0'
ORDER_STATUS_PARTIALLY_FILLED = '1'
ORDER_STATUS_FILLED = '2'
ORDER_STATUS_DONE_FOR_DAY = '3' # Not typically used for single orders in this context, but exists
ORDER_STATUS_CANCELED = '4'
ORDER_STATUS_REPLACED = '5' # For order modifications
ORDER_STATUS_PENDING_CANCEL = '6'
ORDER_STATUS_STOPPED = '7' # Not used here
ORDER_STATUS_REJECTED = '8'
ORDER_STATUS_SUSPENDED = '9' # Not used here
ORDER_STATUS_PENDING_NEW = 'A'
ORDER_STATUS_CALCULATED = 'B' # Not used here
ORDER_STATUS_EXPIRED = 'C'
ORDER_STATUS_ACCEPTED_FOR_BIDDING = 'D' # Not used here
ORDER_STATUS_PENDING_REPLACE = 'E' # For order modifications

# Define ExecType constants (as per FIX ExecType <150>)
EXEC_TYPE_NEW = '0'
EXEC_TYPE_PARTIAL_FILL = '1'
EXEC_TYPE_FILL = '2'
EXEC_TYPE_DONE_FOR_DAY = '3' # As above
EXEC_TYPE_CANCELLED = '4'
EXEC_TYPE_REPLACE = '5' # As above
EXEC_TYPE_PENDING_CANCEL = '6'
EXEC_TYPE_REJECTED = '8'
EXEC_TYPE_SUSPENDED = '9' # As above
EXEC_TYPE_PENDING_NEW = 'A'
EXEC_TYPE_RESTATED = 'D' # Not common for client orders
EXEC_TYPE_PENDING_REPLACE = 'E'
EXEC_TYPE_TRADE = 'F' # Fill or partial fill
EXEC_TYPE_TRADE_CORRECT = 'G' # Not used here
EXEC_TYPE_TRADE_CANCEL = 'H' # Not used here
EXEC_TYPE_ORDER_STATUS = 'I' # Used to request order status

class TradeExecutor:
    def __init__(self, fix_client):
        self.fix_client = fix_client
        self.pending_orders = {}  # Stores orders by ClOrdID
        
        # Register the handler for ExecutionReport messages
        if self.fix_client:
            logger.info("Registering ExecutionReport (35=8) and OrderCancelReject (35=9) handlers with FixClient.")
            self.fix_client.register_message_handler("8", self.handle_execution_report)
            self.fix_client.register_message_handler("9", self.handle_order_cancel_reject) # For OrderCancelReject
        else:
            logger.warning("TradeExecutor initialized without a valid FixClient. Message handlers not registered.")

    def _generate_clordid(self):
        """Generates a unique client order ID."""
        return str(uuid.uuid4())

    def place_order(self, symbol: str, side: str, order_type: str, quantity: float, price: float = None, clordid: str = None):
        """
        Constructs and sends a NewOrderSingle (35=D) message.
        
        Args:
            symbol (str): Tag 55 (e.g., "EUR/USD")
            side (str): Tag 54 ('1' for Buy, '2' for Sell)
            order_type (str): Tag 40 ('1' for Market, '2' for Limit)
            quantity (float): Tag 38 (Order quantity)
            price (float, optional): Tag 44 (Required for Limit orders)
            clordid (str, optional): Tag 11 (Unique order ID). If None, generates one.
        
        Returns:
            str: The ClOrdID of the placed order, or None if sending failed.
        """
        if not self.fix_client or not self.fix_client.session_active:
            logger.error("Cannot place order: FIX client not connected or session not active.")
            return None

        if clordid is None:
            clordid = self._generate_clordid()
            logger.debug(f"Generated new ClOrdID: {clordid} for place_order request.")

        if order_type == '2' and price is None: # '2' is Limit order
            logger.error(f"Cannot place Limit order {clordid}: Price is required.")
            return None

        order_msg = simplefix.FixMessage()
        order_msg.append_pair(35, "D")  # MsgType: NewOrderSingle

        # Required fields
        order_msg.append_pair(11, clordid)  # ClOrdID
        order_msg.append_pair(55, symbol)  # Symbol
        order_msg.append_pair(54, side)  # Side (1=Buy, 2=Sell)
        order_msg.append_pair(60, datetime.datetime.utcnow().strftime("%Y%m%d-%H:%M:%S.%f")[:-3])  # TransactTime
        order_msg.append_pair(40, order_type)  # OrdType (1=Market, 2=Limit)
        order_msg.append_pair(38, quantity)  # OrderQty

        if order_type == '2':  # Limit order
            order_msg.append_pair(44, price)  # Price

        # Optional fields can be added here, e.g., TimeInForce (59)
        # order_msg.append_pair(59, "0") # Day Order (Day)
        # order_msg.append_pair(59, "1") # GTC (Good Till Cancel)

        log_msg_summary = (f"Placing order: ClOrdID={clordid}, Symbol={symbol}, Side={side}, "
                           f"Qty={quantity}, Type={order_type}, Price={price if price else 'N/A'}")
        logger.info(log_msg_summary)
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"Full NewOrderSingle message for {clordid}:\n{order_msg.encode().decode(errors='replace').replace(simplefix.SOH, '|')}")

        if self.fix_client.send_message(order_msg):
            self.pending_orders[clordid] = {
                "ClOrdID": clordid,
                "Symbol": symbol,
                "Side": side,
                "OrderQty": quantity,
                "OrdType": order_type,
                "Price": price,
                "OrdStatus": ORDER_STATUS_PENDING_NEW, # Initial status
                "CumQty": 0.0,
                "AvgPx": 0.0,
                "LeavesQty": quantity,
                "LastPx": 0.0,
                "LastQty": 0.0,
                "OrderID": None, # Will be populated by ExecutionReport
                "SubmissionTime": time.time()
            }
            logger.info(f"Order {clordid} sent successfully and marked as PENDING_NEW.")
            return clordid
        else:
            logger.error(f"Failed to send order {clordid}.")
            return None

    def handle_execution_report(self, message: simplefix.FixMessage):
        """
        Handles ExecutionReport (35=8) messages.
        This method is registered as a callback with FixClient.
        """
        clordid = message.get_value(11)  # ClOrdID
        orig_clordid = message.get_value(41) # OrigClOrdID (for cancels/replaces)
        order_id = message.get_value(37)    # OrderID (Broker's ID for the order)
        ord_status = message.get_value(39)  # OrdStatus
        exec_type = message.get_value(150)  # ExecType
        
        last_px_str = message.get_value(31) # LastPx
        last_qty_str = message.get_value(32) # LastShares (FIX < 4.4) or LastQty (FIX >= 4.4)
        cum_qty_str = message.get_value(14)  # CumQty
        avg_px_str = message.get_value(6)    # AvgPx
        leaves_qty_str = message.get_value(151) # LeavesQty
        text = message.get_value(58) # Text (reason for reject etc)

        log_er_summary = (
            f"ExecutionReport: ClOrdID={clordid}, OrigClOrdID={orig_clordid}, OrderID={order_id}, "
            f"OrdStatus={self._map_ord_status_to_text(ord_status)}({ord_status}), "
            f"ExecType={self._map_exec_type_to_text(exec_type)}({exec_type}), "
            f"CumQty={cum_qty_str}, AvgPx={avg_px_str}, LastQty={last_qty_str}, LastPx={last_px_str}, "
            f"LeavesQty={leaves_qty_str}, Text='{text}'"
        )
        logger.info(log_er_summary)
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"Full ExecutionReport message:\n{message.encode().decode(errors='replace').replace(simplefix.SOH, '|')}")
        
        # Determine which order to update (original or modification)
        target_clordid = clordid or orig_clordid # Prefer ClOrdID if present, else OrigClOrdID

        if not target_clordid:
            logger.error("ExecutionReport received without ClOrdID (11) or OrigClOrdID (41). Cannot process.")
            return

        order_data = self.pending_orders.get(target_clordid)
        if not order_data:
            logger.warning(f"Received ExecutionReport for unknown/untracked ClOrdID: {target_clordid}. It might be a stale or manual report. ER: {log_er_summary}")
            # Optionally create a new record if appropriate for the workflow.
            # For now, we'll ignore ERs for orders not initiated by this client instance's current pending_orders.
            return

        # Update order details based on ER
        if order_id: order_data["OrderID"] = order_id
        if ord_status: order_data["OrdStatus"] = ord_status
        
        try:
            if cum_qty_str: order_data["CumQty"] = float(cum_qty_str)
            if avg_px_str: order_data["AvgPx"] = float(avg_px_str)
            if last_px_str: order_data["LastPx"] = float(last_px_str)
            if last_qty_str: order_data["LastQty"] = float(last_qty_str)
            if leaves_qty_str: 
                order_data["LeavesQty"] = float(leaves_qty_str)
            elif cum_qty_str and "OrderQty" in order_data: # Calculate if LeavesQty not present
                order_data["LeavesQty"] = order_data["OrderQty"] - order_data["CumQty"]
                logger.debug(f"Calculated LeavesQty for {target_clordid} as {order_data['LeavesQty']}")

        except ValueError as e:
            logger.error(f"Error parsing numeric value from ExecutionReport for {target_clordid}: {e}. Raw ER: {log_er_summary}", exc_info=True)
            # Potentially mark order as having an issue or await manual intervention


        # Specific logic based on OrdStatus or ExecType
        if ord_status == ORDER_STATUS_REJECTED:
            logger.warning(f"Order {target_clordid} REJECTED by server. Reason: {text if text else 'N/A'}")
            # Potentially remove from active pending_orders or move to a 'rejected_orders' list
        elif ord_status == ORDER_STATUS_FILLED:
            logger.info(f"Order {target_clordid} FULLY FILLED. CumQty: {order_data['CumQty']}, AvgPx: {order_data['AvgPx']}")
        elif ord_status == ORDER_STATUS_PARTIALLY_FILLED:
            logger.info(f"Order {target_clordid} PARTIALLY FILLED. LastQty: {order_data['LastQty']}, LastPx: {order_data['LastPx']}, CumQty: {order_data['CumQty']}, AvgPx: {order_data['AvgPx']}")
        elif ord_status == ORDER_STATUS_NEW: # ExecType NEW or OrdStatus NEW
             logger.info(f"Order {target_clordid} ACKNOWLEDGED as NEW by server. OrderID: {order_id}")
        elif ord_status == ORDER_STATUS_CANCELED:
            logger.info(f"Order {target_clordid} CONFIRMED CANCELED.")
        elif ord_status == ORDER_STATUS_PENDING_CANCEL:
            logger.info(f"Order {target_clordid} is PENDING CANCEL.")
        
        # For exec_type specific information (e.g., if it's a trade confirmation)
        if exec_type == EXEC_TYPE_TRADE or exec_type == EXEC_TYPE_FILL: # EXEC_TYPE_PARTIAL_FILL is covered by OrdStatus PARTIALLY_FILLED
             logger.info(f"Trade Confirmed for {target_clordid}: Qty={last_qty_str} @ Px={last_px_str}")

        # Clean up filled or terminal state orders if desired
        if ord_status in [ORDER_STATUS_FILLED, ORDER_STATUS_CANCELED, ORDER_STATUS_REJECTED, ORDER_STATUS_EXPIRED]:
            logger.info(f"Order {target_clordid} reached terminal state: {self._map_ord_status_to_text(ord_status)}. "
                        f"It will remain in pending_orders for now for status checks but is considered complete/inactive.")
            # Consider delaying removal or moving to an archive.
            # For now, just log. A real system would have more robust cleanup or archiving.
            # If removing:
            # try:
            #     del self.pending_orders[target_clordid]
            #     logger.info(f"Order {target_clordid} removed from active tracking.")
            # except KeyError:
            #     logger.warning(f"Attempted to remove already removed order {target_clordid} from tracking.")


        self.pending_orders[target_clordid] = order_data # Ensure updates are saved back
        logger.debug(f"Updated order data for {target_clordid}: {self.pending_orders[target_clordid]}")


    def handle_order_cancel_reject(self, message: simplefix.FixMessage):
        """
        Handles OrderCancelReject (35=9) messages.
        """
        clordid = message.get_value(11)      # ClOrdID of the cancel request
        orig_clordid = message.get_value(41) # ClOrdID of the original order to be cancelled
        order_id = message.get_value(37)     # OrderID (Broker's ID, if known)
        cxl_rej_response_to = message.get_value(434) # CxlRejResponseTo (1=Cancel Request, 2=Cancel/Replace)
        cxl_rej_reason_code = message.get_value(102) # CxlRejReason
        text = message.get_value(58) # Text

        cxl_rej_reason_text = self._map_cxl_rej_reason_to_text(cxl_rej_reason_code)
        response_to_text = ('Cancel Request' if cxl_rej_response_to == '1' 
                            else 'Cancel/Replace Request' if cxl_rej_response_to == '2' 
                            else f"Unknown({cxl_rej_response_to})")

        log_ocr_summary = (
            f"OrderCancelReject: ClOrdID (of CancelRq)={clordid}, OrigClOrdID (of Order)={orig_clordid}, "
            f"OrderID={order_id if order_id else 'N/A'}, CxlRejResponseTo={response_to_text}({cxl_rej_response_to}), "
            f"CxlRejReason={cxl_rej_reason_text}({cxl_rej_reason_code}), Text='{text}'"
        )
        logger.warning(log_ocr_summary) # Warning because it's a rejection
        if logger.isEnabledFor(logging.DEBUG):
             logger.debug(f"Full OrderCancelReject message:\n{message.encode().decode(errors='replace').replace(simplefix.SOH, '|')}")

        target_order_clordid = orig_clordid # The order that failed to be cancelled

        if not target_order_clordid:
            logger.error("OrderCancelReject received without OrigClOrdID (41). Cannot process against a specific order.")
            return

        order_data = self.pending_orders.get(target_order_clordid)
        if order_data:
            current_status = order_data.get("OrdStatus")
            rejection_info = text or cxl_rej_reason_text
            order_data["CancelRejectReason"] = rejection_info
            
            logger.info(f"Cancellation of order {target_order_clordid} (current status: {self._map_ord_status_to_text(current_status)}) "
                        f"REJECTED. Reason: {rejection_info}")
            
            # If the order was PENDING_CANCEL, it might revert to its previous state.
            # However, without storing previous state, we might just leave its OrdStatus as is,
            # and rely on a subsequent ExecutionReport to clarify the true current state.
            # For now, we'll mark that the cancel was rejected. The OrdStatus itself isn't changed by the reject message.
            # A follow-up ER (OrderStatus='I') might be needed to confirm true state if uncertain.
            if current_status == ORDER_STATUS_PENDING_CANCEL:
                # Consider reverting to a previous known active status if available, or mark as 'active_cancel_rejected'.
                # For now, the status remains PENDING_CANCEL, but with a rejection note.
                # A more robust system might query order status or await an unsolicited ER.
                logger.warning(f"Order {target_order_clordid} was PENDING_CANCEL. The cancel attempt was rejected. "
                               f"The order is likely still live. Current OrdStatus in record is {self._map_ord_status_to_text(current_status)}. "
                               "Awaiting further ExecutionReports for definitive status.")
            
            self.pending_orders[target_order_clordid] = order_data
        else:
            logger.warning(f"Received OrderCancelReject for unknown/untracked OrigClOrdID: {target_order_clordid}. Reject Info: {log_ocr_summary}")
            
    def cancel_order(self, orig_clordid: str, cancel_clordid: str = None):
        """
        Constructs and sends an OrderCancelRequest (35=F) message.

        Args:
            orig_clordid (str): Tag 41 (ClOrdID of the order to be cancelled)
            cancel_clordid (str, optional): Tag 11 (Unique ID for this cancel request). If None, generates one.

        Returns:
            str: The ClOrdID of the cancel request, or None if sending failed.
        """
        if not self.fix_client or not self.fix_client.session_active:
            logger.error("Cannot cancel order: FIX client not connected or session not active.")
            return None

        order_to_cancel = self.pending_orders.get(orig_clordid)
        if not order_to_cancel:
            logger.error(f"Cannot cancel order {orig_clordid}: Order not found in local pending orders cache.")
            return None
        
        current_ord_status = order_to_cancel.get("OrdStatus")
        # Check if order is already in a terminal state or pending cancel (redundant cancel)
        if current_ord_status in [ORDER_STATUS_FILLED, ORDER_STATUS_CANCELED, ORDER_STATUS_REJECTED, ORDER_STATUS_EXPIRED]:
            logger.warning(f"Order {orig_clordid} is already in a terminal state "
                           f"({self._map_ord_status_to_text(current_ord_Status)}) and cannot be cancelled.")
            return None
        if current_ord_status == ORDER_STATUS_PENDING_CANCEL:
            logger.info(f"Order {orig_clordid} is already PENDING_CANCEL. Not sending another cancel request. "
                        f"Previous CancelClOrdID: {order_to_cancel.get('CancelClOrdID', 'N/A')}")
            return order_to_cancel.get('CancelClOrdID') # Return existing cancel request ID

        if cancel_clordid is None:
            cancel_clordid = self._generate_clordid()
            logger.debug(f"Generated new ClOrdID: {cancel_clordid} for cancel_order request on {orig_clordid}.")

        cancel_msg = simplefix.FixMessage()
        cancel_msg.append_pair(35, "F")  # MsgType: OrderCancelRequest

        cancel_msg.append_pair(11, cancel_clordid)    # ClOrdID (for this cancel request)
        cancel_msg.append_pair(41, orig_clordid)     # OrigClOrdID (of the order to cancel)
        
        # Required fields from original order
        cancel_msg.append_pair(55, order_to_cancel["Symbol"])  # Symbol
        cancel_msg.append_pair(54, order_to_cancel["Side"])  # Side
        cancel_msg.append_pair(60, datetime.datetime.utcnow().strftime("%Y%m%d-%H:%M:%S.%f")[:-3])  # TransactTime
        
        # Optional: OrderQty (38) might be required by some counterparties on cancel request
        # cancel_msg.append_pair(38, order_to_cancel["OrderQty"])


        log_cancel_summary = (f"Requesting cancel for order {orig_clordid} (Symbol: {order_to_cancel['Symbol']}, "
                              f"Side: {order_to_cancel['Side']}) with CancelClOrdID {cancel_clordid}.")
        logger.info(log_cancel_summary)
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"Full OrderCancelRequest message for {orig_clordid}:\n{cancel_msg.encode().decode(errors='replace').replace(simplefix.SOH, '|')}")
        
        if self.fix_client.send_message(cancel_msg):
            # Update status of the original order to PENDING_CANCEL
            order_to_cancel["OrdStatus"] = ORDER_STATUS_PENDING_CANCEL
            order_to_cancel["CancelClOrdID"] = cancel_clordid # Store the ID of the cancel request
            self.pending_orders[orig_clordid] = order_to_cancel
            logger.info(f"OrderCancelRequest for {orig_clordid} sent successfully. Marked as PENDING_CANCEL.")
            return cancel_clordid
        else:
            logger.error(f"Failed to send OrderCancelRequest for order {orig_clordid}.")
            return None

    def get_order_status(self, clordid: str):
        """Retrieves the current status of a tracked order from local cache."""
        order_info = self.pending_orders.get(clordid, None)
        if order_info:
            logger.debug(f"Status for {clordid}: {order_info}")
        else:
            logger.debug(f"Order {clordid} not found in local cache for get_order_status.")
        return order_info

    def _map_ord_status_to_text(self, status_code):
        if status_code is None: return "None"
        status_map = {
            '0': "New", '1': "PartiallyFilled", '2': "Filled", '3': "DoneForDay",
            '4': "Canceled", '5': "Replaced", '6': "PendingCancel", '7': "Stopped",
            '8': "Rejected", '9': "Suspended", 'A': "PendingNew", 'B': "Calculated",
            'C': "Expired", 'D': "AcceptedForBidding", 'E': "PendingReplace"
        }
        return status_map.get(str(status_code), f"UnknownOrdStatus({status_code})")

    def _map_exec_type_to_text(self, exec_code):
        if exec_code is None: return "None"
        exec_map = {
            '0': "New", '1': "PartialFill", '2': "Fill", '3': "DoneForDay",
            '4': "Canceled", '5': "Replace", '6': "PendingCancel", '8': "Rejected",
            '9': "Suspended", 'A': "PendingNew", 'D': "Restated", 'E': "PendingReplace",
            'F': "Trade (Fill or Partial Fill)", 'I': "OrderStatus"
        }
        return exec_map.get(str(exec_code), f"UnknownExecType({exec_code})")

    def _map_cxl_rej_reason_to_text(self, reason_code):
        if reason_code is None: return "None"
        reason_map = {
            '0': "Too late to cancel",
            '1': "Unknown order",
            '2': "Broker / Exchange Option",
            '3': "Order already in Pending Cancel or Pending Replace status",
            # Add more from FIX spec as needed
            '99': "Other"
        }
        return reason_map.get(reason_code, f"UnknownReason({reason_code})")

    def __del__(self):
        return reason_map.get(str(reason_code), f"UnknownReason({reason_code})")

    def __del__(self):
        # Unregister handlers when TradeExecutor instance is deleted
        if self.fix_client:
            logger.info("TradeExecutor being deleted. Unregistering message handlers from FixClient.")
            try:
                self.fix_client.unregister_message_handler("8")
                self.fix_client.unregister_message_handler("9")
            except Exception as e:
                logger.error(f"Error unregistering handlers during TradeExecutor deletion: {e}", exc_info=True)
        else:
            logger.debug("TradeExecutor being deleted, no FixClient instance to unregister from.")


# Example Usage (Conceptual - requires a running FixClient and server)
if __name__ == "__main__":
    # This example is conceptual and won't run directly without a FixClient setup
    # Setup basic logging for the self-test if not configured elsewhere
    if not logging.getLogger("fixna_app").hasHandlers(): # Check if specific app logger has handlers
         if not logging.getLogger().hasHandlers(): # Fallback to check root logger
            logging.basicConfig(level=logging.DEBUG, 
                                format='%(asctime)s - %(name)s - %(levelname)s - %(module)s - %(message)s',
                                handlers=[logging.StreamHandler()])

    logger.info("--- TradeExecutor Example (Conceptual Self-Test) ---")

    # --- Mock FixClient setup (for local testing of TradeExecutor logic) ---
    class MockFixClient:
        def __init__(self):
            self.session_active = True
            self.message_handlers = {}
            logger.info("MockFixClient initialized for TradeExecutor self-test.")

        def send_message(self, message):
            msg_type = message.get_value(35)
            clordid = message.get_value(11)
            logger.info(f"MockFixClient: send_message called for MsgType {msg_type}, ClOrdID {clordid}")
            
            # Simulate an immediate ACK for NewOrderSingle
            if msg_type == "D": # NewOrderSingle
                # Simulate an ExecutionReport - New
                exec_report_new = simplefix.FixMessage()
                exec_report_new.append_pair(35, "8") # ExecutionReport
                exec_report_new.append_pair(11, clordid) # ClOrdID
                exec_report_new.append_pair(37, "MOCK_ORDID_" + clordid) # OrderID
                exec_report_new.append_pair(39, ORDER_STATUS_NEW) # OrdStatus = New
                exec_report_new.append_pair(150, EXEC_TYPE_NEW) # ExecType = New
                exec_report_new.append_pair(14, "0") # CumQty
                exec_report_new.append_pair(151, message.get_value(38)) # LeavesQty = OrderQty
                exec_report_new.append_pair(6, "0") # AvgPx
                
                if "8" in self.message_handlers: # Check if ER handler is registered
                    logger.debug(f"MockFixClient: Simulating ER (New) for {clordid}")
                    time.sleep(0.05) # simulate network delay
                    self.message_handlers["8"](exec_report_new)

                # Simulate a Fill
                exec_report_fill = simplefix.FixMessage()
                exec_report_fill.append_pair(35, "8") # ExecutionReport
                exec_report_fill.append_pair(11, clordid) # ClOrdID
                exec_report_fill.append_pair(37, "MOCK_ORDID_" + clordid) # OrderID
                exec_report_fill.append_pair(39, ORDER_STATUS_FILLED) # OrdStatus = Filled
                exec_report_fill.append_pair(150, EXEC_TYPE_FILL) # ExecType = Fill
                
                order_qty_str = message.get_value(38)
                price_str = message.get_value(44) # Price for Limit
                price = float(price_str) if price_str else 1.2345 # Mock fill price for market

                exec_report_fill.append_pair(14, order_qty_str) # CumQty
                exec_report_fill.append_pair(151, "0") # LeavesQty
                exec_report_fill.append_pair(31, str(price)) # LastPx
                exec_report_fill.append_pair(32, order_qty_str) # LastQty
                exec_report_fill.append_pair(6, str(price)) # AvgPx
                
                if "8" in self.message_handlers:
                    logger.debug(f"MockFixClient: Simulating ER (Fill) for {clordid}")
                    time.sleep(0.1) # simulate more delay
                    self.message_handlers["8"](exec_report_fill)
            
            elif msg_type == "F": # OrderCancelRequest
                orig_clordid = message.get_value(41)
                # Simulate an ExecutionReport - Canceled
                exec_report_cancel = simplefix.FixMessage()
                exec_report_cancel.append_pair(35, "8") # ExecutionReport
                exec_report_cancel.append_pair(11, clordid) # ClOrdID of cancel req
                exec_report_cancel.append_pair(41, orig_clordid) # OrigClOrdID
                exec_report_cancel.append_pair(37, "MOCK_ORDID_" + orig_clordid) # OrderID
                exec_report_cancel.append_pair(39, ORDER_STATUS_CANCELED) # OrdStatus = Canceled
                exec_report_cancel.append_pair(150, EXEC_TYPE_CANCELLED) # ExecType = Canceled
                # CumQty and LeavesQty depend on previous fills, assume 0 for simplicity here
                exec_report_cancel.append_pair(14, order_qty_str if order_qty_str else "0") # CumQty from original order
                exec_report_cancel.append_pair(151, "0") # LeavesQty
                
                if "8" in self.message_handlers: # Check if ER handler is registered
                    logger.debug(f"MockFixClient: Simulating ER (Canceled) for {orig_clordid}")
                    time.sleep(0.05)
                    self.message_handlers["8"](exec_report_cancel)
            return True

        def register_message_handler(self, msg_type, handler_callback):
            logger.info(f"MockFixClient: Registering handler for MsgType {msg_type}: {handler_callback.__name__}")
            self.message_handlers[msg_type] = handler_callback
            
        def unregister_message_handler(self, msg_type):
            if msg_type in self.message_handlers:
                logger.info(f"MockFixClient: Unregistered handler for MsgType {msg_type}")
                del self.message_handlers[msg_type]
            else:
                logger.warning(f"MockFixClient: No handler to unregister for MsgType {msg_type}")

    # --- End Mock FixClient ---

    mock_client = MockFixClient()
    executor = TradeExecutor(mock_client)

    logger.info("\n--- Placing a Limit Buy Order (Self-Test) ---")
    limit_clordid = executor.place_order(
        symbol="EUR/USD",
        side="1",  # Buy
        order_type="2",  # Limit
        quantity=1000,
        price=1.0750
    )
    if limit_clordid:
        logger.info(f"Limit order placed. ClOrdID: {limit_clordid}")
        time.sleep(0.3) # Allow simulated ERs to process
        status = executor.get_order_status(limit_clordid)
        logger.info(f"Status for {limit_clordid}: {executor._map_ord_status_to_text(status.get('OrdStatus')) if status else 'Not Found'}")
        if status: logger.debug(f"Full status for {limit_clordid}: {status}")

    logger.info("\n--- Placing a Market Sell Order (Self-Test) ---")
    market_clordid = executor.place_order(
        symbol="GBP/USD",
        side="2",  # Sell
        order_type="1",  # Market
        quantity=500
    )
    if market_clordid:
        logger.info(f"Market order placed. ClOrdID: {market_clordid}")
        time.sleep(0.3) # Allow simulated ERs to process
        status = executor.get_order_status(market_clordid)
        logger.info(f"Status for {market_clordid}: {executor._map_ord_status_to_text(status.get('OrdStatus')) if status else 'Not Found'}")
        if status: logger.debug(f"Full status for {market_clordid}: {status}")

    logger.info("\n--- Attempting to Cancel the Limit Order (Self-Test) ---")
    if limit_clordid:
        order_data_for_cancel = executor.get_order_status(limit_clordid)
        if order_data_for_cancel and order_data_for_cancel.get("OrdStatus") == ORDER_STATUS_FILLED:
            logger.warning(f"Mock Scenario: Order {limit_clordid} was 'Filled'. "
                           "To test cancel, it should ideally be 'New' or 'PartiallyFilled'. "
                           "Mock ER simulation might have auto-filled it.")
            # Forcing status to New for this mock test of cancel logic
            order_data_for_cancel["OrdStatus"] = ORDER_STATUS_NEW
            order_data_for_cancel["CumQty"] = 0.0
            order_data_for_cancel["LeavesQty"] = order_data_for_cancel["OrderQty"]
            logger.info(f"Mock HACK: Resetting {limit_clordid} status to NEW for cancel test.")


        cancel_req_id = executor.cancel_order(orig_clordid=limit_clordid)
        if cancel_req_id:
            logger.info(f"Cancel request sent for {limit_clordid}. CancelClOrdID: {cancel_req_id}")
            time.sleep(0.3) # Allow simulated ER for cancel to process
            status_after_cancel_req = executor.get_order_status(limit_clordid)
            logger.info(f"Status for {limit_clordid} after cancel request: {executor._map_ord_status_to_text(status_after_cancel_req.get('OrdStatus')) if status_after_cancel_req else 'Not Found'}")
            if status_after_cancel_req: logger.debug(f"Full status for {limit_clordid} after cancel: {status_after_cancel_req}")
        else:
            logger.error(f"Failed to send cancel request for {limit_clordid}.")
            
    # Cleanup (important for real FixClient to stop threads etc.)
    # In this mock scenario, it just unregisters handlers.
    del executor 
    # del mock_client # if mock_client had resources to clean up (none in this simplified mock)

    logger.info("\n--- TradeExecutor Example (Conceptual Self-Test) Finished ---")
