import unittest
from unittest.mock import MagicMock, patch
import simplefix # For creating FIX messages to pass to handlers
import uuid
import time

# Add project root to Python path
import os
import sys
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from src.trade_executor import TradeExecutor, ORDER_STATUS_NEW, ORDER_STATUS_FILLED, \
                               ORDER_STATUS_PARTIALLY_FILLED, ORDER_STATUS_REJECTED, \
                               ORDER_STATUS_PENDING_CANCEL, ORDER_STATUS_CANCELED, \
                               EXEC_TYPE_NEW, EXEC_TYPE_FILL, EXEC_TYPE_PARTIAL_FILL, \
                               EXEC_TYPE_REJECTED, EXEC_TYPE_CANCELLED
from src.fix_client import FixClient # Just for type hinting mock, not direct use

# Mock datetime for consistent TransactTime (60)
MOCK_TRANSACT_TIME = "20230101-12:00:00.000"

@patch('src.trade_executor.datetime', new_callable=MagicMock)
class TestTradeExecutor(unittest.TestCase):

    def setUp(self, mock_datetime_module):
        # Configure the mock datetime.datetime.utcnow().strftime()
        mock_dt_object = MagicMock()
        mock_dt_object.strftime.return_value = MOCK_TRANSACT_TIME
        mock_datetime_module.datetime.utcnow.return_value = mock_dt_object

        self.mock_fix_client = MagicMock(spec=FixClient)
        self.mock_fix_client.session_active = True # Assume session is active for most tests
        self.executor = TradeExecutor(self.mock_fix_client)
        
        # Mock logger for TradeExecutor to suppress output during tests
        # self.mock_te_logger = patch('src.trade_executor.logger', MagicMock()).start()
        # self.addCleanup(patch.stopall) # Stops all patches started with start()

    def tearDown(self):
        # patch.stopall() # If using self.mock_te_logger.start()
        pass


    def test_init_registers_handlers(self, mock_datetime_module):
        """Test that TradeExecutor registers handlers with FixClient on initialization."""
        self.mock_fix_client.register_message_handler.assert_any_call("8", self.executor.handle_execution_report)
        self.mock_fix_client.register_message_handler.assert_any_call("9", self.executor.handle_order_cancel_reject)
        self.assertEqual(self.mock_fix_client.register_message_handler.call_count, 2)

    def test_del_unregisters_handlers(self, mock_datetime_module):
        """Test that TradeExecutor unregisters handlers on deletion."""
        # Need to capture the calls to unregister_message_handler
        # We can do this by creating a new executor and deleting it, or by calling __del__ directly (less ideal)
        temp_executor = TradeExecutor(self.mock_fix_client)
        
        # Reset mock for this specific part of the test if it was called in setUp's executor
        self.mock_fix_client.unregister_message_handler.reset_mock() 
        
        del temp_executor # Trigger __del__

        self.mock_fix_client.unregister_message_handler.assert_any_call("8")
        self.mock_fix_client.unregister_message_handler.assert_any_call("9")
        self.assertEqual(self.mock_fix_client.unregister_message_handler.call_count, 2)


    @patch('src.trade_executor.uuid.uuid4')
    def test_place_market_order_success(self, mock_uuid, mock_datetime_module):
        mock_uuid.return_value = "test-clordid-market-123"
        self.mock_fix_client.send_message.return_value = True

        clordid = self.executor.place_order(
            symbol="EUR/USD", side="1", order_type="1", quantity=1000
        )

        self.assertEqual(clordid, "test-clordid-market-123")
        self.mock_fix_client.send_message.assert_called_once()
        sent_msg = self.mock_fix_client.send_message.call_args[0][0]
        
        self.assertEqual(sent_msg.get_value(35), "D") # NewOrderSingle
        self.assertEqual(sent_msg.get_value(11), "test-clordid-market-123")
        self.assertEqual(sent_msg.get_value(55), "EUR/USD")
        self.assertEqual(sent_msg.get_value(54), "1") # Buy
        self.assertEqual(sent_msg.get_value(40), "1") # Market
        self.assertEqual(sent_msg.get_value(38), 1000)
        self.assertEqual(sent_msg.get_value(60), MOCK_TRANSACT_TIME)
        self.assertIsNone(sent_msg.get_value(44)) # No price for market

        self.assertIn("test-clordid-market-123", self.executor.pending_orders)
        self.assertEqual(self.executor.pending_orders[clordid]["OrdStatus"], ORDER_STATUS_PENDING_NEW)

    @patch('src.trade_executor.uuid.uuid4')
    def test_place_limit_order_success(self, mock_uuid, mock_datetime_module):
        mock_uuid.return_value = "test-clordid-limit-456"
        self.mock_fix_client.send_message.return_value = True

        clordid = self.executor.place_order(
            symbol="GBP/JPY", side="2", order_type="2", quantity=500, price=150.75
        )

        self.assertEqual(clordid, "test-clordid-limit-456")
        self.mock_fix_client.send_message.assert_called_once()
        sent_msg = self.mock_fix_client.send_message.call_args[0][0]

        self.assertEqual(sent_msg.get_value(35), "D")
        self.assertEqual(sent_msg.get_value(11), "test-clordid-limit-456")
        self.assertEqual(sent_msg.get_value(55), "GBP/JPY")
        self.assertEqual(sent_msg.get_value(54), "2") # Sell
        self.assertEqual(sent_msg.get_value(40), "2") # Limit
        self.assertEqual(sent_msg.get_value(38), 500)
        self.assertEqual(sent_msg.get_value(44), 150.75) # Price for limit
        self.assertEqual(sent_msg.get_value(60), MOCK_TRANSACT_TIME)

        self.assertIn("test-clordid-limit-456", self.executor.pending_orders)

    def test_place_limit_order_no_price_fails(self, mock_datetime_module):
        clordid = self.executor.place_order(
            symbol="USD/CAD", side="1", order_type="2", quantity=100 # Missing price for limit
        )
        self.assertIsNone(clordid)
        self.mock_fix_client.send_message.assert_not_called()

    def test_place_order_fix_client_inactive(self, mock_datetime_module):
        self.mock_fix_client.session_active = False
        clordid = self.executor.place_order(
            symbol="EUR/USD", side="1", order_type="1", quantity=1000
        )
        self.assertIsNone(clordid)
        self.mock_fix_client.send_message.assert_not_called()

    def test_handle_execution_report_new(self, mock_datetime_module):
        clordid = "test-order-001"
        self.executor.pending_orders[clordid] = {"ClOrdID": clordid, "OrderQty": 100, "OrdStatus": ORDER_STATUS_PENDING_NEW}

        er_msg = simplefix.FixMessage()
        er_msg.append_pair(35, "8") # ExecutionReport
        er_msg.append_pair(11, clordid)
        er_msg.append_pair(37, "server-order-id-001") # OrderID
        er_msg.append_pair(39, ORDER_STATUS_NEW) # OrdStatus = New
        er_msg.append_pair(150, EXEC_TYPE_NEW)   # ExecType = New
        er_msg.append_pair(14, "0") # CumQty
        er_msg.append_pair(151, "100") # LeavesQty

        self.executor.handle_execution_report(er_msg)

        order_status = self.executor.get_order_status(clordid)
        self.assertEqual(order_status["OrderID"], "server-order-id-001")
        self.assertEqual(order_status["OrdStatus"], ORDER_STATUS_NEW)
        self.assertEqual(order_status["CumQty"], 0.0)
        self.assertEqual(order_status["LeavesQty"], 100.0)

    def test_handle_execution_report_filled(self, mock_datetime_module):
        clordid = "test-order-002"
        self.executor.pending_orders[clordid] = {"ClOrdID": clordid, "OrderQty": 200, "OrdStatus": ORDER_STATUS_NEW}

        er_msg = simplefix.FixMessage()
        er_msg.append_pair(35, "8")
        er_msg.append_pair(11, clordid)
        er_msg.append_pair(37, "server-order-id-002")
        er_msg.append_pair(39, ORDER_STATUS_FILLED) # Filled
        er_msg.append_pair(150, EXEC_TYPE_FILL)    # Fill
        er_msg.append_pair(14, "200") # CumQty
        er_msg.append_pair(6, "1.1234") # AvgPx
        er_msg.append_pair(31, "1.1234") # LastPx
        er_msg.append_pair(32, "200") # LastQty
        er_msg.append_pair(151, "0") # LeavesQty

        self.executor.handle_execution_report(er_msg)
        order_status = self.executor.get_order_status(clordid)
        self.assertEqual(order_status["OrdStatus"], ORDER_STATUS_FILLED)
        self.assertEqual(order_status["CumQty"], 200.0)
        self.assertEqual(order_status["AvgPx"], 1.1234)
        self.assertEqual(order_status["LeavesQty"], 0.0)

    def test_handle_execution_report_partially_filled(self, mock_datetime_module):
        clordid = "test-order-003"
        self.executor.pending_orders[clordid] = {"ClOrdID": clordid, "OrderQty": 500, "OrdStatus": ORDER_STATUS_NEW}

        er_msg = simplefix.FixMessage()
        er_msg.append_pair(35, "8")
        er_msg.append_pair(11, clordid)
        er_msg.append_pair(39, ORDER_STATUS_PARTIALLY_FILLED)
        er_msg.append_pair(150, EXEC_TYPE_PARTIAL_FILL)
        er_msg.append_pair(14, "100") # CumQty
        er_msg.append_pair(6, "150.50") # AvgPx
        er_msg.append_pair(31, "150.50") # LastPx
        er_msg.append_pair(32, "100") # LastQty
        er_msg.append_pair(151, "400") # LeavesQty

        self.executor.handle_execution_report(er_msg)
        order_status = self.executor.get_order_status(clordid)
        self.assertEqual(order_status["OrdStatus"], ORDER_STATUS_PARTIALLY_FILLED)
        self.assertEqual(order_status["CumQty"], 100.0)
        self.assertEqual(order_status["AvgPx"], 150.50)
        self.assertEqual(order_status["LeavesQty"], 400.0)

    def test_handle_execution_report_rejected(self, mock_datetime_module):
        clordid = "test-order-004"
        self.executor.pending_orders[clordid] = {"ClOrdID": clordid, "OrderQty": 100, "OrdStatus": ORDER_STATUS_PENDING_NEW}

        er_msg = simplefix.FixMessage()
        er_msg.append_pair(35, "8")
        er_msg.append_pair(11, clordid)
        er_msg.append_pair(39, ORDER_STATUS_REJECTED)
        er_msg.append_pair(150, EXEC_TYPE_REJECTED)
        er_msg.append_pair(58, "Order rejected by exchange") # Text

        self.executor.handle_execution_report(er_msg)
        order_status = self.executor.get_order_status(clordid)
        self.assertEqual(order_status["OrdStatus"], ORDER_STATUS_REJECTED)
        self.assertIn("Order rejected by exchange", order_status.get("Text", "")) # Text might not be stored directly

    def test_handle_execution_report_unknown_clordid(self, mock_datetime_module):
        er_msg = simplefix.FixMessage()
        er_msg.append_pair(35, "8")
        er_msg.append_pair(11, "unknown-clordid-999") # This ClOrdID is not in pending_orders
        er_msg.append_pair(39, ORDER_STATUS_NEW)
        
        # Should not raise an error, just log a warning (tested via logger if mock_te_logger was active)
        try:
            self.executor.handle_execution_report(er_msg)
        except Exception as e:
            self.fail(f"handle_execution_report raised an exception for unknown ClOrdID: {e}")
        self.assertNotIn("unknown-clordid-999", self.executor.pending_orders)


    @patch('src.trade_executor.uuid.uuid4')
    def test_cancel_order_success(self, mock_uuid, mock_datetime_module):
        orig_clordid = "order-to-cancel-001"
        mock_uuid.return_value = "cancel-req-id-001"
        self.mock_fix_client.send_message.return_value = True
        
        self.executor.pending_orders[orig_clordid] = {
            "ClOrdID": orig_clordid, "Symbol": "EUR/USD", "Side": "1", 
            "OrderQty": 100, "OrdStatus": ORDER_STATUS_NEW
        }

        cancel_clordid = self.executor.cancel_order(orig_clordid)

        self.assertEqual(cancel_clordid, "cancel-req-id-001")
        self.mock_fix_client.send_message.assert_called_once()
        sent_msg = self.mock_fix_client.send_message.call_args[0][0]

        self.assertEqual(sent_msg.get_value(35), "F") # OrderCancelRequest
        self.assertEqual(sent_msg.get_value(11), "cancel-req-id-001")
        self.assertEqual(sent_msg.get_value(41), orig_clordid) # OrigClOrdID
        self.assertEqual(sent_msg.get_value(55), "EUR/USD")
        self.assertEqual(sent_msg.get_value(54), "1")
        self.assertEqual(sent_msg.get_value(60), MOCK_TRANSACT_TIME)

        order_status = self.executor.get_order_status(orig_clordid)
        self.assertEqual(order_status["OrdStatus"], ORDER_STATUS_PENDING_CANCEL)
        self.assertEqual(order_status["CancelClOrdID"], "cancel-req-id-001")


    def test_cancel_order_not_found(self, mock_datetime_module):
        cancel_clordid = self.executor.cancel_order("non-existent-order-id")
        self.assertIsNone(cancel_clordid)
        self.mock_fix_client.send_message.assert_not_called()

    def test_cancel_order_already_terminal_state(self, mock_datetime_module):
        orig_clordid = "terminal-order-001"
        self.executor.pending_orders[orig_clordid] = {
            "ClOrdID": orig_clordid, "Symbol": "EUR/USD", "Side": "1",
            "OrderQty": 100, "OrdStatus": ORDER_STATUS_FILLED # Already filled
        }
        cancel_clordid = self.executor.cancel_order(orig_clordid)
        self.assertIsNone(cancel_clordid)
        self.mock_fix_client.send_message.assert_not_called()

    def test_handle_order_cancel_reject(self, mock_datetime_module):
        orig_clordid = "order-failed-to-cancel-001"
        cancel_req_clordid = "cancel-req-for-failed-001"
        
        self.executor.pending_orders[orig_clordid] = {
            "ClOrdID": orig_clordid, "Symbol": "USD/JPY", "Side": "2",
            "OrderQty": 2000, "OrdStatus": ORDER_STATUS_PENDING_CANCEL, # Was pending cancel
            "CancelClOrdID": cancel_req_clordid
        }

        ocr_msg = simplefix.FixMessage()
        ocr_msg.append_pair(35, "9") # OrderCancelReject
        ocr_msg.append_pair(11, cancel_req_clordid) # ClOrdID of the cancel request
        ocr_msg.append_pair(41, orig_clordid) # OrigClOrdID of the order
        ocr_msg.append_pair(37, "server-order-id-for-failed-cancel") # OrderID
        ocr_msg.append_pair(102, "0") # CxlRejReason = Too late to cancel
        ocr_msg.append_pair(58, "Too late, order already filled") # Text

        self.executor.handle_order_cancel_reject(ocr_msg)

        order_status = self.executor.get_order_status(orig_clordid)
        self.assertIn("CancelRejectReason", order_status)
        self.assertEqual(order_status["CancelRejectReason"], "Too late, order already filled")
        # The OrdStatus might remain PENDING_CANCEL or revert based on more complex logic.
        # Current implementation just adds CancelRejectReason.
        self.assertEqual(order_status["OrdStatus"], ORDER_STATUS_PENDING_CANCEL)


if __name__ == '__main__':
    unittest.main()
