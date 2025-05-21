import time
import os
import sys
import logging

# Add project root to Python path to allow direct imports from src, config etc.
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from config.settings import AppSettings
from src.fix_client import FixClient
from src.trade_executor import TradeExecutor # Assuming TradeExecutor might be used later
from src.logger_setup import setup_logging

# Get a logger for this module (main application)
# Logger configuration will be applied by setup_logging
logger = logging.getLogger("fixna_app") # Using the same name as in logger_setup for consistency

def main():
    """
    Main function to start the FIXNA trading application.
    """
    # --- 0. Initial Basic Logging (before full config is loaded) ---
    # This will use Python's default logging until setup_logging is called.
    # Useful for capturing very early issues.
    logging.basicConfig(level=logging.INFO) # Temporary basic config
    logger.info("Starting FIXNA trading application...")
    logger.info(f"Project root determined as: {project_root}")
    logger.info(f"Looking for configuration files in: {os.path.join(project_root, 'config')}")

    # --- 1. Load Configuration ---
    try:
        config_file_path = os.path.join(project_root, "config", "config.ini")
        example_config_path = os.path.join(project_root, "config", "config.example.ini")

        if not os.path.exists(config_file_path):
            if os.path.exists(example_config_path):
                logger.warning(f"'{config_file_path}' not found. "
                               f"Please copy '{example_config_path}' to '{config_file_path}' and customize it.")
                logger.info(f"For this run, attempting to use settings from '{example_config_path}'.")
            else:
                logger.critical(f"CRITICAL ERROR: Neither '{config_file_path}' nor '{example_config_path}' found.")
                logger.critical("Application cannot start without configuration.")
                return # Exit

        settings = AppSettings() # Loads 'config/config.ini' or 'config/config.example.ini'
        
        # --- 1a. Setup Logging (using loaded settings) ---
        # The logger_name "fixna_app" should match what's used in logger_setup.py for the main app logger
        setup_logging(log_level_str=settings.app_log_level, 
                      log_file=settings.app_log_file, 
                      logger_name="fixna_app")
        
        logger.info("Configuration loaded and logging configured successfully.")
        logger.info(f"  FIX Server: {settings.fix_host}:{settings.fix_port}")
        logger.info(f"  SenderCompID: {settings.fix_sender_comp_id}")
        logger.info(f"  TargetCompID: {settings.fix_target_comp_id}")
        logger.info(f"  Heartbeat Interval: {settings.fix_heartbeat_interval}s")
        logger.info(f"  Log Level: {settings.app_log_level}")
        logger.info(f"  Log File: {settings.app_log_file}") # This path is now resolved in logger_setup
        if settings.account_username:
            logger.info(f"  Username: {settings.account_username}")

    except FileNotFoundError as e:
        logger.critical(f"Error: Configuration file issue. {e}", exc_info=True)
        logger.critical("Please ensure 'config/config.ini' or 'config/config.example.ini' exists and is readable.")
        return
    except ValueError as e: # For missing required fields or parsing errors
        logger.critical(f"Error: Configuration data invalid. {e}", exc_info=True)
        return
    except Exception as e:
        logger.critical(f"An unexpected error occurred during configuration loading or initial logging setup: {e}", exc_info=True)
        return

    # --- 2. Initialize FIX Client ---
    logger.info("Initializing FIX Client...")
    fix_client = FixClient(
        host=settings.fix_host,
        port=settings.fix_port,
        sender_comp_id=settings.fix_sender_comp_id,
        target_comp_id=settings.fix_target_comp_id,
        heartbeat_interval=settings.fix_heartbeat_interval
    )
    
    # --- 3. Initialize Trade Executor (if used directly in main) ---
    # trade_executor = TradeExecutor(fix_client) # TradeExecutor also uses logging
    # logger.info("Trade Executor initialized.")

    # --- 4. Connect and Logon ---
    logger.info("Attempting to connect to FIX server...")
    if fix_client.connect():
        logger.info("Connection successful. Attempting logon...")
        if fix_client.logon():
            logger.info("Logon successful. Session is active.")
            
            # Main application loop (example)
            try:
                start_time = time.time()
                # Run for a shorter time for typical test runs, e.g., 10-15 seconds
                # unless a specific longer test is needed.
                run_duration = 15 
                logger.info(f"Main loop will run for approximately {run_duration} seconds.")

                while fix_client.session_active and (time.time() - start_time) < run_duration:
                    fix_client.maintain_session()
                    msg = fix_client.receive_message(timeout=0.1) 
                    if msg:
                        # fix_client.py now handles detailed logging of received messages
                        logger.debug(f"MainApp: Received FIX MsgType: {msg.get_value(35)} (SeqNum: {msg.get_value(34)})")
                    
                    time.sleep(0.5) # Main loop processing interval, reduced for faster heartbeat checks if needed

                logger.info("Simulated activity period ended or session became inactive.")

            except KeyboardInterrupt:
                logger.info("KeyboardInterrupt received. Shutting down...")
            except Exception as e:
                logger.exception(f"Unhandled exception in main application loop: {e}")
            finally:
                if fix_client.session_active:
                    logger.info("Attempting graceful logout...")
                    fix_client.logout()
                    logout_wait_start = time.time()
                    # Wait for logout confirmation or timeout
                    while fix_client.session_active and (time.time() - logout_wait_start < 5): # 5s timeout for logout
                        fix_client.receive_message(timeout=0.1) # Process potential logout confirmation
                        time.sleep(0.1)
                    if fix_client.session_active:
                         logger.warning("Logout did not complete cleanly or no confirmation received within timeout.")
                
                fix_client.disconnect()
        else:
            logger.error("Logon failed.")
            fix_client.disconnect() # Ensure socket is closed if logon fails after connect
    else:
        logger.error("Connection to FIX server failed.")

    logger.info("FIXNA trading application finished.")

if __name__ == "__main__":
    main()
