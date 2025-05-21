import logging
import os
import sys

def setup_logging(log_level_str="INFO", log_file="logs/app.log", logger_name="fixna_app"):
    """
    Configures logging for the application.

    Args:
        log_level_str (str): The desired logging level (e.g., "DEBUG", "INFO", "WARNING", "ERROR").
        log_file (str): The path to the log file.
        logger_name (str): The name of the logger to configure. If None, configures the root logger.
    """
    numeric_level = getattr(logging, log_level_str.upper(), None)
    if not isinstance(numeric_level, int):
        print(f"Warning: Invalid log level '{log_level_str}'. Defaulting to INFO.")
        numeric_level = logging.INFO
        log_level_str = "INFO" # Update for consistency in messages

    # Ensure log directory exists
    if log_file:
        log_dir = os.path.dirname(log_file)
        # If log_dir is empty, it means LogFile is in the current dir or just a filename.
        # If it's relative, make it relative to project root.
        if not os.path.isabs(log_dir) and log_dir:
            # Assuming this script is in src/, project root is its parent.
            project_root = os.path.dirname(os.path.abspath(__file__)) 
            # If logger_setup is in src, then project_root is parent of src
            project_root = os.path.dirname(project_root) 
            log_dir = os.path.join(project_root, log_dir)
            log_file = os.path.join(project_root, log_file) # Ensure log_file path is also absolute or correct relative
        
        if log_dir and not os.path.exists(log_dir):
            try:
                os.makedirs(log_dir, exist_ok=True)
                print(f"Log directory '{log_dir}' created.")
            except OSError as e:
                print(f"Warning: Could not create log directory '{log_dir}': {e}. Log file might not be written.")
                log_file = None # Disable file logging if directory creation fails
        elif not log_dir and not os.path.isabs(log_file): # Log file in project root if no dir specified
            project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            log_file = os.path.join(project_root, log_file)


    # Define log format
    log_format = "%(asctime)s - %(name)s - %(levelname)s - %(module)s - %(message)s"
    formatter = logging.Formatter(log_format)

    # Get the logger
    if logger_name:
        logger = logging.getLogger(logger_name)
    else:
        logger = logging.getLogger() # Root logger

    logger.setLevel(numeric_level)
    
    # Clear existing handlers to avoid duplicate logs if setup_logging is called multiple times
    if logger.hasHandlers():
        logger.handlers.clear()

    # Console Handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # File Handler (if log_file is specified and valid)
    if log_file:
        try:
            file_handler = logging.FileHandler(log_file, mode='a') # Append mode
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
            print(f"Logging configured: Level={log_level_str}, File='{log_file}'")
        except Exception as e:
            print(f"Warning: Could not set up file logging for '{log_file}': {e}")
    else:
        print(f"Logging configured: Level={log_level_str}, Console only (no valid log file path).")

    # If configuring a specific logger, propagate its messages to parent (root)
    # unless explicitly set not to. By default, this is True.
    # logger.propagate = True 

    # Example basic log after setup (if root logger is configured or this is the main app logger)
    # logging.info("Logging setup complete.") # Use this if configuring root logger
    # logger.info("Logging setup complete.") # Use this if configuring a named logger

if __name__ == "__main__":
    print("--- Logger Setup Example ---")
    
    # Test 1: Basic INFO logging to console and a test file
    print("\nTest 1: INFO level, console and file (logs/test_app.log)")
    setup_logging("INFO", "logs/test_app.log", logger_name="TestApp1")
    test_logger1 = logging.getLogger("TestApp1")
    test_logger1.debug("This is a DEBUG message (TestApp1).") # Won't show
    test_logger1.info("This is an INFO message (TestApp1).")
    test_logger1.warning("This is a WARNING message (TestApp1).")

    # Test 2: DEBUG logging to console only
    print("\nTest 2: DEBUG level, console only")
    setup_logging("DEBUG", None, logger_name="TestApp2") # No log file
    test_logger2 = logging.getLogger("TestApp2")
    test_logger2.debug("This is a DEBUG message (TestApp2).") # Will show
    test_logger2.info("This is an INFO message (TestApp2).")
    
    # Test 3: Invalid log level, should default to INFO
    print("\nTest 3: Invalid log level, should default to INFO")
    setup_logging("VERBOSE", "logs/test_app_invalid.log", logger_name="TestApp3")
    test_logger3 = logging.getLogger("TestApp3")
    test_logger3.debug("This is a DEBUG message (TestApp3).") # Won't show
    test_logger3.info("This is an INFO message (TestApp3).") # Will show

    # Test 4: Root logger configuration
    # print("\nTest 4: Root logger configuration")
    # setup_logging("DEBUG", "logs/root_test.log", logger_name=None)
    # logging.debug("Root DEBUG message.") # Accessing root logger directly
    # logging.info("Root INFO message.")
    # sub_logger = logging.getLogger("SubModule") # Gets 'SubModule' which is child of root
    # sub_logger.info("Message from sub_logger, should also go to root handlers.")

    print("\n--- Logger Setup Example Finished ---")
    print("Check 'logs/' directory for test_app.log, test_app_invalid.log if tests ran correctly.")
