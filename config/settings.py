import configparser
import os
import logging

# Get a logger for this module
logger = logging.getLogger(__name__)

class AppSettings:
    """
    Manages application settings from a configuration file.
    Uses configparser to read from an INI file.
    """
    def __init__(self, config_filepath="config.ini"):
        """
        Initializes the AppSettings instance.

        Args:
            config_filepath (str): Path to the configuration file.
                                   This can be an absolute path or relative to the project root.
        """
        self.parser = configparser.ConfigParser()
        self.config_file_path = self._resolve_config_path(config_filepath)
        
        if not os.path.exists(self.config_file_path):
            example_path = self._resolve_config_path("config.example.ini")
            if os.path.exists(example_path):
                logger.warning(f"Configuration file '{self.config_file_path}' not found. "
                               f"Loading from '{example_path}' as a fallback. "
                               "Please create your own config.ini for production settings.")
                self.parser.read(example_path)
            else:
                # This is a critical error, so log it before raising
                err_msg = (f"Configuration file '{self.config_file_path}' not found, and "
                           f"example configuration '{example_path}' is also missing.")
                logger.critical(err_msg)
                raise FileNotFoundError(err_msg)
        else:
            self.parser.read(self.config_file_path)
            logger.info(f"Configuration loaded from: {self.config_file_path}")

        self._load_settings()

    def _resolve_config_path(self, config_filename):
        """Resolves the path to the configuration file, assuming it's in the 'config' directory
           or the project root if specified as such."""
        # If config_filename is 'config.ini' or 'config.example.ini', look in 'config/' dir
        if config_filename in ["config.ini", "config.example.ini"]:
             # Project root is parent of 'config' directory which is parent of this file's directory
            project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            return os.path.join(project_root, "config", config_filename)
        # Allow absolute paths or paths relative to CWD for custom locations
        return config_filename


    def _load_settings(self):
        """Loads settings from the parsed configuration file into instance attributes."""
        # FIX Server settings
        self.fix_host = self.get_setting('FIX_SERVER', 'Host', fallback='127.0.0.1')
        self.fix_port = self.get_int_setting('FIX_SERVER', 'Port', fallback=5001)
        self.fix_sender_comp_id = self.get_setting('FIX_SERVER', 'SenderCompID', required=True)
        self.fix_target_comp_id = self.get_setting('FIX_SERVER', 'TargetCompID', required=True)
        self.fix_heartbeat_interval = self.get_int_setting('FIX_SERVER', 'HeartbeatIntervalSeconds', fallback=30)

        # Account settings
        self.account_username = self.get_setting('ACCOUNT', 'Username', fallback=None) # Optional
        self.account_password = self.get_setting('ACCOUNT', 'Password', fallback=None) # Optional

        # Application settings
        self.app_log_level = self.get_setting('APPLICATION', 'LogLevel', fallback='INFO').upper()
        self.app_log_file = self.get_setting('APPLICATION', 'LogFile', fallback='logs/app.log')
        
        # Ensure log directory exists if LogFile is specified
        if self.app_log_file:
            log_dir = os.path.dirname(self.app_log_file)
            # If log_dir is empty, it means LogFile is in the current dir or just a filename.
            # If it's relative, make it relative to project root.
            if not os.path.isabs(log_dir) and log_dir:
                project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                log_dir = os.path.join(project_root, log_dir)

            if log_dir and not os.path.exists(log_dir):
                try:
                    os.makedirs(log_dir, exist_ok=True)
                    logger.info(f"Created log directory: {log_dir}")
                except OSError as e:
                    logger.warning(f"Could not create log directory '{log_dir}': {e}")


    def get_setting(self, section, key, fallback=configparser._UNSET, required=False):
        """
        Retrieves a configuration value.
        If required is True and value is not found, raises an error.
        """
        try:
            value = self.parser.get(section, key)
            return value
        except (configparser.NoSectionError, configparser.NoOptionError):
            if required:
                err_msg = f"Missing required configuration: section='{section}', key='{key}' in '{self.config_file_path}'"
                logger.error(err_msg)
                raise ValueError(err_msg)
            if fallback is configparser._UNSET: # No fallback provided for optional value
                logger.debug(f"Optional key '{key}' not found in section '{section}', no fallback. Returning None.")
                return None
            logger.debug(f"Optional key '{key}' not found in section '{section}', using fallback: {fallback}")
            return fallback

    def get_int_setting(self, section, key, fallback=configparser._UNSET, required=False):
        """Retrieves a configuration value as an integer."""
        value_str = self.get_setting(section, key, fallback=str(fallback) if fallback is not configparser._UNSET else configparser._UNSET, required=required)
        if value_str is None: return None # Fallback was None or value not found and not required
        try:
            return int(value_str)
        except ValueError:
            err_msg = f"Invalid integer value for section='{section}', key='{key}': '{value_str}' in '{self.config_file_path}'"
            logger.error(err_msg)
            raise ValueError(err_msg)

    def get_boolean_setting(self, section, key, fallback=configparser._UNSET, required=False):
        """Retrieves a configuration value as a boolean."""
        value_str = self.get_setting(section, key, fallback=str(fallback).lower() if fallback is not configparser._UNSET else configparser._UNSET, required=required)
        if value_str is None: return None # Fallback was None or value not found and not required
        try:
            return self.parser._convert_to_boolean(value_str) # Use parser's method
        except ValueError: # Should not happen if using _convert_to_boolean properly
            err_msg = f"Invalid boolean value for section='{section}', key='{key}': '{value_str}' in '{self.config_file_path}'"
            logger.error(err_msg)
            raise ValueError(err_msg)


# Global settings object (optional, can be instantiated in main.py)
# For this structure, it's better to instantiate it where needed, typically in main.py.
# settings = AppSettings()

# Example of how to use this class:
if __name__ == "__main__":
    # Basic logging setup for the example, normally done in main.py by setup_logging
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logger.info("--- Example Usage of AppSettings ---")
    
    # Create a dummy config.ini for testing if it doesn't exist
    dummy_config_content = """
[FIX_SERVER]
Host = example.com
Port = 6001
SenderCompID = TESTSENDER
TargetCompID = TESTTARGET
HeartbeatIntervalSeconds = 45

[ACCOUNT]
Username = testuser

[APPLICATION]
LogLevel = DEBUG
LogFile = logs/example_app.log
"""
    project_root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    dummy_config_path = os.path.join(project_root_dir, "config", "config.ini")

    if not os.path.exists(dummy_config_path):
        logger.info(f"Creating dummy '{dummy_config_path}' for example usage...")
        os.makedirs(os.path.join(project_root_dir, "config"), exist_ok=True)
        with open(dummy_config_path, "w") as f:
            f.write(dummy_config_content)
        created_dummy = True
    else:
        created_dummy = False
        logger.info(f"Using existing '{dummy_config_path}' for example usage.")

    try:
        # Test with default path "config.ini"
        settings = AppSettings() # Looks for 'config/config.ini' by default relative to project root
        
        logger.info("\nLoaded Settings:")
        logger.info(f"  FIX Host: {settings.fix_host}")
        logger.info(f"  FIX Port: {settings.fix_port}")
        logger.info(f"  SenderCompID: {settings.fix_sender_comp_id}")
        logger.info(f"  TargetCompID: {settings.fix_target_comp_id}")
        logger.info(f"  Heartbeat Interval: {settings.fix_heartbeat_interval}s")
        logger.info(f"  Username: {settings.account_username}")
        logger.info(f"  Password: {'********' if settings.account_password else 'Not set'}")
        logger.info(f"  Log Level: {settings.app_log_level}")
        logger.info(f"  Log File: {settings.app_log_file}")

        # Test missing optional value (assuming Password is not in dummy_config_content)
        logger.info(f"  Account Password (raw): {settings.account_password}")
        
        # Test fallback for a non-existent key
        logger.info(f"  Custom Optional Setting (with fallback): {settings.get_setting('APPLICATION', 'NonExistentKey', fallback='DefaultValue')}")

        # Test required key missing (will raise error if uncommented and key is missing)
        # logger.error(f"  Custom Required Setting: {settings.get_setting('APPLICATION', 'DefinitelyMissingRequired', required=True)}")

    except FileNotFoundError as e:
        logger.critical(f"Error: {e}")
    except ValueError as e:
        logger.critical(f"Configuration Error: {e}")
    except Exception as e:
        logger.exception(f"An unexpected error occurred during AppSettings example: {e}")
    finally:
        if created_dummy:
            logger.info(f"\nRemoving dummy '{dummy_config_path}'...")
            os.remove(dummy_config_path)
            # Attempt to remove 'config' dir if it became empty (and was created by this script)
            try:
                config_dir_path = os.path.join(project_root_dir, "config")
                if os.path.exists(config_dir_path) and not os.listdir(config_dir_path):
                    # This check is basic, ensure it's truly empty and was meant to be removed
                    # os.rmdir(config_dir_path) # Careful with this
                    logger.info(f"Directory '{config_dir_path}' is now empty but not removed by example script.")
                    pass
            except OSError as e:
                logger.warning(f"Error removing dummy config directory: {e}")

    logger.info("\n--- End of Example Usage ---")
