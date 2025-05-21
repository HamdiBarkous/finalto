import unittest
from unittest.mock import patch, mock_open, MagicMock
import configparser
import os
import sys

# Ensure the config and src directories are in the Python path for imports
# This might be needed if running tests directly from the tests directory
# or if the test runner doesn't handle project structure well.
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Now we can import AppSettings
from config.settings import AppSettings

class TestAppSettings(unittest.TestCase):

    def _get_default_config_content(self):
        return """
[FIX_SERVER]
Host = 127.0.0.1
Port = 5001
SenderCompID = DEFAULT_SENDER
TargetCompID = DEFAULT_TARGET
HeartbeatIntervalSeconds = 30

[ACCOUNT]
Username = default_user

[APPLICATION]
LogLevel = INFO
LogFile = logs/default_app.log
"""

    def _get_example_config_content(self):
        return """
[FIX_SERVER]
Host = example.host.com
Port = 5002
SenderCompID = EXAMPLE_SENDER
TargetCompID = EXAMPLE_TARGET
HeartbeatIntervalSeconds = 45

[ACCOUNT]
Username = example_user
Password = example_password

[APPLICATION]
LogLevel = DEBUG
LogFile = logs/example_app.log
"""

    @patch('config.settings.os.makedirs')
    @patch('config.settings.os.path.exists')
    @patch('config.settings.configparser.ConfigParser.read')
    def test_load_settings_successful(self, mock_read, mock_exists, mock_makedirs):
        """Test successful loading of settings from a mocked config.ini file."""
        mock_exists.return_value = True # Assume config.ini exists

        # Mock the ConfigParser instance that will be created within AppSettings
        mock_parser_instance = configparser.ConfigParser()
        
        # Prepare the data for the parser as if it read from a file
        config_data = {
            'FIX_SERVER': {
                'Host': 'testhost.com',
                'Port': '1234',
                'SenderCompID': 'TESTSENDER',
                'TargetCompID': 'TESTTARGET',
                'HeartbeatIntervalSeconds': '60'
            },
            'ACCOUNT': {
                'Username': 'testuser',
                'Password': 'testpassword'
            },
            'APPLICATION': {
                'LogLevel': 'DEBUG',
                'LogFile': 'logs/test_app.log'
            }
        }
        # Populate the mock_parser_instance by overriding its sections() and get() methods
        # or by directly setting its internal dictionary if possible (less direct).
        # Easier: mock its `read_dict` behavior or ensure `mock_read` (which is already ConfigParser.read)
        # results in this state. For this test, we'll assume `mock_read` populates it
        # and AppSettings uses the standard `get` methods.
        
        # To simulate `read` correctly, we need `ConfigParser` to actually parse something.
        # The easiest way is to let `read_string` do the job on a mock parser.
        # Since AppSettings creates its own parser, we patch `ConfigParser` constructor.
        
        with patch('config.settings.configparser.ConfigParser') as mock_ConfigParser:
            # Configure the mock_ConfigParser_instance that AppSettings will use
            mock_cp_instance = mock_ConfigParser.return_value
            
            # This function will be called by AppSettings when it does self.parser.read(filepath)
            def side_effect_read(filepath):
                # Simulate reading the config_data by populating the mock ConfigParser instance
                mock_cp_instance.read_dict(config_data)
            
            mock_cp_instance.read.side_effect = side_effect_read
            
            # We also need to mock 'get' for sections that might be missing but have fallbacks
            # or are optional. For this test, all are provided.
            def get_side_effect(section, key, fallback=None):
                if fallback is configparser._UNSET : # if configparser.get raises NoOptionError
                    if section in config_data and key in config_data[section]:
                         return config_data[section][key]
                    raise configparser.NoOptionError(key,section)
                return config_data.get(section, {}).get(key, fallback)

            mock_cp_instance.get.side_effect = get_side_effect
            mock_cp_instance.getint.side_effect = lambda s, k, fallback=None: int(get_side_effect(s,k,fallback))


            settings = AppSettings(config_filepath="dummy_config.ini")

            self.assertEqual(settings.fix_host, 'testhost.com')
            self.assertEqual(settings.fix_port, 1234)
            self.assertEqual(settings.fix_sender_comp_id, 'TESTSENDER')
            self.assertEqual(settings.fix_target_comp_id, 'TESTTARGET')
            self.assertEqual(settings.fix_heartbeat_interval, 60)
            self.assertEqual(settings.account_username, 'testuser')
            self.assertEqual(settings.account_password, 'testpassword')
            self.assertEqual(settings.app_log_level, 'DEBUG')
            self.assertEqual(settings.app_log_file, 'logs/test_app.log')
            
            # Check if log directory creation was attempted
            log_dir_path = os.path.join(project_root, "logs") # AppSettings resolves this
            mock_makedirs.assert_called_once_with(log_dir_path, exist_ok=True)


    @patch('config.settings.os.makedirs')
    @patch('config.settings.os.path.exists')
    @patch('config.settings.configparser.ConfigParser') # Patch the constructor
    def test_load_fallback_to_example_ini(self, MockConfigParser, mock_os_exists, mock_os_makedirs):
        """Test fallback to config.example.ini if config.ini is missing."""
        
        # Simulate config.ini not existing, but config.example.ini existing
        def os_exists_side_effect(path):
            if path.endswith("config.ini"): # Path to primary config file
                return False 
            if path.endswith("config.example.ini"): # Path to example
                return True
            if "logs" in path : # For log directory check
                 return False # assume log dir doesn't exist initially
            return False # Default for other paths if any

        mock_os_exists.side_effect = os_exists_side_effect
        
        mock_cp_instance = MockConfigParser.return_value
        example_data = self._get_example_config_content()
        
        # Simulate that parser.read(example_config_path) populates the parser
        def read_side_effect(filepath):
            if "example.ini" in filepath:
                mock_cp_instance.read_string(example_data)
            # else: if it tries to read config.ini, it would be empty or error
        mock_cp_instance.read.side_effect = read_side_effect

        settings = AppSettings(config_filepath="config.ini") # Request primary, should fallback

        self.assertEqual(settings.fix_host, 'example.host.com')
        self.assertEqual(settings.fix_port, 5002)
        self.assertEqual(settings.fix_sender_comp_id, 'EXAMPLE_SENDER')
        self.assertEqual(settings.fix_target_comp_id, 'EXAMPLE_TARGET')
        self.assertEqual(settings.fix_heartbeat_interval, 45)
        self.assertEqual(settings.account_username, 'example_user')
        self.assertEqual(settings.account_password, 'example_password')
        self.assertEqual(settings.app_log_level, 'DEBUG')
        
        # Check that the correct file path was attempted for reading (the example one)
        # The first call to mock_cp_instance.read would be for config.ini (which is "empty" as it doesn't exist),
        # the second one for config.example.ini
        self.assertIn("example.ini", mock_cp_instance.read.call_args_list[0][0][0])


    @patch('config.settings.os.makedirs')
    @patch('config.settings.os.path.exists')
    @patch('config.settings.configparser.ConfigParser')
    def test_missing_optional_keys_and_defaults(self, MockConfigParser, mock_os_exists, mock_os_makedirs):
        """Test handling of missing optional keys and application of default values."""
        mock_os_exists.return_value = True # Assume config.ini exists

        mock_cp_instance = MockConfigParser.return_value
        # Config data missing 'Password' (optional) and 'HeartbeatIntervalSeconds' (has fallback)
        # Also missing 'LogLevel' and 'LogFile' (have fallbacks)
        minimal_config_data = """
[FIX_SERVER]
Host = minimalhost
Port = 7000
SenderCompID = MIN_SENDER
TargetCompID = MIN_TARGET

[ACCOUNT]
Username = min_user
""" # APPLICATION section is missing entirely

        def read_side_effect(filepath):
            mock_cp_instance.read_string(minimal_config_data)
        mock_cp_instance.read.side_effect = read_side_effect

        settings = AppSettings(config_filepath="dummy_config.ini")

        self.assertEqual(settings.fix_host, 'minimalhost')
        self.assertEqual(settings.fix_port, 7000)
        self.assertEqual(settings.fix_sender_comp_id, 'MIN_SENDER')
        self.assertEqual(settings.fix_target_comp_id, 'MIN_TARGET')
        
        # Test fallbacks
        self.assertEqual(settings.fix_heartbeat_interval, 30) # Default fallback in AppSettings
        self.assertIsNone(settings.account_password) # Optional, no fallback value, should be None
        self.assertEqual(settings.app_log_level, 'INFO') # Default fallback
        self.assertEqual(settings.app_log_file, 'logs/app.log') # Default fallback


    @patch('config.settings.os.makedirs')
    @patch('config.settings.os.path.exists')
    @patch('config.settings.configparser.ConfigParser')
    def test_missing_required_keys_raises_error(self, MockConfigParser, mock_os_exists, mock_os_makedirs):
        """Test that missing required keys raise a ValueError."""
        mock_os_exists.return_value = True

        mock_cp_instance = MockConfigParser.return_value
        # Config data missing required 'SenderCompID'
        invalid_config_data = """
[FIX_SERVER]
Host = host_no_sender
Port = 8000
TargetCompID = TARGET_ONLY
"""
        def read_side_effect(filepath):
            mock_cp_instance.read_string(invalid_config_data)
        mock_cp_instance.read.side_effect = read_side_effect
        
        # Simulate .get() behavior for the ConfigParser instance used by AppSettings
        # When a required key is missing, .get() would raise NoOptionError
        def get_side_effect(section, key, fallback=None):
            if section == 'FIX_SERVER' and key == 'SenderCompID':
                 # This is the crucial part for required=True in AppSettings.get_setting
                raise configparser.NoOptionError(key, section) 
            
            # Minimal simulation for other keys potentially accessed before the error
            if section == 'FIX_SERVER' and key == 'Host': return 'host_no_sender'
            if section == 'FIX_SERVER' and key == 'Port': return '8000' # String form
            if section == 'FIX_SERVER' and key == 'TargetCompID': return 'TARGET_ONLY'
            if section == 'FIX_SERVER' and key == 'HeartbeatIntervalSeconds': return '30' # Fallback will be applied by AppSettings

            # Fallback for other sections/keys if AppSettings tries to read them.
            # For ACCOUNT and APPLICATION, they are missing, so NoSectionError would be more accurate
            # but for this test, we only care about the SenderCompID error.
            if section in ['ACCOUNT', 'APPLICATION']:
                raise configparser.NoSectionError(section)
            
            # Default for any other .get calls
            if fallback is not configparser._UNSET:
                return fallback
            raise configparser.NoOptionError(key, section)

        mock_cp_instance.get.side_effect = get_side_effect
        mock_cp_instance.getint.side_effect = lambda s, k, fallback=None: int(mock_cp_instance.get(s,k,fallback=str(fallback) if fallback is not configparser._UNSET else None))


        with self.assertRaisesRegex(ValueError, "Missing required configuration: section='FIX_SERVER', key='SenderCompID'"):
            AppSettings(config_filepath="dummy_config.ini")


    @patch('config.settings.os.path.exists')
    @patch('config.settings.configparser.ConfigParser')
    def test_log_directory_creation(self, MockConfigParser, mock_os_exists):
        """Test that os.makedirs is called if the log directory doesn't exist."""
        
        # Simulate log directory not existing, then existing after makedirs
        log_dir_path_relative = "logs" 
        # AppSettings._resolve_config_path and then _load_settings will form the absolute path.
        # Let's find out what that path would be.
        # project_root = os.path.dirname(os.path.dirname(os.path.abspath(config.settings.__file__)))
        # This is tricky because config.settings.__file__ is not available directly here easily.
        # We'll rely on the fact that AppSettings calls os.path.join(project_root, "logs")
        # So, we need to know where AppSettings *thinks* project_root is.
        # The AppSettings._resolve_config_path uses os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        # where __file__ is config/settings.py. So project_root is parent of 'config'.
        
        # For the test, we can simply check the argument to os.makedirs.
        # The AppSettings will make it absolute if it's relative.
        # log_dir_abs = os.path.join(project_root, "config", "..", "logs") # Simplified
        # More robustly:
        # config_module_dir = os.path.dirname(config.settings.__file__) -> this is hard to get in test without importing config directly
        # settings_file_dir = os.path.join(project_root, 'config')
        # For this test, we assume AppSettings correctly forms an absolute path for 'logs/'
        # and we just need to ensure `mock_os_makedirs` is called with something ending in '/logs'.

        mock_os_exists.side_effect = lambda path: not path.endswith(log_dir_path_relative) if "logs" in path else True
        
        with patch('config.settings.os.makedirs') as mock_os_makedirs_dynamic:
            mock_cp_instance = MockConfigParser.return_value
            default_config = self._get_default_config_content()
            mock_cp_instance.read_string(default_config) # Populate parser
            
            # Call AppSettings
            AppSettings(config_filepath="dummy_config.ini")

            # Assert that os.makedirs was called for the log directory
            # The path passed to makedirs will be an absolute path.
            # We check if it was called, and can inspect call_args if needed.
            mock_os_makedirs_dynamic.assert_called_once()
            called_path = mock_os_makedirs_dynamic.call_args[0][0]
            self.assertTrue(called_path.endswith(os.sep + "default_app.log")) # Path to file
            # No, it should be called with the directory, not the file path.
            # AppSettings._load_settings does: log_dir = os.path.dirname(self.app_log_file)
            # then, if log_dir is relative: log_dir = os.path.join(project_root, log_dir)
            # then, if log_dir and not os.path.exists(log_dir): os.makedirs(log_dir)
            # So, for 'logs/default_app.log', log_dir is 'logs'.
            # If project_root is '/app', then it calls makedirs with '/app/logs'.
            self.assertTrue(called_path.endswith(os.sep + "logs"))


    @patch('config.settings.os.makedirs') # Mock makedirs to prevent actual dir creation
    @patch('config.settings.os.path.exists')
    @patch('config.settings.configparser.ConfigParser')
    def test_file_not_found_neither_config_nor_example(self, MockConfigParser, mock_os_exists, mock_os_makedirs):
        """Test FileNotFoundError if neither config.ini nor config.example.ini exists."""
        mock_os_exists.return_value = False # Simulate no config files existing
        
        with self.assertRaises(FileNotFoundError):
            AppSettings(config_filepath="config.ini")

if __name__ == '__main__':
    unittest.main()
