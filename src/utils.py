# Utility functions for the FIXNA trading application.

import configparser
import os

def load_config(config_file="config/config.ini"):
    """
    Loads the application configuration from a .ini file.

    Args:
        config_file (str): Path to the configuration file.

    Returns:
        configparser.ConfigParser: Loaded configuration object.
    """
    config = configparser.ConfigParser()
    if not os.path.exists(config_file):
        raise FileNotFoundError(f"Configuration file not found: {config_file}. Please create one from config.example.ini.")
    config.read(config_file)
    return config

def get_project_root():
    """Returns the project root directory."""
    return os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Example of another utility function
def format_price(price):
    """
    Formats a price to two decimal places.
    """
    return f"{price:.2f}"
