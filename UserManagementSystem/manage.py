#!/usr/bin/env python
"""
Django's command-line utility for administrative tasks.
"""
import os
import sys


def main():
    """
    Run administrative tasks.
    """
    # Set the default Django settings module
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'UserManagementSystem.settings')

    try:
        # Import and execute the Django management command
        from django.core.management import execute_from_command_line
        execute_from_command_line(sys.argv)
    except ImportError as exc:
        # Provide a more informative error message
        raise ImportError(
            "Couldn't import Django. Make sure it's installed and "
            "available on your PYTHONPATH environment variable. "
            "Did you forget to activate a virtual environment?"
        ) from exc


if __name__ == '__main__':
    main()