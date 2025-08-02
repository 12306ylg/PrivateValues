# PrivateValues

A simple tool to encrypt and manage secrets in open-source projects.

## Features

*   Strong encryption for your secrets.
*   Optional encryption for secret keys.
*   Easy-to-use command-line interface (CLI) and graphical user interface (GUI).
*   Support for multiple secret packages (e.g., for different environments).

## Installation

To install PrivateValues, simply run:

```bash
pip install .
```

This will install the `privatevalues` and `privatevalues-gui` commands, and make the `PrivateValues` module available for import in your Python code.

## Usage

### CLI

Initialize the secret storage. By default, it creates a `.privatevalues` file.

```bash
# Default initialization
privatevalues init

# Initialize with encrypted key names
privatevalues init --encrypt-keys
```

You can also specify a different path for your package:
```bash
privatevalues init --path .my_other_secrets
```

Set a secret:
```bash
privatevalues set my_secret "my_value"
```

Get a secret:
```bash
privatevalues get my_secret
```

List all secrets in a package:
```bash
privatevalues list
```

Delete a secret:
```bash
privatevalues delete my_secret
```

Rename a secret key:
```bash
privatevalues rename my_secret my_new_secret
```

Rename a package:
```bash
privatevalues rename-package my_package my_new_package
```

Delete a package:
```bash
privatevalues delete-package my_package
```

To use a different package, use the `--path` argument:
```bash
privatevalues --path .my_other_secrets set db_pass "12345"
```

### GUI

Launch the GUI with the following command:

```bash
privatevalues-gui
```

The GUI provides a user-friendly interface to manage your secrets and packages. You can:
*   Create new packages, with an option to encrypt key names.
*   Manage secrets using the "Save", "New", "Rename", and "Delete" buttons.
*   Right-click on packages in the package list to rename or delete them.
*   The window title provides helpful tips, including a warning when the window is too small to display all controls.

### In Code

```python
from privatevalues import PrivateValues

# Initialize with key encryption enabled
pv = PrivateValues(encrypt_keys=True)

# Set a secret
pv.set("api_key", "your_api_key")

# Get a secret
api_key = pv.get("api_key")
print(f"API Key: {api_key}")

# List all secret keys
keys = pv.get_all_keys()
print("All keys:", keys)

# Create a sub-package for different secrets
# This will create a new file named .privatevalues_database
db_secrets = pv.sub_package("database")
db_secrets.set("password", "db_password")
```