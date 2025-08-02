import argparse
from . import PrivateValues

def main():
    parser = argparse.ArgumentParser(description="Manage private values.")
    parser.add_argument("-p", "--path", default=".privatevalues", help="Path to the secret storage file.")
    subparsers = parser.add_subparsers(dest="command")

    # init command
    init_parser = subparsers.add_parser("init", help="Initialize the secret storage.")
    init_parser.add_argument("--encrypt-keys", action="store_true", help="Encrypt secret key names.")

    # get command
    get_parser = subparsers.add_parser("get", help="Get a secret.")
    get_parser.add_argument("key", help="The key of the secret to get.")

    # set command
    set_parser = subparsers.add_parser("set", help="Set a secret.")
    set_parser.add_argument("key", help="The key of the secret to set.")
    set_parser.add_argument("value", help="The value of the secret to set.")

    # list command
    list_parser = subparsers.add_parser("list", help="List all secret keys.")

    # delete command
    delete_parser = subparsers.add_parser("delete", help="Delete a secret.")
    delete_parser.add_argument("key", help="The key of the secret to delete.")

    # rename command
    rename_parser = subparsers.add_parser("rename", help="Rename a secret key.")
    rename_parser.add_argument("old_key", help="The current key of the secret.")
    rename_parser.add_argument("new_key", help="The new key for the secret.")

    # rename-package command
    rename_pkg_parser = subparsers.add_parser("rename-package", help="Rename a package.")
    rename_pkg_parser.add_argument("old_name", help="The current name of the package.")
    rename_pkg_parser.add_argument("new_name", help="The new name for the package.")

    # delete-package command
    delete_pkg_parser = subparsers.add_parser("delete-package", help="Delete a package.")
    delete_pkg_parser.add_argument("name", help="The name of the package to delete.")

    args = parser.parse_args()

    if args.command == "init":
        PrivateValues(path=args.path, encrypt_keys=args.encrypt_keys)
        print(f"Secret storage initialized at '{args.path}'.")
        if args.encrypt_keys:
            print("Key encryption is enabled for this package.")
        return

    if args.command == "rename-package":
        old_path = f".privatevalues_{args.old_name}"
        new_path = f".privatevalues_{args.new_name}"
        if not os.path.exists(old_path):
            print(f"Error: Package '{args.old_name}' not found.")
            return
        if os.path.exists(new_path):
            print(f"Error: Package '{args.new_name}' already exists.")
            return
        os.rename(old_path, new_path)
        print(f"Package '{args.old_name}' has been renamed to '{args.new_name}'.")
        return

    if args.command == "delete-package":
        path = f".privatevalues_{args.name}"
        if not os.path.exists(path):
            print(f"Error: Package '{args.name}' not found.")
            return
        # Add a confirmation step for safety
        confirm = input(f"Are you sure you want to delete package '{args.name}' and all its secrets? [y/N] ")
        if confirm.lower() == 'y':
            os.remove(path)
            print(f"Package '{args.name}' deleted.")
        else:
            print("Deletion cancelled.")
        return

    pv = PrivateValues(path=args.path)

    if args.command == "get":
        value = pv.get(args.key)
        if value is not None:
            print(value)
        else:
            print(f"Secret '{args.key}' not found.")
    elif args.command == "set":
        pv.set(args.key, args.value)
        print(f"Secret '{args.key}' set.")
    elif args.command == "list":
        keys = pv.get_all_keys()
        if keys:
            print("Stored keys:")
            for key in keys:
                print(f"- {key}")
        else:
            print("No secrets found in this package.")
    elif args.command == "delete":
        if pv.delete(args.key):
            print(f"Secret '{args.key}' deleted.")
        else:
            print(f"Secret '{args.key}' not found.")
    elif args.command == "rename":
        try:
            if pv.rename(args.old_key, args.new_key):
                print(f"Secret '{args.old_key}' has been renamed to '{args.new_key}'.")
            else:
                print(f"Secret '{args.old_key}' not found.")
        except ValueError as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    main()