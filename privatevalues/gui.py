import sys
import os
import tkinter as tk
from tkinter import ttk, simpledialog, messagebox
from .core import PrivateValues

class NewPackageDialog(simpledialog.Dialog):
    def __init__(self, parent, title=None):
        self.name_var = tk.StringVar()
        self.encrypt_var = tk.BooleanVar()
        super().__init__(parent, title)

    def body(self, master):
        ttk.Label(master, text="Enter sub-package name:").grid(row=0, sticky=tk.W)
        self.name_entry = ttk.Entry(master, textvariable=self.name_var)
        self.name_entry.grid(row=1, sticky=(tk.W, tk.E))
        self.encrypt_checkbox = ttk.Checkbutton(master, text="Encrypt key names", variable=self.encrypt_var)
        self.encrypt_checkbox.grid(row=2, sticky=tk.W)
        return self.name_entry

    def apply(self):
        self.result = self.name_var.get(), self.encrypt_var.get()

class SecretManager(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PrivateValues Secret Manager")
        self.geometry("600x400")
        self.pv = None
        self.password_cache = {}
        self.init_ui()
        if self.packages:
            self.package_list.selection_set(0)
            self.load_package_from_list()

    def init_ui(self):
        self.style = ttk.Style(self)

        main_frame = ttk.Frame(self, padding=15)
        main_frame.pack(fill=tk.BOTH, expand=True)

        left_frame = ttk.Frame(main_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))

        ttk.Label(left_frame, text="Secrets in Package:").pack(anchor=tk.W)
        self.secrets_list = tk.Listbox(left_frame, selectmode=tk.SINGLE, exportselection=False)
        self.secrets_list.pack(fill=tk.BOTH, expand=True)
        self.secrets_list.bind('<<ListboxSelect>>', self.show_secret)

        right_frame = ttk.Frame(main_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.Y)

        package_frame = ttk.LabelFrame(right_frame, text="Packages")
        package_frame.pack(fill=tk.X)

        self.packages = self.find_packages()
        self.package_var = tk.StringVar(value=self.packages)
        self.package_list = tk.Listbox(package_frame, listvariable=self.package_var, selectmode=tk.SINGLE, exportselection=False)
        self.package_list.pack(fill=tk.X)
        self.package_list.bind('<<ListboxSelect>>', self.load_package_from_list)
        self.package_list.bind('<Button-3>', self.show_package_context_menu)

        new_package_btn = ttk.Button(package_frame, text="New Package", command=self.new_package)
        new_package_btn.pack(fill=tk.X, pady=(5,0))

        self.action_frame = ttk.Frame(right_frame)
        self.action_frame.pack(pady=10, fill=tk.X)

        self.init_edit_widgets()
        self.init_password_widgets()

        self.show_password_widgets()

        self.bind("<Configure>", self.on_resize)


    def init_edit_widgets(self):
        self.edit_frame = ttk.LabelFrame(self.action_frame, text="Add/Edit Secret")
        ttk.Label(self.edit_frame, text="Key:").pack(anchor=tk.W)
        self.key_entry = ttk.Entry(self.edit_frame)
        self.key_entry.pack(fill=tk.X)
        ttk.Label(self.edit_frame, text="Value:").pack(anchor=tk.W)
        
        value_frame = ttk.Frame(self.edit_frame)
        value_frame.pack(fill=tk.X)
        self.value_entry = ttk.Entry(value_frame, show='*')
        self.value_entry.pack(side=tk.LEFT, expand=True, fill=tk.X)
        self.toggle_visibility_btn = ttk.Button(value_frame, text="Show", command=self.toggle_value_visibility, width=5)
        self.toggle_visibility_btn.pack(side=tk.RIGHT)

        button_frame = ttk.Frame(self.edit_frame)
        button_frame.pack(fill=tk.X, pady=5)
        ttk.Button(button_frame, text="Save", command=self.save_secret).pack(fill=tk.X, pady=2)
        ttk.Button(button_frame, text="New", command=self.new_secret).pack(fill=tk.X, pady=2)
        ttk.Button(button_frame, text="Rename", command=self.rename_secret).pack(fill=tk.X, pady=2)
        ttk.Button(button_frame, text="Delete", command=self.delete_secret).pack(fill=tk.X, pady=2)

    def init_password_widgets(self):
        self.password_frame = ttk.LabelFrame(self.action_frame, text="Unlock Package")
        ttk.Label(self.password_frame, text="Password:").pack(anchor=tk.W)
        self.password_entry = ttk.Entry(self.password_frame, show='*')
        self.password_entry.pack(fill=tk.X)
        self.password_entry.bind('<Return>', self.unlock_package)
        ttk.Button(self.password_frame, text="Unlock", command=self.unlock_package).pack(fill=tk.X, pady=5)

    def show_edit_widgets(self):
        self.password_frame.pack_forget()
        self.edit_frame.pack(fill=tk.X)

    def show_password_widgets(self):
        self.edit_frame.pack_forget()
        self.password_frame.pack(fill=tk.X)

    def find_packages(self):
        packages = [".privatevalues"]
        for f in os.listdir("."):
            if f.startswith(".privatevalues_"):
                packages.append(f)
        return packages

    def show_package_context_menu(self, event):
        selection_index = self.package_list.nearest(event.y)
        if not selection_index or self.package_list.get(selection_index) == ".privatevalues":
            return
        
        self.package_list.selection_clear(0, tk.END)
        self.package_list.selection_set(selection_index)
        
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="Rename", command=lambda: self.rename_package(selection_index))
        menu.add_command(label="Delete", command=lambda: self.delete_package(selection_index))
        menu.tk_popup(event.x_root, event.y_root)

    def rename_package(self, index):
        old_path = self.package_list.get(index)
        sub_name = old_path.replace(".privatevalues_", "")
        package_name = simpledialog.askstring("Rename Package", "Enter new sub-package name:", initialvalue=sub_name)

        if package_name and package_name != sub_name:
            new_path = f".privatevalues_{package_name}"
            if new_path in self.packages:
                messagebox.showwarning("Warning", f"Package '{new_path}' already exists.")
                return
            
            try:
                os.rename(old_path, new_path)
            except OSError as e:
                messagebox.showerror("Error", f"Could not rename package: {e}")
                return
            
            self.packages.remove(old_path)
            self.packages.append(new_path)
            self.package_list.delete(index)
            self.package_list.insert(index, new_path)
            self.package_list.selection_set(index)

            if old_path in self.password_cache:
                self.password_cache[new_path] = self.password_cache.pop(old_path)
            
            if self.pv and self.pv.path == old_path:
                self.pv.path = new_path

    def delete_package(self, index):
        package_path = self.package_list.get(index)
        if messagebox.askyesno("Confirm", f"Are you sure you want to delete package '{package_path}' and all its secrets?"):
            try:
                os.remove(package_path)
            except OSError as e:
                messagebox.showerror("Error", f"Could not delete package: {e}")
                return

            self.packages.remove(package_path)
            self.password_cache.pop(package_path, None)
            self.package_list.delete(index)

            if self.pv and self.pv.path == package_path:
                self.pv = None
                self.secrets_list.delete(0, tk.END)
                self.key_entry.delete(0, tk.END)
                self.value_entry.delete(0, tk.END)
                self.show_password_widgets()
                
                if self.package_list.size() > 0:
                    self.package_list.selection_set(0)
                    self.load_package_from_list()

    def unlock_package(self, event=None):
        password = self.password_entry.get()
        selection = self.package_list.curselection()
        if not selection:
            return
        package_path = self.package_list.get(selection[0])

        try:
            self.pv = PrivateValues(path=package_path, password=password)
            self.password_cache[package_path] = password
            self.show_edit_widgets()
            self.refresh_secrets_list()
        except ValueError as e:
            messagebox.showerror("Error", str(e))
        finally:
            self.password_entry.delete(0, tk.END)

    def load_package_from_list(self, event=None):
        selection = self.package_list.curselection()
        if not selection:
            return
        package_path = self.package_list.get(selection[0])
        self.secrets_list.delete(0, tk.END)
        self.key_entry.delete(0, tk.END)
        self.value_entry.delete(0, tk.END)

        if package_path in self.password_cache:
            try:
                self.pv = PrivateValues(path=package_path, password=self.password_cache[package_path])
                self.show_edit_widgets()
                self.refresh_secrets_list()
            except ValueError:
                self.password_cache.pop(package_path, None)
                self.show_password_widgets()
        else:
            self.pv = None
            self.show_password_widgets()

    def new_package(self):
        dialog = NewPackageDialog(self, title="New Package")
        if dialog.result:
            package_name, encrypt_keys = dialog.result
            if package_name:
                new_path = f".privatevalues_{package_name}"
                if new_path not in self.packages:
                    self.packages.append(new_path)
                    self.package_list.insert(tk.END, new_path)
                
                password = simpledialog.askstring("New Password", f"Create a password for {new_path}:", show='*')
                if password:
                    self.pv = PrivateValues(path=new_path, password=password, encrypt_keys=encrypt_keys)
                    self.password_cache[new_path] = password
                    self.refresh_secrets_list()
                    
                    idx = self.package_list.get(0, tk.END).index(new_path)
                    self.package_list.selection_clear(0, tk.END)
                    self.package_list.selection_set(idx)
                    self.show_edit_widgets()
                else:
                    if new_path in self.packages:
                        self.packages.remove(new_path)
                        idx = self.package_list.get(0, tk.END).index(new_path)
                        self.package_list.delete(idx)

    def refresh_secrets_list(self):
        self.secrets_list.delete(0, tk.END)
        if self.pv:
            for key in self.pv.get_all_keys():
                self.secrets_list.insert(tk.END, key)

    def show_secret(self, event=None):
        selection = self.secrets_list.curselection()
        if not selection:
            return
        key = self.secrets_list.get(selection[0])
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, key)
        self.value_entry.delete(0, tk.END)
        self.value_entry.insert(0, self.pv.get(key))
        self.value_entry.config(show='*')
        self.toggle_visibility_btn.config(text="Show")

    def toggle_value_visibility(self):
        if self.value_entry.cget('show') == '*':
            self.value_entry.config(show='')
            self.toggle_visibility_btn.config(text="Hide")
        else:
            self.value_entry.config(show='*')
            self.toggle_visibility_btn.config(text="Show")

    def on_resize(self, event):
        base_title = "PrivateValues Secret Manager"
        tip_small = " - Window too small"
        tip_right_click = " - Tip: Right-click a package to rename or delete"

        if event.width < 550 or event.height < 400:
            self.title(base_title + tip_small)
        else:
            self.title(base_title + tip_right_click)

    def new_secret(self):
        self.secrets_list.selection_clear(0, tk.END)
        self.key_entry.delete(0, tk.END)
        self.value_entry.delete(0, tk.END)
        self.key_entry.focus_set()

    

    def rename_secret(self):
        selection = self.secrets_list.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a secret to rename.")
            return

        old_key = self.secrets_list.get(selection[0])
        new_key = simpledialog.askstring("Rename Secret", "Enter new key name:", initialvalue=old_key)

        if new_key and new_key != old_key:
            try:
                if self.pv.rename(old_key, new_key):
                    self.refresh_secrets_list()
                    # Find and select the renamed key
                    all_keys = self.secrets_list.get(0, tk.END)
                    if new_key in all_keys:
                        new_index = all_keys.index(new_key)
                        self.secrets_list.selection_set(new_index)
                        self.show_secret()
                else:
                    messagebox.showerror("Error", f"Could not find key '{old_key}' to rename.")
            except ValueError as e:
                messagebox.showerror("Error", str(e))

    def save_secret(self):
        key = self.key_entry.get()
        value = self.value_entry.get()
        if self.pv and key and value:
            self.pv.set(key, value)
            self.refresh_secrets_list()
            
            # Find and select the saved key
            all_keys = self.secrets_list.get(0, tk.END)
            if key in all_keys:
                idx = all_keys.index(key)
                self.secrets_list.selection_set(idx)
        else:
            messagebox.showwarning("Warning", "Key and Value cannot be empty.")

    def delete_secret(self):
        selection = self.secrets_list.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a secret to delete.")
            return
        
        key = self.secrets_list.get(selection[0])
        if messagebox.askyesno("Confirm", f"Are you sure you want to delete '{key}'?"):
            if self.pv.delete(key):
                self.refresh_secrets_list()
                self.key_entry.delete(0, tk.END)
                self.value_entry.delete(0, tk.END)
            else:
                messagebox.showerror("Error", f"Could not delete key '{key}'.")

def main():
    try:
        import tkinter as tk
        from tkinter import ttk
    except ImportError:
        print("tkinter is not installed. Please install it to use the GUI.")
        sys.exit(1)
        
    app = SecretManager()
    app.mainloop()

if __name__ == "__main__":
    main()