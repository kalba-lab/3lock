"""
Simple GUI for 3Lock using tkinter.
No external dependencies.
"""

import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from pathlib import Path
from typing import Optional

from ..storage import Vault, VaultError, WrongPasswordError
from ..clipboard import SecureClipboard


class PasswordDialog(tk.Toplevel):
    """Modal dialog for password entry."""
    
    def __init__(self, parent, title: str, confirm: bool = False):
        super().__init__(parent)
        self.title(title)
        self.password: Optional[str] = None
        self.transient(parent)
        self.grab_set()
        
        # Size and center on parent
        width, height = 300, 200 if confirm else 150
        self.resizable(False, False)
        
        # Wait for parent to be positioned, then center
        self.update_idletasks()
        px = parent.winfo_x()
        py = parent.winfo_y()
        pw = parent.winfo_width()
        ph = parent.winfo_height()
        x = px + (pw - width) // 2
        y = py + (ph - height) // 2
        self.geometry(f"{width}x{height}+{x}+{y}")
        
        frame = ttk.Frame(self, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="Password:").pack(anchor=tk.W)
        self.entry = ttk.Entry(frame, show="•", width=30)
        self.entry.pack(fill=tk.X, pady=(5, 10))
        self.entry.focus()
        
        if confirm:
            ttk.Label(frame, text="Confirm:").pack(anchor=tk.W)
            self.confirm_entry = ttk.Entry(frame, show="•", width=30)
            self.confirm_entry.pack(fill=tk.X, pady=(5, 10))
        else:
            self.confirm_entry = None
        
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Button(btn_frame, text="OK", command=self._ok).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=self._cancel).pack(side=tk.RIGHT)
        
        self.bind("<Return>", lambda e: self._ok())
        self.bind("<Escape>", lambda e: self._cancel())
        
        self.wait_window()
    
    def _ok(self):
        pwd = self.entry.get()
        if len(pwd) < 8:
            messagebox.showerror("Error", "Password must be at least 8 characters.")
            return
        
        if self.confirm_entry:
            if pwd != self.confirm_entry.get():
                messagebox.showerror("Error", "Passwords don't match.")
                return
        
        self.password = pwd
        self.destroy()
    
    def _cancel(self):
        self.destroy()


class TopicDialog(tk.Toplevel):
    """Dialog for adding/editing a topic."""
    
    def __init__(self, parent, title: str = "Add Topic", 
                 initial_title: str = "", initial_note: str = "",
                 is_edit: bool = False):
        super().__init__(parent)
        self.title(title)
        self.result: Optional[dict] = None
        self.transient(parent)
        self.grab_set()
        
        width, height = 450, 400
        self.resizable(False, False)
        
        # Center on parent
        self.update_idletasks()
        px = parent.winfo_x()
        py = parent.winfo_y()
        pw = parent.winfo_width()
        ph = parent.winfo_height()
        x = px + (pw - width) // 2
        y = py + (ph - height) // 2
        self.geometry(f"{width}x{height}+{x}+{y}")
        
        frame = ttk.Frame(self, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        ttk.Label(frame, text="Title:").pack(anchor=tk.W)
        self.title_entry = ttk.Entry(frame, width=45)
        self.title_entry.insert(0, initial_title)
        self.title_entry.pack(fill=tk.X, pady=(5, 10))
        self.title_entry.focus()
        
        # Note (multiline with scrollbar)
        ttk.Label(frame, text="Note:").pack(anchor=tk.W)
        note_frame = ttk.Frame(frame)
        note_frame.pack(fill=tk.BOTH, expand=True, pady=(5, 10))
        
        note_scroll = ttk.Scrollbar(note_frame)
        note_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.note_entry = tk.Text(note_frame, width=45, height=8, 
                                   yscrollcommand=note_scroll.set, wrap=tk.WORD)
        self.note_entry.insert("1.0", initial_note)
        self.note_entry.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        note_scroll.config(command=self.note_entry.yview)
        
        # Password
        pwd_label = "Password (leave empty to keep current):" if is_edit else "Password:"
        ttk.Label(frame, text=pwd_label).pack(anchor=tk.W)
        self.pwd_entry = ttk.Entry(frame, show="•", width=45)
        self.pwd_entry.pack(fill=tk.X, pady=(5, 10))
        
        # Buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Button(btn_frame, text="Save", command=self._save).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=self._cancel).pack(side=tk.RIGHT)
        
        self.bind("<Escape>", lambda e: self._cancel())
        
        self.wait_window()
    
    def _save(self):
        title = self.title_entry.get().strip()
        if not title:
            messagebox.showerror("Error", "Title is required.")
            return
        
        self.result = {
            "title": title,
            "note": self.note_entry.get("1.0", tk.END).strip(),
            "password": self.pwd_entry.get() if self.pwd_entry.get() else None
        }
        self.destroy()
    
    def _cancel(self):
        self.destroy()


class SettingsDialog(tk.Toplevel):
    """Settings dialog with master password change and about info."""
    
    def __init__(self, parent, on_change_password):
        super().__init__(parent)
        self.title("Settings")
        self.transient(parent)
        self.grab_set()
        self.on_change_password = on_change_password
        
        width, height = 350, 300
        self.resizable(False, False)
        
        # Center on parent
        self.update_idletasks()
        px = parent.winfo_x()
        py = parent.winfo_y()
        pw = parent.winfo_width()
        ph = parent.winfo_height()
        x = px + (pw - width) // 2
        y = py + (ph - height) // 2
        self.geometry(f"{width}x{height}+{x}+{y}")
        
        frame = ttk.Frame(self, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Security section
        ttk.Label(frame, text="Security", font=("", 11, "bold")).pack(anchor=tk.W)
        ttk.Button(frame, text="Change Master Password", 
                   command=self._change_password).pack(fill=tk.X, pady=(5, 15))
        
        # About section
        ttk.Label(frame, text="About", font=("", 11, "bold")).pack(anchor=tk.W)
        
        about_text = """3Lock v0.1.0
Simple. Local. Secure.

• All data encrypted with AES-256
• Password never leaves your device
• Open source"""
        
        ttk.Label(frame, text=about_text, justify=tk.LEFT).pack(anchor=tk.W, pady=5)
        
        # Website link
        link = ttk.Label(frame, text="🔗 3lock.app", foreground="blue", cursor="hand2")
        link.pack(anchor=tk.W)
        link.bind("<Button-1>", lambda e: self._open_website())
        
        # Close button
        ttk.Button(frame, text="Close", command=self.destroy).pack(side=tk.BOTTOM, pady=(10, 0))
    
    def _change_password(self):
        self.destroy()
        self.on_change_password()
    
    def _open_website(self):
        import webbrowser
        webbrowser.open("https://3lock.app")


class App(tk.Tk):
    """Main application window."""
    
    def __init__(self, vault_path: Path, timeout_minutes: int = 5):
        super().__init__()
        
        self.vault_path = Path(vault_path)
        self.vault: Optional[Vault] = None
        self.clipboard = SecureClipboard(clear_after=30)
        self.timeout_minutes = timeout_minutes
        self._last_activity = time.time()
        self._running = True
        
        self.title("3Lock")
        self.minsize(600, 400)
        
        # Center window on screen
        self._center_window(800, 500)
        
        self._setup_ui()
        self._setup_bindings()
        self._start_timeout_monitor()
        
        # Start with unlock
        self.after(100, self._unlock)
    
    def _center_window(self, width: int, height: int):
        """Center window on screen."""
        screen_w = self.winfo_screenwidth()
        screen_h = self.winfo_screenheight()
        x = (screen_w - width) // 2
        y = (screen_h - height) // 2
        self.geometry(f"{width}x{height}+{x}+{y}")
    
    def _setup_ui(self):
        """Create main UI layout."""
        # Main container
        main = ttk.Frame(self, padding=10)
        main.pack(fill=tk.BOTH, expand=True)
        
        # Left panel - topic list (fixed width)
        left = ttk.Frame(main, width=200)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        left.pack_propagate(False)
        
        ttk.Label(left, text="Topics", font=("", 12, "bold")).pack(anchor=tk.W)
        
        # Topic list with scrollbar
        list_frame = ttk.Frame(left)
        list_frame.pack(fill=tk.BOTH, expand=True, pady=(5, 10))
        
        list_scroll = ttk.Scrollbar(list_frame)
        list_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.topic_list = tk.Listbox(list_frame, selectmode=tk.SINGLE, 
                                      yscrollcommand=list_scroll.set)
        self.topic_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        list_scroll.config(command=self.topic_list.yview)
        self.topic_list.bind("<<ListboxSelect>>", self._on_topic_select)
        
        btn_frame = ttk.Frame(left)
        btn_frame.pack(fill=tk.X)
        
        ttk.Button(btn_frame, text="Add", command=self._add_topic).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Edit", command=self._edit_topic).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Delete", command=self._delete_topic).pack(side=tk.LEFT, padx=2)
        
        # Right panel - details (expands)
        right = ttk.Frame(main)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Header with title and settings
        header = ttk.Frame(right)
        header.pack(fill=tk.X)
        ttk.Label(header, text="Details", font=("", 12, "bold")).pack(side=tk.LEFT)
        ttk.Button(header, text="⚙", width=3, command=self._show_settings).pack(side=tk.RIGHT)
        
        # Title row
        title_frame = ttk.Frame(right)
        title_frame.pack(fill=tk.X, pady=5)
        ttk.Label(title_frame, text="Title:").pack(side=tk.LEFT)
        self.detail_title = ttk.Label(title_frame, text="-")
        self.detail_title.pack(side=tk.LEFT, padx=10)
        
        # Note label
        ttk.Label(right, text="Note:").pack(anchor=tk.W)
        
        # Note with scrollbar (expands, but limited)
        note_frame = ttk.Frame(right)
        note_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        note_scroll = ttk.Scrollbar(note_frame)
        note_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.detail_note = tk.Text(note_frame, state=tk.DISABLED, wrap=tk.WORD,
                                    yscrollcommand=note_scroll.set)
        self.detail_note.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        note_scroll.config(command=self.detail_note.yview)
        
        # Password row (always at bottom of right panel)
        pwd_frame = ttk.Frame(right)
        pwd_frame.pack(fill=tk.X, pady=10, side=tk.BOTTOM)
        ttk.Label(pwd_frame, text="Password:").pack(side=tk.LEFT)
        ttk.Label(pwd_frame, text="••••••••").pack(side=tk.LEFT, padx=10)
        self.copy_btn = ttk.Button(pwd_frame, text="Copy", command=self._copy_password, state=tk.DISABLED)
        self.copy_btn.pack(side=tk.LEFT, padx=10)
        
        # Status bar
        self.status = ttk.Label(self, text="Ready", relief=tk.SUNKEN, anchor=tk.W)
        self.status.pack(side=tk.BOTTOM, fill=tk.X)
    
    def _setup_bindings(self):
        """Setup keyboard bindings."""
        self.bind_all("<Button-1>", lambda e: self._touch_activity())
        self.bind_all("<Key>", lambda e: self._touch_activity())
        self.protocol("WM_DELETE_WINDOW", self._quit)
    
    def _unlock(self):
        """Show password dialog and unlock vault."""
        if not self.vault_path.exists():
            # Create new vault
            dialog = PasswordDialog(self, "Create Master Password", confirm=True)
            if not dialog.password:
                self.destroy()
                return
            
            self._set_status("Creating vault...")
            try:
                self.vault = Vault.create(self.vault_path, dialog.password)
                self._set_status("Vault created")
            except Exception as e:
                messagebox.showerror("Error", str(e))
                self.destroy()
                return
        else:
            # Open existing vault
            attempts = 0
            while attempts < 5:
                dialog = PasswordDialog(self, "Unlock Vault")
                if not dialog.password:
                    self.destroy()
                    return
                
                self._set_status("Unlocking...")
                try:
                    self.vault = Vault.open(self.vault_path, dialog.password)
                    self._set_status("Unlocked")
                    break
                except WrongPasswordError:
                    attempts += 1
                    remaining = 5 - attempts
                    if remaining > 0:
                        messagebox.showerror("Error", f"Wrong password. {remaining} attempts remaining.")
                    else:
                        messagebox.showerror("Error", "Too many failed attempts.")
                        self.destroy()
                        return
                except Exception as e:
                    messagebox.showerror("Error", str(e))
                    self.destroy()
                    return
        
        self._refresh_topics()
    
    def _refresh_topics(self):
        """Refresh topic list."""
        self.topic_list.delete(0, tk.END)
        
        if self.vault:
            for topic in self.vault.list_topics():
                self.topic_list.insert(tk.END, topic.title)
        
        self._clear_details()
    
    def _clear_details(self):
        """Clear detail panel."""
        self.detail_title.config(text="-")
        self.detail_note.config(state=tk.NORMAL)
        self.detail_note.delete(1.0, tk.END)
        self.detail_note.config(state=tk.DISABLED)
        self.copy_btn.config(state=tk.DISABLED)
    
    def _on_topic_select(self, event):
        """Handle topic selection."""
        selection = self.topic_list.curselection()
        if not selection or not self.vault:
            return
        
        idx = selection[0]
        topics = self.vault.list_topics()
        if idx >= len(topics):
            return
        
        topic = topics[idx]
        note = self.vault.get_note(topic.id)
        
        self.detail_title.config(text=topic.title)
        self.detail_note.config(state=tk.NORMAL)
        self.detail_note.delete(1.0, tk.END)
        self.detail_note.insert(1.0, note)
        self.detail_note.config(state=tk.DISABLED)
        self.copy_btn.config(state=tk.NORMAL)
        
        # Store selected topic id
        self._selected_topic_id = topic.id
    
    def _add_topic(self):
        """Add new topic."""
        dialog = TopicDialog(self, "Add Topic")
        if not dialog.result or not self.vault:
            return
        
        password = dialog.result["password"] or ""
        self.vault.add_topic(
            dialog.result["title"],
            dialog.result["note"],
            password
        )
        self.vault.save()
        self._refresh_topics()
        self._set_status("Topic added")
    
    def _edit_topic(self):
        """Edit selected topic."""
        if not hasattr(self, '_selected_topic_id') or not self.vault:
            return
        
        topic = self.vault.get_topic(self._selected_topic_id)
        if not topic:
            return
        
        note = self.vault.get_note(self._selected_topic_id)
        
        dialog = TopicDialog(self, "Edit Topic", topic.title, note, is_edit=True)
        if not dialog.result:
            return
        
        self.vault.update_topic(
            self._selected_topic_id,
            title=dialog.result["title"],
            note=dialog.result["note"],
            password=dialog.result["password"]
        )
        self.vault.save()
        self._refresh_topics()
        self._set_status("Topic updated")
    
    def _delete_topic(self):
        """Delete selected topic."""
        if not hasattr(self, '_selected_topic_id') or not self.vault:
            return
        
        topic = self.vault.get_topic(self._selected_topic_id)
        if not topic:
            return
        
        if not messagebox.askyesno("Confirm", f"Delete '{topic.title}'?"):
            return
        
        self.vault.delete_topic(self._selected_topic_id)
        self.vault.save()
        self._selected_topic_id = None
        self._refresh_topics()
        self._set_status("Topic deleted")
    
    def _copy_password(self):
        """Copy password to clipboard."""
        if not hasattr(self, '_selected_topic_id') or not self.vault:
            return
        
        password_bytes = self.vault.get_password_bytes(self._selected_topic_id)
        self.clipboard.copy_password(password_bytes)
        
        # Wipe from memory
        for i in range(len(password_bytes)):
            password_bytes[i] = 0
        
        self._set_status(f"Password copied (clears in {self.clipboard.clear_after}s)")
    
    def _change_master_password(self):
        """Change the master password."""
        if not self.vault:
            return
        
        # Get old password
        old_dialog = PasswordDialog(self, "Current Password")
        if not old_dialog.password:
            return
        old_password = old_dialog.password
        
        # Get new password with confirmation
        new_dialog = PasswordDialog(self, "New Master Password", confirm=True)
        if not new_dialog.password:
            return
        new_password = new_dialog.password
        
        self._set_status("Changing password...")
        self.update()
        
        try:
            self.vault.change_password(old_password, new_password)
            self._set_status("Master password changed!")
            messagebox.showinfo("Success", "Master password changed successfully.")
        except Exception as e:
            self._set_status("Password change failed")
            messagebox.showerror("Error", f"Failed to change password: {e}")
    
    def _show_settings(self):
        """Show settings dialog."""
        SettingsDialog(self, self._change_master_password)
    
    def _set_status(self, text: str):
        """Update status bar."""
        self.status.config(text=text)
    
    def _touch_activity(self):
        """Update last activity timestamp."""
        self._last_activity = time.time()
    
    def _start_timeout_monitor(self):
        """Start background timeout monitor."""
        def check_timeout():
            if not self._running:
                return
            
            idle_minutes = (time.time() - self._last_activity) / 60
            if idle_minutes >= self.timeout_minutes:
                self._lock_vault()
            else:
                self.after(10000, check_timeout)  # Check every 10 sec
        
        self.after(10000, check_timeout)
    
    def _lock_vault(self):
        """Lock vault due to timeout."""
        if self.vault:
            self.vault.lock()
            self.vault = None
        
        messagebox.showwarning("Timeout", "Session timed out. Vault locked.")
        self.destroy()
    
    def _quit(self):
        """Clean exit."""
        self._running = False
        if self.vault:
            self.vault.lock()
        self.clipboard.clear()
        self.destroy()


def run_gui(vault_path: Path, timeout_minutes: int = 5) -> int:
    """Run the GUI application."""
    try:
        app = App(vault_path, timeout_minutes)
        app.mainloop()
        return 0
    except Exception as e:
        print(f"Error: {e}")
        return 1