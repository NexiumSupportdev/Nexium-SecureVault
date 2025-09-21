import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
from password_checker import PasswordChecker
from data_manager import DataManager
from security_features import SecurityManager
import pyperclip

class NexiumSecureVault:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("🔐 Nexium SecureVault")
        self.root.geometry("1000x700")
        self.root.configure(bg='#1a1a1a')
        
        self.password_checker = PasswordChecker()
        self.data_manager = DataManager()
        self.security_manager = SecurityManager()
        self.master_password = None
        self.is_authenticated = False
        
        # Configure style
        self.setup_style()
        
        # Authenticate user
        self.authenticate_user()
        
        if self.is_authenticated:
            self.setup_ui()
    
    def setup_style(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure colors
        style.configure('TLabel', background='#1a1a1a', foreground='white')
        style.configure('TFrame', background='#1a1a1a')
        style.configure('TNotebook', background='#1a1a1a')
        style.configure('TNotebook.Tab', background='#2d2d2d', foreground='white')
        style.map('TNotebook.Tab', background=[('selected', '#4a4a4a')])
        style.configure('TEntry', fieldbackground='#2d2d2d', foreground='white')
        style.configure('TText', fieldbackground='#2d2d2d', foreground='white')
        style.configure('TButton', background='#8a2be2', foreground='white')
        style.map('TButton', background=[('active', '#9932cc')])
    

    
    def authenticate_user(self):
        """Authenticate existing user"""
        if self.data_manager.is_first_time():
            messagebox.showerror("Error", "No master password found. Please use the web version to create your master password first.")
            self.root.quit()
            return
        
        max_attempts = 3
        attempts = 0
        
        while attempts < max_attempts:
            password = simpledialog.askstring(
                "Authentication", 
                f"Enter your master password (Attempt {attempts + 1}/{max_attempts}):", 
                show='*'
            )
            
            if password is None:  # User cancelled
                self.root.quit()
                return
            
            if self.data_manager.verify_master_password(password):
                self.master_password = password
                self.is_authenticated = True
                messagebox.showinfo("Success", "Welcome back!")
                return
            else:
                attempts += 1
                if attempts < max_attempts:
                    messagebox.showerror("Error", f"Invalid password. {max_attempts - attempts} attempts remaining.")
        
        messagebox.showerror("Error", "Too many failed attempts. Application will close.")
        self.root.quit()
    
    def setup_ui(self):
        # Header
        header_frame = ttk.Frame(self.root)
        header_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(header_frame, text="🔐 Nexium SecureVault", 
                 font=('Arial', 20, 'bold')).pack(side='left')
        
        # Action buttons
        action_frame = ttk.Frame(header_frame)
        action_frame.pack(side='right')
        
        ttk.Button(action_frame, text="📤 Export", command=self.export_data).pack(side='left', padx=2)
        ttk.Button(action_frame, text="📥 Import", command=self.import_data).pack(side='left', padx=2)
        ttk.Button(action_frame, text="🚪 Logout", command=self.logout).pack(side='left', padx=2)
        
        # Main notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Password Checker Tab
        self.checker_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.checker_frame, text="🔍 Password Checker")
        self.setup_checker_tab()
        
        # Password Manager Tab
        self.manager_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.manager_frame, text="🔐 Password Manager")
        self.setup_manager_tab()
        
        # Secure Notes Tab
        self.notes_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.notes_frame, text="📝 Secure Notes")
        self.setup_notes_tab()
    
    def setup_checker_tab(self):
        ttk.Label(self.checker_frame, text="Password Strength Checker", 
                 font=('Arial', 14, 'bold')).pack(pady=10)
        
        ttk.Label(self.checker_frame, text="Enter password:").pack()
        self.password_entry = ttk.Entry(self.checker_frame, show="*", width=40)
        self.password_entry.pack(pady=5)
        
        ttk.Button(self.checker_frame, text="Check Strength", 
                  command=self.check_password).pack(pady=5)
        
        self.strength_label = ttk.Label(self.checker_frame, text="", 
                                       font=('Arial', 12, 'bold'))
        self.strength_label.pack(pady=5)
        
        self.feedback_text = tk.Text(self.checker_frame, height=5, width=60)
        self.feedback_text.pack(pady=5)
        
        ttk.Button(self.checker_frame, text="Generate Strong Password", 
                  command=self.generate_password).pack(pady=5)
    
    def setup_manager_tab(self):
        ttk.Label(self.manager_frame, text="🔐 Password Manager", 
                 font=('Arial', 14, 'bold')).pack(pady=10)
        
        # Add password form
        form_frame = ttk.LabelFrame(self.manager_frame, text="➕ Add New Password")
        form_frame.pack(fill='x', padx=10, pady=5)
        
        # Create grid layout
        ttk.Label(form_frame, text="Title/Site:").grid(row=0, column=0, sticky='w', padx=5, pady=2)
        self.title_entry = ttk.Entry(form_frame, width=25)
        self.title_entry.grid(row=0, column=1, padx=5, pady=2)
        
        ttk.Label(form_frame, text="Username:").grid(row=0, column=2, sticky='w', padx=5, pady=2)
        self.username_entry = ttk.Entry(form_frame, width=25)
        self.username_entry.grid(row=0, column=3, padx=5, pady=2)
        
        ttk.Label(form_frame, text="URL:").grid(row=1, column=0, sticky='w', padx=5, pady=2)
        self.url_entry = ttk.Entry(form_frame, width=25)
        self.url_entry.grid(row=1, column=1, padx=5, pady=2)
        
        ttk.Label(form_frame, text="Category:").grid(row=1, column=2, sticky='w', padx=5, pady=2)
        self.category_var = tk.StringVar()
        self.category_combo = ttk.Combobox(form_frame, textvariable=self.category_var, width=22,
                                          values=['Social Media', 'Work', 'Banking', 'Shopping', 'Email', 'Gaming', 'Other'])
        self.category_combo.grid(row=1, column=3, padx=5, pady=2)
        
        ttk.Label(form_frame, text="Password:").grid(row=2, column=0, sticky='w', padx=5, pady=2)
        self.pwd_entry = ttk.Entry(form_frame, show="*", width=25)
        self.pwd_entry.grid(row=2, column=1, padx=5, pady=2)
        
        # Password buttons
        pwd_btn_frame = ttk.Frame(form_frame)
        pwd_btn_frame.grid(row=2, column=2, columnspan=2, padx=5, pady=2)
        
        ttk.Button(pwd_btn_frame, text="🎲 Generate", 
                  command=self.generate_and_fill_password).pack(side='left', padx=2)
        ttk.Button(pwd_btn_frame, text="👁️ Show", 
                  command=self.toggle_password_visibility).pack(side='left', padx=2)
        
        ttk.Button(form_frame, text="💾 Save Password", 
                  command=self.add_password).grid(row=3, column=1, columnspan=2, pady=10)
        
        # Password list
        list_frame = ttk.LabelFrame(self.manager_frame, text="📋 Saved Passwords")
        list_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Treeview for passwords
        columns = ('Title', 'Username', 'Category', 'Created')
        self.password_tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=10)
        
        for col in columns:
            self.password_tree.heading(col, text=col)
            self.password_tree.column(col, width=150)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient='vertical', command=self.password_tree.yview)
        self.password_tree.configure(yscrollcommand=scrollbar.set)
        
        self.password_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # Context menu
        self.password_tree.bind('<Button-3>', self.show_password_context_menu)
        self.password_tree.bind('<Double-1>', self.view_password_details)
        
        # Load passwords
        self.refresh_password_list()
    
    def setup_notes_tab(self):
        ttk.Label(self.notes_frame, text="📝 Secure Notes", 
                 font=('Arial', 14, 'bold')).pack(pady=10)
        
        # Note form
        form_frame = ttk.LabelFrame(self.notes_frame, text="➕ Create New Note")
        form_frame.pack(fill='x', padx=10, pady=5)
        
        # Title and category row
        title_frame = ttk.Frame(form_frame)
        title_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(title_frame, text="Title:").pack(side='left')
        self.note_title_entry = ttk.Entry(title_frame, width=30)
        self.note_title_entry.pack(side='left', padx=5)
        
        ttk.Label(title_frame, text="Category:").pack(side='left', padx=(20, 0))
        self.note_category_var = tk.StringVar()
        self.note_category_combo = ttk.Combobox(title_frame, textvariable=self.note_category_var, width=20,
                                               values=['Personal', 'Work', 'Financial', 'Medical', 'Legal', 'Ideas', 'Other'])
        self.note_category_combo.pack(side='left', padx=5)
        
        # Tags
        tags_frame = ttk.Frame(form_frame)
        tags_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(tags_frame, text="Tags (comma separated):").pack(side='left')
        self.note_tags_entry = ttk.Entry(tags_frame, width=40)
        self.note_tags_entry.pack(side='left', padx=5)
        
        # Content
        ttk.Label(form_frame, text="Content:").pack(anchor='w', padx=5)
        
        content_frame = ttk.Frame(form_frame)
        content_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.note_content = tk.Text(content_frame, height=8, width=80, bg='#2d2d2d', fg='white', insertbackground='white')
        note_scrollbar = ttk.Scrollbar(content_frame, orient='vertical', command=self.note_content.yview)
        self.note_content.configure(yscrollcommand=note_scrollbar.set)
        
        self.note_content.pack(side='left', fill='both', expand=True)
        note_scrollbar.pack(side='right', fill='y')
        
        ttk.Button(form_frame, text="💾 Save Note", 
                  command=self.save_note).pack(pady=10)
        
        # Notes list
        list_frame = ttk.LabelFrame(self.notes_frame, text="📋 Saved Notes")
        list_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Treeview for notes
        columns = ('Title', 'Category', 'Preview', 'Created')
        self.notes_tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=8)
        
        for col in columns:
            self.notes_tree.heading(col, text=col)
            if col == 'Preview':
                self.notes_tree.column(col, width=300)
            else:
                self.notes_tree.column(col, width=120)
        
        # Scrollbar for notes
        notes_scrollbar = ttk.Scrollbar(list_frame, orient='vertical', command=self.notes_tree.yview)
        self.notes_tree.configure(yscrollcommand=notes_scrollbar.set)
        
        self.notes_tree.pack(side='left', fill='both', expand=True)
        notes_scrollbar.pack(side='right', fill='y')
        
        # Context menu for notes
        self.notes_tree.bind('<Button-3>', self.show_notes_context_menu)
        self.notes_tree.bind('<Double-1>', self.view_note_details)
        
        # Load notes
        self.refresh_notes_list()
    
    def show_notes_context_menu(self, event):
        """Show context menu for note items"""
        item = self.notes_tree.selection()[0] if self.notes_tree.selection() else None
        if not item:
            return
        
        context_menu = tk.Menu(self.root, tearoff=0)
        context_menu.add_command(label="👁️ View Details", command=self.view_note_details)
        context_menu.add_separator()
        context_menu.add_command(label="🗑️ Delete", command=self.delete_note)
        
        try:
            context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            context_menu.grab_release()
    
    def view_note_details(self, event=None):
        """View note details in a popup"""
        selection = self.notes_tree.selection()
        if not selection:
            return
        
        item = selection[0]
        note_id = int(self.notes_tree.item(item, 'tags')[0])
        
        # Find note
        notes = self.data_manager.get_notes()
        note_data = next((n for n in notes if n['id'] == note_id), None)
        
        if not note_data:
            return
        
        # Create details window
        details_window = tk.Toplevel(self.root)
        details_window.title(f"Note - {note_data['title']}")
        details_window.geometry("600x500")
        details_window.configure(bg='#1a1a1a')
        
        # Display details
        ttk.Label(details_window, text=note_data['title'], font=('Arial', 14, 'bold')).pack(pady=10)
        
        info_frame = ttk.Frame(details_window)
        info_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(info_frame, text=f"Category: {note_data['category']}").pack(side='left')
        ttk.Label(info_frame, text=f"Tags: {note_data['tags']}").pack(side='right')
        
        # Content
        content_frame = ttk.Frame(details_window)
        content_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        content_text = tk.Text(content_frame, bg='#2d2d2d', fg='white', state='disabled')
        content_scrollbar = ttk.Scrollbar(content_frame, orient='vertical', command=content_text.yview)
        content_text.configure(yscrollcommand=content_scrollbar.set)
        
        content_text.config(state='normal')
        content_text.insert('1.0', note_data['content'])
        content_text.config(state='disabled')
        
        content_text.pack(side='left', fill='both', expand=True)
        content_scrollbar.pack(side='right', fill='y')
    
    def delete_note(self):
        """Delete selected note"""
        selection = self.notes_tree.selection()
        if not selection:
            return
        
        item = selection[0]
        note_id = int(self.notes_tree.item(item, 'tags')[0])
        
        if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this note?"):
            if self.data_manager.delete_note(note_id):
                messagebox.showinfo("Success", "Note deleted successfully!")
                self.refresh_notes_list()
            else:
                messagebox.showerror("Error", "Failed to delete note!")
    

    
    def check_password(self):
        password = self.password_entry.get()
        result = self.password_checker.check_strength(password)
        
        self.strength_label.config(text=f"Strength: {result['strength']} ({result['score']}/100)")
        
        self.feedback_text.delete(1.0, tk.END)
        if result['feedback']:
            self.feedback_text.insert(tk.END, "Suggestions:\n" + "\n".join(result['feedback']))
        else:
            self.feedback_text.insert(tk.END, "Excellent password!")
    
    def generate_password(self):
        password = self.password_checker.generate_password()
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, password)
        self.check_password()
    
    def generate_and_fill_password(self):
        """Generate strong password and fill the entry"""
        password = self.password_checker.generate_password()
        self.pwd_entry.delete(0, tk.END)
        self.pwd_entry.insert(0, password)
        
        # Show strength
        strength = self.password_checker.check_strength(password)
        messagebox.showinfo("Generated Password", 
                           f"Strong password generated!\nStrength: {strength['strength']} ({strength['score']}/100)")
    
    def toggle_password_visibility(self):
        """Toggle password visibility in entry"""
        if self.pwd_entry.cget('show') == '*':
            self.pwd_entry.config(show='')
        else:
            self.pwd_entry.config(show='*')
    
    def add_password(self):
        title = self.title_entry.get().strip()
        username = self.username_entry.get().strip()
        password = self.pwd_entry.get()
        url = self.url_entry.get().strip()
        category = self.category_var.get()
        
        if not title or not password:
            messagebox.showerror("Error", "Title and password are required!")
            return
        
        if self.data_manager.add_password(title, username, password, url, category):
            messagebox.showinfo("Success", "Password saved successfully!")
            
            # Clear form
            self.title_entry.delete(0, tk.END)
            self.username_entry.delete(0, tk.END)
            self.pwd_entry.delete(0, tk.END)
            self.url_entry.delete(0, tk.END)
            self.category_var.set('')
            
            # Refresh list
            self.refresh_password_list()
        else:
            messagebox.showerror("Error", "Failed to save password!")
    
    def refresh_password_list(self):
        """Refresh the password list"""
        # Clear existing items
        for item in self.password_tree.get_children():
            self.password_tree.delete(item)
        
        # Load passwords
        passwords = self.data_manager.get_passwords()
        for pwd in passwords:
            self.password_tree.insert('', 'end', values=(
                pwd['title'],
                pwd['username'],
                pwd['category'],
                pwd['created_at'][:10] if pwd['created_at'] else ''
            ), tags=(pwd['id'],))
    
    def show_password_context_menu(self, event):
        """Show context menu for password items"""
        item = self.password_tree.selection()[0] if self.password_tree.selection() else None
        if not item:
            return
        
        context_menu = tk.Menu(self.root, tearoff=0)
        context_menu.add_command(label="👁️ View Details", command=self.view_password_details)
        context_menu.add_command(label="📋 Copy Password", command=self.copy_password)
        context_menu.add_command(label="📋 Copy Username", command=self.copy_username)
        context_menu.add_separator()
        context_menu.add_command(label="🗑️ Delete", command=self.delete_password)
        
        try:
            context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            context_menu.grab_release()
    
    def view_password_details(self, event=None):
        """View password details in a popup"""
        selection = self.password_tree.selection()
        if not selection:
            return
        
        item = selection[0]
        password_id = int(self.password_tree.item(item, 'tags')[0])
        
        # Find password
        passwords = self.data_manager.get_passwords()
        password_data = next((p for p in passwords if p['id'] == password_id), None)
        
        if not password_data:
            return
        
        # Create details window
        details_window = tk.Toplevel(self.root)
        details_window.title(f"Password Details - {password_data['title']}")
        details_window.geometry("400x300")
        details_window.configure(bg='#1a1a1a')
        
        # Display details
        ttk.Label(details_window, text="Title:", font=('Arial', 10, 'bold')).pack(anchor='w', padx=10, pady=2)
        ttk.Label(details_window, text=password_data['title']).pack(anchor='w', padx=20)
        
        ttk.Label(details_window, text="Username:", font=('Arial', 10, 'bold')).pack(anchor='w', padx=10, pady=2)
        ttk.Label(details_window, text=password_data['username']).pack(anchor='w', padx=20)
        
        ttk.Label(details_window, text="URL:", font=('Arial', 10, 'bold')).pack(anchor='w', padx=10, pady=2)
        ttk.Label(details_window, text=password_data['url']).pack(anchor='w', padx=20)
        
        ttk.Label(details_window, text="Category:", font=('Arial', 10, 'bold')).pack(anchor='w', padx=10, pady=2)
        ttk.Label(details_window, text=password_data['category']).pack(anchor='w', padx=20)
        
        ttk.Label(details_window, text="Password:", font=('Arial', 10, 'bold')).pack(anchor='w', padx=10, pady=2)
        
        pwd_frame = ttk.Frame(details_window)
        pwd_frame.pack(anchor='w', padx=20, pady=5)
        
        pwd_var = tk.StringVar(value='•' * len(password_data['password']))
        pwd_label = ttk.Label(pwd_frame, textvariable=pwd_var, font=('Courier', 10))
        pwd_label.pack(side='left')
        
        def toggle_pwd():
            if pwd_var.get().startswith('•'):
                pwd_var.set(password_data['password'])
            else:
                pwd_var.set('•' * len(password_data['password']))
        
        ttk.Button(pwd_frame, text="👁️", command=toggle_pwd).pack(side='left', padx=5)
        ttk.Button(pwd_frame, text="📋", command=lambda: pyperclip.copy(password_data['password'])).pack(side='left')
    
    def copy_password(self):
        """Copy password to clipboard"""
        selection = self.password_tree.selection()
        if not selection:
            return
        
        item = selection[0]
        password_id = int(self.password_tree.item(item, 'tags')[0])
        
        passwords = self.data_manager.get_passwords()
        password_data = next((p for p in passwords if p['id'] == password_id), None)
        
        if password_data:
            pyperclip.copy(password_data['password'])
            messagebox.showinfo("Success", "Password copied to clipboard!")
    
    def copy_username(self):
        """Copy username to clipboard"""
        selection = self.password_tree.selection()
        if not selection:
            return
        
        item = selection[0]
        password_id = int(self.password_tree.item(item, 'tags')[0])
        
        passwords = self.data_manager.get_passwords()
        password_data = next((p for p in passwords if p['id'] == password_id), None)
        
        if password_data:
            pyperclip.copy(password_data['username'])
            messagebox.showinfo("Success", "Username copied to clipboard!")
    
    def delete_password(self):
        """Delete selected password"""
        selection = self.password_tree.selection()
        if not selection:
            return
        
        item = selection[0]
        password_id = int(self.password_tree.item(item, 'tags')[0])
        
        if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this password?"):
            if self.data_manager.delete_password(password_id):
                messagebox.showinfo("Success", "Password deleted successfully!")
                self.refresh_password_list()
            else:
                messagebox.showerror("Error", "Failed to delete password!")
    
    def save_note(self):
        title = self.note_title_entry.get().strip()
        content = self.note_content.get(1.0, tk.END).strip()
        category = self.note_category_var.get()
        tags = self.note_tags_entry.get().strip()
        
        if not title or not content:
            messagebox.showerror("Error", "Title and content are required!")
            return
        
        if self.data_manager.add_note(title, content, category, tags):
            messagebox.showinfo("Success", "Note saved successfully!")
            
            # Clear form
            self.note_title_entry.delete(0, tk.END)
            self.note_content.delete(1.0, tk.END)
            self.note_category_var.set('')
            self.note_tags_entry.delete(0, tk.END)
            
            # Refresh list
            self.refresh_notes_list()
        else:
            messagebox.showerror("Error", "Failed to save note!")
    
    def refresh_notes_list(self):
        """Refresh the notes list"""
        # Clear existing items
        for item in self.notes_tree.get_children():
            self.notes_tree.delete(item)
        
        # Load notes
        notes = self.data_manager.get_notes()
        for note in notes:
            preview = note['content'][:50] + '...' if len(note['content']) > 50 else note['content']
            self.notes_tree.insert('', 'end', values=(
                note['title'],
                note['category'],
                preview,
                note['created_at'][:10] if note['created_at'] else ''
            ), tags=(note['id'],))
    
    def export_data(self):
        """Export encrypted data to file"""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Export Nexium Vault Data"
        )
        
        if file_path:
            if self.data_manager.export_data(file_path):
                messagebox.showinfo("Success", "Data exported successfully!")
            else:
                messagebox.showerror("Error", "Failed to export data!")
    
    def import_data(self):
        """Import encrypted data from file"""
        file_path = filedialog.askopenfilename(
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Import Nexium Vault Data"
        )
        
        if file_path:
            if messagebox.askyesno("Confirm Import", "This will replace all current data. Continue?"):
                try:
                    import shutil
                    shutil.copy2(file_path, self.data_manager.data_path)
                    messagebox.showinfo("Success", "Data imported successfully! Please restart the application.")
                    self.refresh_password_list()
                    self.refresh_notes_list()
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to import data: {e}")
    
    def logout(self):
        """Logout and clear sensitive data"""
        if messagebox.askyesno("Confirm Logout", "Are you sure you want to logout?"):
            self.master_password = None
            self.is_authenticated = False
            self.data_manager.encryption_key = None
            messagebox.showinfo("Success", "Logged out successfully!")
            self.root.quit()
    
    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = NexiumSecureVault()
    app.run()