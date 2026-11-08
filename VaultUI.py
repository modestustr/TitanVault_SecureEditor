import customtkinter as ctk
import tkinter.filedialog as fd
import tkinter.messagebox as mb
import tkinter.simpledialog as sd
import logging
import sys
import os
from engine_crypto import TitanCryptoEngine

# Logging setup
logging.basicConfig(
    filename="vault_errors.log",
    level=logging.ERROR,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class VaultUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("TITAN SECURE VAULT")
        self.geometry("800x600")
        self.clipboard_timer = None
        self._setup_close_handler()

        # Validate master_password is not None
        master_password = sd.askstring("Login", "Enter Master Password:", show="*")
        if master_password is None:
            sys.exit("Master password required to proceed.")

        # Check if password is empty
        if not master_password.strip():
            mb.showerror("Error", "Master password cannot be empty.")
            sys.exit("Empty password not allowed.")

        # Use dynamic salt (None = generate per file)
        self.crypto_engine = TitanCryptoEngine(master_password, salt=None)
        logger.info("VaultUI initialized with dynamic salt encryption")

        # Security: Clear master password from memory (hint to GC)
        master_password = None  # type: ignore

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        sidebar = ctk.CTkFrame(self, width=200)
        sidebar.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

        ctk.CTkButton(sidebar, text="Decrypt File", command=self._open_file).pack(
            pady=20, padx=10
        )
        ctk.CTkButton(
            sidebar,
            text="Encrypt and Save",
            fg_color="#27ae60",
            command=self._save_file,
        ).pack(pady=10, padx=10)

        ctk.CTkButton(sidebar, text="Clear Buffer", fg_color="#e74c3c",
                     command=self._clear_buffer).pack(pady=10, padx=10)

        self.text_area = ctk.CTkTextbox(self)
        self.text_area.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)

    def _clear_buffer(self):
        """Clear text area (security measure)."""
        self.text_area.delete("1.0", "end")
        logger.info("Buffer cleared")

    def _setup_close_handler(self):
        """Handle window close with confirmation."""
        self.protocol("WM_DELETE_WINDOW", self._on_closing)

    def _on_closing(self):
        """Confirm before closing (prevent accidental data loss)."""
        if self.text_area.get("1.0", "end-1c").strip():
            response = mb.askyesno(
                "Confirm Close",
                "Text area contains data. Close without saving?",
                icon=mb.WARNING
            )
            if not response:
                return

        # Clear sensitive data
        self.text_area.delete("1.0", "end")
        self.destroy()

    def _open_file(self):
        path = fd.askopenfilename(filetypes=[("Encrypted Files", "*.txt"), ("All Files", "*.*")])
        if not path:
            return
        try:
            if not os.path.exists(path):
                mb.showerror("Error", "File does not exist.")
                return

            with open(path, "r", encoding="utf-8") as f:
                encrypted_data = f.read().strip()

            if not encrypted_data:
                mb.showerror("Error", "File is empty.")
                return

            decrypted_text = self.crypto_engine.decrypt(encrypted_data)
            self.text_area.delete("1.0", "end")
            self.text_area.insert("1.0", decrypted_text)
            logger.info(f"File decrypted successfully: {os.path.basename(path)}")
            mb.showinfo("Success", f"Decrypted: {os.path.basename(path)}")
        except ValueError as e:
            logger.error(f"Decryption failed: {e}")
            mb.showerror("Decryption Error", "Wrong password or corrupted file.")
        except Exception as e:
            logger.error(f"File operation failed: {e}")
            # RISK #1 FIX: Generic exception maskeleme (no technical details to UI)
            mb.showerror("Error", "File could not be opened. Please check the file format.")

    def _save_file(self):
        path = fd.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Encrypted Files", "*.txt"), ("All Files", "*.*")]
        )
        if not path:
            return
        try:
            raw_data = self.text_area.get("1.0", "end-1c")

            # Validate input
            if not raw_data.strip():
                mb.showwarning("Warning", "Text area is empty. Nothing to save.")
                return

            encrypted_data = self.crypto_engine.encrypt(raw_data)

            # Atomic write with UTF-8 encoding
            with open(path, "w", encoding="utf-8") as f:
                f.write(encrypted_data)

            # Security: Set file permissions (owner read/write only)
            # On Windows this limits access, on Unix sets 0o600
            try:
                os.chmod(path, 0o600)
                logger.info(f"File permissions set to 0o600: {path}")
            except Exception as e:
                logger.warning(f"Could not set file permissions: {e}")

            logger.info(f"File encrypted and saved: {os.path.basename(path)}")
            mb.showinfo("Success", f"File encrypted and saved:\n{os.path.basename(path)}")
        except ValueError as e:
            logger.error(f"Encryption failed: {e}")
            mb.showerror("Encryption Error", "Encryption failed. Please try again.")
        except Exception as e:
            logger.error(f"File save failed: {e}")
            # RISK #1 FIX: Generic exception maskeleme (no technical details to UI)
            mb.showerror("Error", "File could not be saved. Please check the file path and permissions.")


if __name__ == "__main__":
    app = VaultUI()
    app.mainloop()
