import { App, Modal, Plugin, PluginSettingTab, Setting, MarkdownView } from "obsidian";

// ── Types ─────────────────────────────────────────────────────────────────

interface CryptoPadSettings {
  passphrase: string;
  rememberPassphrase: boolean;
  defaultMode: "encrypt" | "decrypt";
}

const DEFAULT_SETTINGS: CryptoPadSettings = {
  passphrase: "",
  rememberPassphrase: false,
  defaultMode: "encrypt",
};

// ── Crypto Utilities ──────────────────────────────────────────────────────

const PBKDF2_ITERATIONS = 200_000;
const SALT_LENGTH = 16;
const IV_LENGTH = 12;

function bufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToBuffer(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

async function deriveKey(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(passphrase),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptText(passphrase: string, plaintext: string): Promise<string> {
  if (!passphrase) throw new Error("Passphrase is required.");
  if (!plaintext) throw new Error("Text to encrypt/decrypt is required.");

  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const key = await deriveKey(passphrase, salt);

  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(plaintext)
  );

  const result = new Uint8Array(SALT_LENGTH + IV_LENGTH + encrypted.byteLength);
  result.set(salt, 0);
  result.set(iv, SALT_LENGTH);
  result.set(new Uint8Array(encrypted), SALT_LENGTH + IV_LENGTH);
  return bufferToBase64(result.buffer);
}

async function decryptText(passphrase: string, ciphertextB64: string): Promise<string> {
  if (!passphrase) throw new Error("Passphrase is required.");
  if (!ciphertextB64) throw new Error("Ciphertext is required.");

  let bytes: Uint8Array;
  try {
    bytes = base64ToBuffer(ciphertextB64.trim());
  } catch {
    throw new Error("Invalid ciphertext — not valid base64.");
  }

  if (bytes.byteLength <= SALT_LENGTH + IV_LENGTH) {
    throw new Error("Invalid ciphertext — data too short.");
  }

  const salt = bytes.slice(0, SALT_LENGTH);
  const iv = bytes.slice(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
  const ciphertext = bytes.slice(SALT_LENGTH + IV_LENGTH);
  const key = await deriveKey(passphrase, salt);

  let decrypted: ArrayBuffer;
  try {
    decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
  } catch {
    throw new Error("Decryption failed — wrong passphrase or corrupted data.");
  }

  return new TextDecoder().decode(decrypted);
}

// ── Modal ─────────────────────────────────────────────────────────────────

class CryptoPadModal extends Modal {
  private plugin: CryptoPadPlugin;
  private mode: "encrypt" | "decrypt" = "encrypt";
  private passInput!: HTMLInputElement;
  private inputArea!: HTMLTextAreaElement;
  private outputArea!: HTMLTextAreaElement;
  private errorEl!: HTMLDivElement;
  private resultBlock!: HTMLDivElement;
  private statusEl!: HTMLDivElement;
  private commandInput!: HTMLInputElement;

  constructor(app: App, plugin: CryptoPadPlugin) {
    super(app);
    this.plugin = plugin;
    this.mode = plugin.settings.defaultMode;
  }

  setMode(newMode: "encrypt" | "decrypt"): void {
    this.mode = newMode;
  }

  onOpen(): void {
    const { contentEl, modalEl } = this;
    contentEl.empty();
    contentEl.addClass("cryptopad-modal");
    modalEl.style.position = "relative";
    this.buildUI();

    // Get selected text from editor
    const selectedText = this.getSelectedText();
    if (selectedText) {
      this.inputArea.value = selectedText;
      this.inputArea.focus();
    }
  }

  private getSelectedText(): string {
    const view = this.app.workspace.getActiveViewOfType(MarkdownView);
    if (view && view.editor) {
      const selection = view.editor.getSelection();
      return selection || "";
    }
    return "";
  }

  private buildUI(): void {
    const { contentEl, modalEl } = this;

    // ── Header with status ──
    const header = contentEl.createDiv({ cls: "cryptopad-header" });
    header.createSpan({ cls: "cryptopad-title", text: "🔐 CryptoPad" });
    this.statusEl = header.createDiv({ cls: "cryptopad-status" });
    this.updateStatus();

    // ── Command line ──
    const commandRow = contentEl.createDiv({ cls: "cryptopad-command-row" });
    commandRow.createSpan({ text: ":" });
    this.commandInput = commandRow.createEl("input", {
      cls: "cryptopad-command-input",
      placeholder: "e/d/c/q",
    }) as HTMLInputElement;
    this.commandInput.autocomplete = "off";
    this.commandInput.spellcheck = false;
    this.commandInput.tabIndex = 0;

    // ── Body ──
    const bodyEl = contentEl.createDiv({ cls: "cryptopad-body" });

    // Passphrase row
    bodyEl.createEl("label", { cls: "cryptopad-label", text: "Passphrase" });
    const passRow = bodyEl.createDiv({ cls: "cryptopad-pass-row" });
    this.passInput = passRow.createEl("input", {
      cls: "cryptopad-input-field",
      placeholder: "Enter passphrase... (Ctrl+P to toggle visibility)",
    }) as HTMLInputElement;
    this.passInput.type = "password";
    this.passInput.autocomplete = "off";
    this.passInput.spellcheck = false;
    this.passInput.tabIndex = 1;
    if (this.plugin.settings.rememberPassphrase) {
      this.passInput.value = this.plugin.settings.passphrase;
    }

    // Remember row
    const rememberRow = bodyEl.createDiv({ cls: "cryptopad-remember-row" });
    const rememberLabel = rememberRow.createEl("label", {
      cls: "cryptopad-checkbox-label",
    });
    const rememberCheck = rememberLabel.createEl("input") as HTMLInputElement;
    rememberCheck.type = "checkbox";
    rememberCheck.checked = this.plugin.settings.rememberPassphrase;
    rememberCheck.tabIndex = 2;
    rememberLabel.appendText(" Remember passphrase");

    // Input area
    const inputLabel = bodyEl.createEl("label", {
      cls: "cryptopad-label",
      text: "Text to encrypt/decrypt",
    });
    this.inputArea = bodyEl.createEl("textarea", {
      cls: "cryptopad-input-field cryptopad-textarea",
      placeholder: "Type or paste text here... (Ctrl+Enter to process, Ctrl+C to clear)",
    }) as HTMLTextAreaElement;
    this.inputArea.rows = 3;
    this.inputArea.spellcheck = false;
    this.inputArea.tabIndex = 2;

    // Error
    this.errorEl = bodyEl.createDiv({ cls: "cryptopad-error" });
    this.errorEl.style.display = "none";

    // Result block
    this.resultBlock = bodyEl.createDiv({ cls: "cryptopad-result-block" });
    this.resultBlock.style.display = "none";
    const outputLabel = this.resultBlock.createEl("label", {
      cls: "cryptopad-label",
      text: "Encrypted output",
    });
    this.outputArea = this.resultBlock.createEl("textarea", {
      cls: "cryptopad-input-field cryptopad-textarea cryptopad-output",
    }) as HTMLTextAreaElement;
    this.outputArea.rows = 6;
    this.outputArea.readOnly = true;
    this.outputArea.spellcheck = false;
    this.outputArea.tabIndex = 4;

    // Help section (always visible)
    const helpEl = bodyEl.createDiv({ cls: "cryptopad-help" });
    helpEl.innerHTML = `
      <div class="cryptopad-help-title">⌨️ Keyboard Shortcuts</div>
      <div class="cryptopad-help-content">
        <div><strong>:e</strong> — Encrypt mode</div>
        <div><strong>:d</strong> — Decrypt mode</div>
        <div><strong>:c</strong> — Copy output</div>
        <div><strong>:q</strong> — Quit</div>
        <div><strong>Ctrl+Enter</strong> — Process</div>
        <div><strong>Ctrl+P</strong> — Show passphrase</div>
        <div><strong>Ctrl+C</strong> — Copy</div>
      </div>
    `;

    // Toast (attached to modal container for absolute positioning)
    const toast = modalEl.createDiv({ cls: "cryptopad-toast", text: "✅ Copied!" });

    // Helper to switch mode
    const switchMode = (newMode: "encrypt" | "decrypt") => {
      this.mode = newMode;
      this.resultBlock.style.display = "none";
      this.errorEl.style.display = "none";
      this.updateStatus();
      this.passInput.focus();
    };

    // ── Process action ──
    const handleAction = async () => {
      const passphrase = this.passInput.value.trim();
      const input = this.inputArea.value;

      this.errorEl.style.display = "none";
      this.resultBlock.style.display = "none";

      try {
        const remember = rememberCheck.checked;
        this.plugin.settings.rememberPassphrase = remember;
        this.plugin.settings.passphrase = remember ? passphrase : "";
        await this.plugin.saveSettings();

        const result =
          this.mode === "encrypt"
            ? await encryptText(passphrase, input)
            : await decryptText(passphrase, input);

        this.outputArea.value = result;
        this.resultBlock.style.display = "flex";
        this.outputArea.select();
      } catch (err: unknown) {
        this.errorEl.textContent = (err as Error).message;
        this.errorEl.style.display = "block";
      }
    };

    // ── Copy helper ──
    const showToast = () => {
      toast.addClass("cryptopad-toast--visible");
      setTimeout(() => toast.removeClass("cryptopad-toast--visible"), 2000);
    };

    const copyOutput = async () => {
      if (!this.outputArea.value) return;
      try {
        await navigator.clipboard.writeText(this.outputArea.value);
        showToast();
      } catch {
        this.outputArea.select();
        document.execCommand("copy");
        showToast();
      }
    };

    // ── Keyboard shortcuts ──
    this.passInput.addEventListener("keydown", (e: KeyboardEvent) => {
      // Ctrl+P to toggle visibility
      if ((e.ctrlKey || e.metaKey) && e.key === "p") {
        e.preventDefault();
        this.passInput.type = this.passInput.type === "password" ? "text" : "password";
      }
      // Tab to move to input area
      if (e.key === "Tab" && !e.shiftKey) {
        e.preventDefault();
        this.inputArea.focus();
      }
      // Shift+Tab to move to command input
      if (e.key === "Tab" && e.shiftKey) {
        e.preventDefault();
        this.commandInput.focus();
      }
    });

    this.inputArea.addEventListener("keydown", (e: KeyboardEvent) => {
      // Ctrl+Enter to process
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
        e.preventDefault();
        handleAction();
      }
      // Ctrl+C to clear
      if ((e.ctrlKey || e.metaKey) && e.key === "c" && !e.shiftKey) {
        e.preventDefault();
        this.inputArea.value = "";
        this.resultBlock.style.display = "none";
        this.errorEl.style.display = "none";
      }
    });

    this.outputArea.addEventListener("keydown", (e: KeyboardEvent) => {
      // Ctrl+C to copy from output
      if ((e.ctrlKey || e.metaKey) && e.key === "c" && !e.shiftKey) {
        e.preventDefault();
        copyOutput();
      }
    });

    // Command handler
    this.commandInput.addEventListener("keydown", (e: KeyboardEvent) => {
      if (e.key === "Tab") {
        e.preventDefault();
        const cmd = this.commandInput.value.toLowerCase().trim();

        // If there's a command, execute it. Otherwise just move to passphrase.
        if (cmd.length > 0) {
          this.commandInput.value = "";
          switch (cmd) {
            case "e":
              switchMode("encrypt");
              break;
            case "d":
              switchMode("decrypt");
              break;
            case "c":
              copyOutput();
              break;
            case "q":
            case "quit":
            case "exit":
              this.close();
              return;
            case "h":
            case "help":
              this.errorEl.textContent =
                "Commands: e(ncrypt) d(ecrypt) c(opy) q(uit). Ctrl+Enter: process | Ctrl+C: clear/copy";
              this.errorEl.style.display = "block";
              break;
            default:
              this.errorEl.textContent = `Unknown command: ${cmd}`;
              this.errorEl.style.display = "block";
              return;
          }
        }
        // Move focus to passphrase after command execution or if no command
        this.passInput.focus();
      }
      if (e.key === "Enter") {
        e.preventDefault();
        const cmd = this.commandInput.value.toLowerCase().trim();
        this.commandInput.value = "";

        switch (cmd) {
          case "e":
            switchMode("encrypt");
            break;
          case "d":
            switchMode("decrypt");
            break;
          case "c":
            copyOutput();
            break;
          case "q":
          case "quit":
          case "exit":
            this.close();
            break;
          case "h":
          case "help":
            this.errorEl.textContent =
              "Commands: e(ncrypt) d(ecrypt) c(opy) q(uit). Ctrl+Enter: process | Ctrl+C: clear/copy";
            this.errorEl.style.display = "block";
            break;
          default:
            if (cmd.length > 0) {
              this.errorEl.textContent = `Unknown command: ${cmd}`;
              this.errorEl.style.display = "block";
            }
        }
      }
      if (e.key === "Escape") {
        this.commandInput.value = "";
        this.inputArea.focus();
      }
    });

    // Focus management
    if (!this.passInput.value) {
      this.passInput.focus();
    } else {
      this.inputArea.focus();
    }
  }

  private updateStatus(): void {
    const modeText = this.mode === "encrypt" ? "ENCRYPT" : "DECRYPT";
    this.statusEl.innerHTML = `<span class="cryptopad-mode-badge">${modeText}</span> E/D to switch | Ctrl+Enter to process`;

    // Trigger highlight animation
    const badge = this.statusEl.querySelector(".cryptopad-mode-badge") as HTMLElement;
    if (badge) {
      badge.classList.remove("highlight");
      // Trigger reflow to restart animation
      void badge.offsetWidth;
      badge.classList.add("highlight");
    }
  }

  onClose(): void {
    this.contentEl.empty();
  }
}

// ── Settings Tab ──────────────────────────────────────────────────────────

class CryptoPadSettingTab extends PluginSettingTab {
  plugin: CryptoPadPlugin;

  constructor(app: App, plugin: CryptoPadPlugin) {
    super(app, plugin);
    this.plugin = plugin;
  }

  display(): void {
    const { containerEl } = this;
    containerEl.empty();

    containerEl.createEl("h2", { text: "🔐 CryptoPad" });

    new Setting(containerEl)
      .setName("Saved passphrase")
      .setDesc("Pre-filled in the modal when opened. Leave empty to always type it manually.")
      .addText((text) => {
        const input = text.inputEl;
        input.type = "password";
        text
          .setPlaceholder("Enter passphrase...")
          .setValue(this.plugin.settings.passphrase)
          .onChange(async (value) => {
            this.plugin.settings.passphrase = value;
            await this.plugin.saveSettings();
          });
      });

    new Setting(containerEl)
      .setName("Remember passphrase")
      .setDesc("Pre-fill the passphrase field each time the modal opens.")
      .addToggle((toggle) =>
        toggle
          .setValue(this.plugin.settings.rememberPassphrase)
          .onChange(async (value) => {
            this.plugin.settings.rememberPassphrase = value;
            await this.plugin.saveSettings();
          })
      );

    new Setting(containerEl)
      .setName("Default mode")
      .setDesc("Start with encrypt or decrypt mode.")
      .addDropdown((dropdown) =>
        dropdown
          .addOption("encrypt", "Encrypt")
          .addOption("decrypt", "Decrypt")
          .setValue(this.plugin.settings.defaultMode)
          .onChange(async (value: string) => {
            this.plugin.settings.defaultMode = value as "encrypt" | "decrypt";
            await this.plugin.saveSettings();
          })
      );

    containerEl.createEl("h3", { text: "Keyboard shortcuts" });
    const shortcutsInfo = [
      "Ctrl+Shift+E — Open CryptoPad",
      "Ctrl+Shift+C — Open in Encrypt mode",
      "Ctrl+Shift+D — Open in Decrypt mode",
      "Tab — Navigate to next field",
      "Ctrl+P — Toggle passphrase visibility",
      "Ctrl+Enter — Encrypt/Decrypt",
      "Ctrl+C — Clear input (in textarea) or copy output",
      ":e — Switch to Encrypt mode",
      ":d — Switch to Decrypt mode",
      ":c — Copy output",
      ":q — Close modal",
      ":help — Show help",
    ];
    const shortcutsList = containerEl.createEl("ul");
    shortcutsInfo.forEach((item) => {
      const li = shortcutsList.createEl("li", { text: item });
      li.style.color = "var(--text-muted)";
      li.style.fontSize = "0.9em";
    });

    containerEl.createEl("h3", { text: "Encryption details" });
    const list = containerEl.createEl("ul");
    [
      "Cipher: AES-256-GCM",
      "Key derivation: PBKDF2-SHA256 (200,000 iterations)",
      "Salt: 16 bytes — random per encryption",
      "IV: 12 bytes — random per encryption",
      "Output encoding: Base64",
      "API: Web Crypto API (native browser/Electron)",
    ].forEach((item) => {
      const li = list.createEl("li", { text: item });
      li.style.color = "var(--text-muted)";
      li.style.fontSize = "0.9em";
    });
  }
}

// ── Plugin ────────────────────────────────────────────────────────────────

export default class CryptoPadPlugin extends Plugin {
  settings: CryptoPadSettings = DEFAULT_SETTINGS;

  async onload(): Promise<void> {
    await this.loadSettings();

    // Main command
    this.addCommand({
      id: "open-cryptopad",
      name: "Open CryptoPad",
      hotkeys: [{ modifiers: ["Mod", "Shift"], key: "E" }],
      callback: () => {
        new CryptoPadModal(this.app, this).open();
      },
    });

    // Quick encrypt command
    this.addCommand({
      id: "encrypt-quick",
      name: "Open in Encrypt mode",
      hotkeys: [{ modifiers: ["Mod", "Shift"], key: "C" }],
      callback: () => {
        const modal = new CryptoPadModal(this.app, this);
        modal.setMode("encrypt");
        modal.open();
      },
    });

    // Quick decrypt command
    this.addCommand({
      id: "decrypt-quick",
      name: "Open in Decrypt mode",
      hotkeys: [{ modifiers: ["Mod", "Shift"], key: "D" }],
      callback: () => {
        const modal = new CryptoPadModal(this.app, this);
        modal.setMode("decrypt");
        modal.open();
      },
    });

    this.addSettingTab(new CryptoPadSettingTab(this.app, this));
  }

  onunload(): void {}

  async loadSettings(): Promise<void> {
    const loaded = await this.loadData();
    this.settings = Object.assign({}, DEFAULT_SETTINGS, loaded);
  }

  async saveSettings(): Promise<void> {
    await this.saveData(this.settings);
  }
}
