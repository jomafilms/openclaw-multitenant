import { LitElement, html, css } from "lit";
import { customElement, property, state, query } from "lit/decorators.js";

/**
 * Reusable 6-digit MFA code input component
 * Features:
 * - Auto-focus on first input
 * - Auto-advance to next input on entry
 * - Auto-submit when all 6 digits are entered
 * - Paste support for full code
 * - Keyboard navigation (backspace, arrows)
 */
@customElement("mfa-code-input")
export class MfaCodeInput extends LitElement {
  static styles = css`
    :host {
      display: block;
    }

    .code-inputs {
      display: flex;
      gap: 8px;
      justify-content: center;
    }

    .code-input {
      width: 48px;
      height: 56px;
      text-align: center;
      font-size: 1.5rem;
      font-weight: 600;
      font-family: monospace;
      border: 2px solid rgba(255, 255, 255, 0.2);
      border-radius: 8px;
      background: rgba(255, 255, 255, 0.1);
      color: white;
      transition: all 0.2s;
    }

    .code-input:focus {
      outline: none;
      border-color: #4f46e5;
      background: rgba(79, 70, 229, 0.1);
    }

    .code-input:disabled {
      opacity: 0.5;
      cursor: not-allowed;
    }

    .code-input.filled {
      border-color: #22c55e;
      background: rgba(34, 197, 94, 0.1);
    }

    .code-input.error {
      border-color: #ef4444;
      background: rgba(239, 68, 68, 0.1);
      animation: shake 0.3s ease-in-out;
    }

    @keyframes shake {
      0%,
      100% {
        transform: translateX(0);
      }
      25% {
        transform: translateX(-4px);
      }
      75% {
        transform: translateX(4px);
      }
    }

    /* Mobile responsive */
    @media (max-width: 400px) {
      .code-inputs {
        gap: 4px;
      }

      .code-input {
        width: 40px;
        height: 48px;
        font-size: 1.25rem;
      }
    }
  `;

  @property({ type: Boolean })
  disabled = false;

  @property({ type: Boolean })
  error = false;

  @state()
  private digits: string[] = ["", "", "", "", "", ""];

  @query(".code-input")
  private firstInput!: HTMLInputElement;

  /**
   * Focus the first input
   */
  focus() {
    this.updateComplete.then(() => {
      const inputs = this.shadowRoot?.querySelectorAll<HTMLInputElement>(".code-input");
      if (inputs && inputs[0]) {
        inputs[0].focus();
      }
    });
  }

  /**
   * Clear all inputs
   */
  clear() {
    this.digits = ["", "", "", "", "", ""];
    this.error = false;
    this.focus();
  }

  /**
   * Get the current code value
   */
  getValue(): string {
    return this.digits.join("");
  }

  private handleInput(index: number, e: Event) {
    const input = e.target as HTMLInputElement;
    const value = input.value;

    // Only allow digits
    const digit = value.replace(/\D/g, "").slice(-1);

    // Update the digit
    const newDigits = [...this.digits];
    newDigits[index] = digit;
    this.digits = newDigits;

    // Clear error state on input
    if (this.error) {
      this.error = false;
    }

    // Auto-advance to next input
    if (digit && index < 5) {
      const inputs = this.shadowRoot?.querySelectorAll<HTMLInputElement>(".code-input");
      if (inputs && inputs[index + 1]) {
        inputs[index + 1].focus();
      }
    }

    // Auto-submit when all digits are filled
    const code = newDigits.join("");
    if (code.length === 6) {
      this.dispatchEvent(
        new CustomEvent("code-complete", {
          detail: { code },
          bubbles: true,
          composed: true,
        }),
      );
    }

    // Emit change event
    this.dispatchEvent(
      new CustomEvent("code-change", {
        detail: { code },
        bubbles: true,
        composed: true,
      }),
    );
  }

  private handleKeyDown(index: number, e: KeyboardEvent) {
    const inputs = this.shadowRoot?.querySelectorAll<HTMLInputElement>(".code-input");
    if (!inputs) return;

    if (e.key === "Backspace") {
      e.preventDefault();

      // Clear current digit
      const newDigits = [...this.digits];

      if (this.digits[index]) {
        // If current digit has value, clear it
        newDigits[index] = "";
        this.digits = newDigits;
      } else if (index > 0) {
        // If current digit is empty, go to previous and clear it
        newDigits[index - 1] = "";
        this.digits = newDigits;
        inputs[index - 1].focus();
      }
    } else if (e.key === "ArrowLeft" && index > 0) {
      e.preventDefault();
      inputs[index - 1].focus();
    } else if (e.key === "ArrowRight" && index < 5) {
      e.preventDefault();
      inputs[index + 1].focus();
    } else if (e.key === "Enter") {
      e.preventDefault();
      const code = this.digits.join("");
      if (code.length === 6) {
        this.dispatchEvent(
          new CustomEvent("code-submit", {
            detail: { code },
            bubbles: true,
            composed: true,
          }),
        );
      }
    }
  }

  private handlePaste(e: ClipboardEvent) {
    e.preventDefault();
    const pastedData = e.clipboardData?.getData("text") || "";
    const digits = pastedData.replace(/\D/g, "").slice(0, 6);

    if (digits.length > 0) {
      const newDigits = [...this.digits];
      for (let i = 0; i < digits.length && i < 6; i++) {
        newDigits[i] = digits[i];
      }
      this.digits = newDigits;

      // Focus appropriate input
      const inputs = this.shadowRoot?.querySelectorAll<HTMLInputElement>(".code-input");
      if (inputs) {
        const focusIndex = Math.min(digits.length, 5);
        inputs[focusIndex].focus();
      }

      // Auto-submit if complete
      const code = newDigits.join("");
      if (code.length === 6) {
        this.dispatchEvent(
          new CustomEvent("code-complete", {
            detail: { code },
            bubbles: true,
            composed: true,
          }),
        );
      }
    }
  }

  render() {
    return html`
      <div class="code-inputs">
        ${this.digits.map(
          (digit, index) => html`
            <input
              type="text"
              inputmode="numeric"
              maxlength="1"
              class="code-input ${digit ? "filled" : ""} ${this.error ? "error" : ""}"
              .value=${digit}
              ?disabled=${this.disabled}
              @input=${(e: Event) => this.handleInput(index, e)}
              @keydown=${(e: KeyboardEvent) => this.handleKeyDown(index, e)}
              @paste=${this.handlePaste}
              @focus=${(e: FocusEvent) => (e.target as HTMLInputElement).select()}
              autocomplete="one-time-code"
            />
          `,
        )}
      </div>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "mfa-code-input": MfaCodeInput;
  }
}
