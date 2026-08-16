/**
 * Stable DOM for a shell tab label.
 *
 * Terminal programs may update their OSC title many times per second (for
 * example, an animated "Working" indicator). Replacing the label's child
 * elements during a pointer gesture makes WebView2 drop the resulting click,
 * because the pointer-down target no longer exists at pointer-up. Keep the
 * elements for the lifetime of the tab and update text nodes in place.
 */
export class TabLabel {
  readonly status: HTMLSpanElement;
  readonly text: HTMLSpanElement;
  readonly primary: HTMLSpanElement;
  readonly secondary: HTMLSpanElement;

  constructor(
    button: HTMLButtonElement,
    createSpan: () => HTMLSpanElement = () => document.createElement("span"),
  ) {
    this.status = createSpan();
    this.status.className = "shell-tab-status";
    this.status.setAttribute("aria-hidden", "true");

    this.text = createSpan();
    this.text.className = "shell-tab-text";
    this.primary = createSpan();
    this.primary.className = "shell-tab-primary";
    this.secondary = createSpan();
    this.secondary.className = "shell-tab-secondary";
    this.text.append(this.primary, this.secondary);
    button.append(this.status, this.text);
  }

  update(primary: string, secondary: string): void {
    this.primary.textContent = primary;
    this.secondary.textContent = secondary;
  }
}
