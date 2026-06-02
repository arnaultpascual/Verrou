# Verrou — image-render brief (for Gemini → trace to SVG)

## App brief (context)
Verrou is a **sovereign, offline, post-quantum-encrypted desktop vault** for passwords, 2FA/TOTP codes, and crypto seed phrases. It never touches the internet — no accounts, no servers, no telemetry. Brand feel: **calm, precise, European minimalism** — a Swiss instrument, not a flashy gadget. The name is French for **"deadbolt."**

## Color
- **Dominant:** Iris indigo **`#7E84E8`**
- **Background:** deep charcoal **`#0F0F14`**
- (optional highlight tint `#9499F0`) — keep to **one accent on dark**, high contrast.

## Why "geometric" matters
Flat, solid-color, geometric shapes with thick even strokes trace into clean SVG paths. Gradients, shadows, 3D, texture, and text all break vectorization — so the prompts below forbid them.

---

## Prompt A — "The Bolt V" (recommended)
```
Flat vector app icon, minimalist geometric logo mark: a padlock abstracted from a bold sharp letter "V" — the V's two strokes form the padlock's angular shackle sitting above a rounded-square lock body with a small circular keyhole. Single color iris indigo #7E84E8 on a solid deep-charcoal #0F0F14 background. Thick uniform line weight, rounded stroke caps, perfectly symmetrical, grid-based geometric construction, generous padding, centered. Flat design, solid colors only — no text, no letters, no gradient, no shadow, no 3D, no bevel, no texture, no photo. 1024x1024.
```

## Prompt B — "Deadbolt" (most literal to the name)
```
Flat vector app icon, minimalist geometric mark: a horizontal deadbolt thrown into a strike plate, abstracted into two bold rounded bars with a circular thumb-turn knob on the left. Single color iris indigo #7E84E8 on solid deep-charcoal #0F0F14. Uniform thick strokes, rounded caps, symmetrical, grid-based, centered with padding. Flat, solid color only — no text, no gradient, no shadow, no 3D, no texture. 1024x1024.
```

## Prompt C — "Lattice keyhole" (nods to lattice-based PQ crypto)
```
Flat vector app icon, minimalist geometric mark: a single keyhole centered inside one cell of a hexagonal lattice grid, suggesting a protective crystalline lattice. Monoline, single color iris indigo #7E84E8 on solid deep-charcoal #0F0F14. Even thin-to-medium strokes, rounded joins, perfectly symmetrical, grid-based geometric construction, centered, generous padding. Flat design, solid colors only — no text, no gradient, no shadow, no 3D, no texture. 1024x1024.
```

## Negative prompt (if supported)
```
text, letters, words, watermark, gradient, drop shadow, 3D, bevel, emboss, glow, photorealistic, mockup, hand, noise, texture, busy detail, multiple icons
```

## Vectorize cleanly afterward
- Generate a few; pick the **simplest silhouette** that still reads at 16px.
- Trace with **vtracer / SVGcode / Illustrator Image Trace** → set to flat/posterize, few colors.
- Simplify + snap nodes to a grid; recolor strokes to `#7E84E8` (or `currentColor` for theming).
- Keep the **wordmark separate** — set "Verrou" in **Inter Medium**, title case, beside the mark (don't let the model draw text).
