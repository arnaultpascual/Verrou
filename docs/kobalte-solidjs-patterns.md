# Kobalte & SolidJS Patterns Reference

_Living document: update when new gotchas are discovered during implementation._

---

## Kobalte Tooltip

### Named Imports Required (Dev Mode)

The `asChild` pattern is incompatible with SolidJS dev mode when using namespace imports. `Comp.name` is undefined in dev, causing crashes.

**Wrong:**
```tsx
import { Tooltip } from "@kobalte/core/tooltip";
<Tooltip.Root>...</Tooltip.Root>
```

**Correct:**
```tsx
import { Root as TooltipRoot, Trigger as TooltipTrigger, Content as TooltipContent, Portal as TooltipPortal } from "@kobalte/core/tooltip";
<TooltipRoot>...</TooltipRoot>
```

### Nested Button Prevention

Kobalte's `Tooltip.Trigger` renders a `<button>` by default. Wrapping a `<Button>` component creates invalid `<button><button>` HTML.

**Wrong:**
```tsx
<TooltipTrigger>
  <Button>Click me</Button>
</TooltipTrigger>
```

**Correct:**
```tsx
<TooltipTrigger as="span">
  <Button>Click me</Button>
</TooltipTrigger>
```

The `as="span"` renders a `<span>` instead. Tooltip still shows correctly via `focusin`/`pointerenter` event bubbling from the inner button.

---

## Kobalte Dialog (Modal)

### Focus Trapping

Kobalte Dialog automatically traps focus inside the modal. No manual implementation needed. Escape key closes the modal and returns focus to the trigger element.

### `aria-disabled` vs `disabled`

Kobalte Button uses `aria-disabled` attribute (not HTML `disabled`). This preserves focus and keyboard accessibility. When testing:

```tsx
// Wrong:
expect(button).toBeDisabled();

// Correct:
expect(button).toHaveAttribute("aria-disabled", "true");
```

---

## SolidJS Testing Patterns

### MemoryRouter + Route Pattern

Components using `@solidjs/router` features (links, useNavigate) need a router wrapper in tests:

```tsx
import { Router, Route } from "@solidjs/router";

render(() => (
  <Router>
    <Route path="/" component={() => <MyComponent />} />
  </Router>
));
```

### Portal Content Access

Kobalte components that use portals (Dialog, Tooltip, Select) render content outside the test container. Use `document.querySelector` instead of `container.querySelector`:

```tsx
// Portal content won't be found here:
const { container } = render(() => <Modal />);
container.querySelector(".content"); // null!

// Use document instead:
document.querySelector(".content"); // found!
```

### `findByText` for Async Content

Toast notifications and async-rendered content need `findByText` (async) not `getByText` (sync):

```tsx
// Wrong (may fail if content renders after a microtask):
expect(getByText("Success")).toBeDefined();

// Correct:
expect(await findByText("Success")).toBeDefined();
```

### Mocking `@tauri-apps/api`

For components using Tauri IPC, mock the module at the top of the test file:

```tsx
vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => {}),
}));

vi.mock("@tauri-apps/api/window", () => ({
  getCurrentWindow: vi.fn().mockReturnValue({
    hide: vi.fn(),
    onFocusChanged: vi.fn().mockResolvedValue(() => {}),
  }),
}));
```

---

## SolidJS Reactivity Rules

### `createEffect(on())` for Side Effects

Never use `createMemo` for side effects. Use `createEffect` with explicit dependency tracking:

```tsx
// Wrong:
createMemo(() => {
  if (count() > 10) doSomething();
});

// Correct:
createEffect(on(count, (c) => {
  if (c > 10) doSomething();
}));
```

### `<Show>` for Conditional Rendering

Never use imperative `if/return` for conditional rendering. Use `<Show>`:

```tsx
// Wrong:
const MyComp = () => {
  if (loading()) return <Spinner />;
  return <Content />;
};

// Correct:
const MyComp = () => (
  <Show when={!loading()} fallback={<Spinner />}>
    <Content />
  </Show>
);
```

---

_Last updated: 2026-02-11 (Epic 4 retrospective)_
