import { render } from "@solidjs/testing-library";
import { describe, expect, it } from "vitest";
import App from "../App";

describe("App", () => {
  it("renders without crashing", () => {
    const { container } = render(() => <App />);
    expect(container).toBeDefined();
  });

  it("renders toast region", () => {
    const { container } = render(() => <App />);
    const region = container.querySelector('[role="region"]');
    expect(region).toBeDefined();
  });
});
