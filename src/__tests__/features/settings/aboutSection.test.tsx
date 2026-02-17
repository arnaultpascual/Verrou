import { render } from "@solidjs/testing-library";
import { describe, expect, it, vi, beforeEach } from "vitest";

// Mock getAppInfo IPC
const mockGetAppInfo = vi.fn();

vi.mock("../../../features/settings/preferencesIpc", () => ({
  getAppInfo: (...args: unknown[]) => mockGetAppInfo(...args),
}));

import { AboutSection } from "../../../features/settings/AboutSection";

describe("AboutSection", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders version, build, license, source code, and audit when IPC succeeds", async () => {
    mockGetAppInfo.mockResolvedValue({
      version: "1.2.3",
      commitHash: "abc1234",
      buildDate: "2026-02-16",
      repository: "https://github.com/cyanodroid/verrou",
      license: "GPL-3.0-or-later",
    });

    const { findByTestId } = render(() => <AboutSection />);

    const version = await findByTestId("about-version");
    expect(version.textContent).toBe("1.2.3");

    const build = await findByTestId("about-build");
    expect(build.textContent).toContain("abc1234");
    expect(build.textContent).toContain("2026-02-16");

    const license = await findByTestId("about-license");
    expect(license.textContent).toBe("GPL-3.0-or-later");

    const source = await findByTestId("about-source");
    expect(source.textContent).toContain("github.com/cyanodroid/verrou");

    const audit = await findByTestId("about-audit");
    expect(audit.textContent).toContain("Not yet published");
  });

  it("renders section title", async () => {
    mockGetAppInfo.mockResolvedValue({
      version: "0.1.0",
      commitHash: "dev",
      buildDate: "dev",
      repository: "https://github.com/cyanodroid/verrou",
      license: "GPL-3.0-or-later",
    });

    const { findByTestId } = render(() => <AboutSection />);
    const section = await findByTestId("about-section");
    expect(section.textContent).toContain("About VERROU");
  });

  it("renders nothing when IPC fails", async () => {
    mockGetAppInfo.mockRejectedValue(new Error("IPC not available"));

    const { queryByTestId } = render(() => <AboutSection />);

    // Wait a tick for the onMount to reject
    await new Promise((r) => setTimeout(r, 50));

    expect(queryByTestId("about-section")).toBeNull();
  });

  it("uses definition list semantics", async () => {
    mockGetAppInfo.mockResolvedValue({
      version: "0.1.0",
      commitHash: "dev",
      buildDate: "dev",
      repository: "https://github.com/cyanodroid/verrou",
      license: "GPL-3.0-or-later",
    });

    const { findByTestId } = render(() => <AboutSection />);
    const section = await findByTestId("about-section");

    const dl = section.querySelector("dl");
    expect(dl).not.toBeNull();

    const dtElements = section.querySelectorAll("dt");
    expect(dtElements.length).toBe(5); // version, build, license, source, audit
  });
});
