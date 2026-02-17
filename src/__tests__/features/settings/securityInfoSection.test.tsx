import { render, fireEvent } from "@solidjs/testing-library";
import { describe, expect, it } from "vitest";
import { SecurityInfoSection } from "../../../features/settings/SecurityInfoSection";

describe("SecurityInfoSection", () => {
  it("renders section with title", () => {
    const { getByTestId } = render(() => <SecurityInfoSection />);
    const section = getByTestId("security-info-section");
    expect(section).toBeDefined();
    expect(section.textContent).toContain("Vault Security");
  });

  it("renders encryption status summary", () => {
    const { getByTestId } = render(() => <SecurityInfoSection />);
    const section = getByTestId("security-info-section");
    expect(section.textContent).toContain(
      "Your data is encrypted and stored only on this device."
    );
  });

  it("renders encryption algorithm details", () => {
    const { getByTestId } = render(() => <SecurityInfoSection />);
    const section = getByTestId("security-info-section");
    expect(section.textContent).toContain("AES-256-GCM");
    expect(section.textContent).toContain("Argon2id");
    expect(section.textContent).toContain("X25519 + ML-KEM-1024");
  });

  it("shows learn more toggle button", () => {
    const { getByTestId } = render(() => <SecurityInfoSection />);
    const toggle = getByTestId("learn-more-toggle");
    expect(toggle).toBeDefined();
    expect(toggle.textContent).toContain("Learn more");
    expect(toggle.getAttribute("aria-expanded")).toBe("false");
  });

  it("clicking learn more expands technical details", () => {
    const { getByTestId, queryByTestId } = render(() => (
      <SecurityInfoSection />
    ));

    // Details should not be visible initially
    expect(queryByTestId("security-details")).toBeNull();

    // Click to expand
    fireEvent.click(getByTestId("learn-more-toggle"));

    const details = getByTestId("security-details");
    expect(details).toBeDefined();
    expect(details.textContent).toContain("AES-256-GCM: 256-bit symmetric");
    expect(details.textContent).toContain("Argon2id: Winner of the Password Hashing Competition");
    expect(details.textContent).toContain("X25519: Elliptic curve Diffie-Hellman");
    expect(details.textContent).toContain("ML-KEM-1024: NIST post-quantum standard");
    expect(details.textContent).toContain("All cryptographic operations run locally");
  });

  it("toggle button text changes when expanded", () => {
    const { getByTestId } = render(() => <SecurityInfoSection />);
    const toggle = getByTestId("learn-more-toggle");

    expect(toggle.textContent).toContain("Learn more");
    fireEvent.click(toggle);
    expect(toggle.textContent).toContain("Show less");
    expect(toggle.getAttribute("aria-expanded")).toBe("true");
  });

  it("clicking toggle again collapses details", () => {
    const { getByTestId, queryByTestId } = render(() => (
      <SecurityInfoSection />
    ));

    // Expand
    fireEvent.click(getByTestId("learn-more-toggle"));
    expect(queryByTestId("security-details")).not.toBeNull();

    // Collapse
    fireEvent.click(getByTestId("learn-more-toggle"));
    expect(queryByTestId("security-details")).toBeNull();
  });

  it("uses definition list for info items", () => {
    const { getByTestId } = render(() => <SecurityInfoSection />);
    const section = getByTestId("security-info-section");

    const dl = section.querySelector("dl");
    expect(dl).not.toBeNull();

    const dtElements = section.querySelectorAll("dt");
    expect(dtElements.length).toBe(3); // encryption, kdf, kem
  });
});
