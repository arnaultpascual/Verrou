import { render, fireEvent, waitFor } from "@solidjs/testing-library";
import { describe, expect, it, vi } from "vitest";
import { ImportWizard } from "../../../features/import/ImportWizard";

describe("ImportWizard", () => {
  it("renders step 1 (source selection) by default", () => {
    const { getByText } = render(() => (
      <ImportWizard onComplete={vi.fn()} onCancel={vi.fn()} />
    ));

    expect(getByText("Choose your import source")).toBeDefined();
    expect(getByText("Google Authenticator")).toBeDefined();
  });

  it("renders StepIndicator with correct labels", () => {
    const { getByText } = render(() => (
      <ImportWizard onComplete={vi.fn()} onCancel={vi.fn()} />
    ));

    expect(getByText("Source")).toBeDefined();
    expect(getByText("Export")).toBeDefined();
    expect(getByText("Review")).toBeDefined();
    expect(getByText("Import")).toBeDefined();
  });

  it("shows Cancel button on step 1", () => {
    const { getByText } = render(() => (
      <ImportWizard onComplete={vi.fn()} onCancel={vi.fn()} />
    ));

    expect(getByText("Cancel")).toBeDefined();
  });

  it("does not show Back button on step 1", () => {
    const { queryByText } = render(() => (
      <ImportWizard onComplete={vi.fn()} onCancel={vi.fn()} />
    ));

    expect(queryByText("Back")).toBeNull();
  });

  it("calls onCancel when Cancel is clicked", () => {
    const onCancel = vi.fn();
    const { getByText } = render(() => (
      <ImportWizard onComplete={vi.fn()} onCancel={onCancel} />
    ));

    fireEvent.click(getByText("Cancel"));
    expect(onCancel).toHaveBeenCalled();
  });

  it("advances to step 2 when a source is selected", async () => {
    const { getByText } = render(() => (
      <ImportWizard onComplete={vi.fn()} onCancel={vi.fn()} />
    ));

    fireEvent.click(getByText("Google Authenticator"));

    await waitFor(() => {
      expect(getByText("Export from Google Authenticator")).toBeDefined();
    });
  });

  it("shows Back button on step 2", async () => {
    const { getByText } = render(() => (
      <ImportWizard onComplete={vi.fn()} onCancel={vi.fn()} />
    ));

    fireEvent.click(getByText("Google Authenticator"));

    await waitFor(() => {
      expect(getByText("Back")).toBeDefined();
    });
  });

  it("goes back to step 1 when Back is clicked on step 2", async () => {
    const { getByText } = render(() => (
      <ImportWizard onComplete={vi.fn()} onCancel={vi.fn()} />
    ));

    fireEvent.click(getByText("Google Authenticator"));

    await waitFor(() => {
      expect(getByText("Back")).toBeDefined();
    });

    fireEvent.click(getByText("Back"));

    await waitFor(() => {
      expect(getByText("Choose your import source")).toBeDefined();
    });
  });

  it("shows step count in StepIndicator", () => {
    const { getByText } = render(() => (
      <ImportWizard onComplete={vi.fn()} onCancel={vi.fn()} />
    ));

    expect(getByText("Step 1 of 4")).toBeDefined();
  });
});
