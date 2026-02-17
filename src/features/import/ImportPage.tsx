import type { Component } from "solid-js";
import { useNavigate } from "@solidjs/router";
import { ImportWizard } from "./ImportWizard";

export const ImportPage: Component = () => {
  const navigate = useNavigate();

  return (
    <ImportWizard
      onComplete={() => navigate("/entries", { replace: true })}
      onCancel={() => navigate("/settings")}
    />
  );
};
