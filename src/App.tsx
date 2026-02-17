import { Router, Route, Navigate } from "@solidjs/router";
import { AppRoot } from "./features/layout/AppRoot";
import { ProtectedLayout } from "./features/layout/ProtectedLayout";
import { UnlockPage } from "./features/vault/UnlockPage";
import { OnboardingPage } from "./features/onboarding/OnboardingPage";
import { RecoveryPage } from "./features/vault/RecoveryPage";
import { EntriesPage } from "./features/entries/EntriesPage";
import { SettingsPage } from "./features/settings/SettingsPage";
import { ImportPage } from "./features/import/ImportPage";
import { PasswordHealthPage } from "./features/password-health/PasswordHealthPage";

export default function App() {
  return (
    <Router root={AppRoot}>
      <Route path="/onboarding" component={OnboardingPage} />
      <Route path="/unlock" component={UnlockPage} />
      <Route path="/recovery" component={RecoveryPage} />
      <Route path="/" component={ProtectedLayout}>
        <Route path="/entries" component={EntriesPage} />
        <Route path="/settings" component={SettingsPage} />
        <Route path="/import" component={ImportPage} />
        <Route path="/password-health" component={PasswordHealthPage} />
        <Route path="/*" component={() => <Navigate href="/entries" />} />
      </Route>
    </Router>
  );
}
