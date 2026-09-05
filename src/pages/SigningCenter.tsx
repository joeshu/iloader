import "./SigningCenter.css";

import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { open as openDialog } from "@tauri-apps/plugin-dialog";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { toast } from "sonner";

export type SigningCenterProps = {
  deviceUdid?: string | null;
};

type SigningCenterSnapshot = {
  email: string;
  teamId: string;
  certificates: Array<{ name?: string | null }>;
  appIds: Array<{ appIdId: string; identifier: string; name: string }>;
  devices: Array<{ name?: string | null; udid: string }>;
  availableAppIds?: number | null;
};

type IpaProfileMatch = {
  appIdId: string;
  identifier: string;
  name: string;
  profileName?: string | null;
  profileStatus?: string | null;
};

type IpaBundleInspection = {
  name: string;
  bundleIdentifier: string;
  signingBundleIdentifier: string;
  version?: string | null;
  build?: string | null;
  minimumOsVersion?: string | null;
  appIdMatch?: IpaProfileMatch | null;
};

type EntitlementCompatibilityItem = {
  key: string;
  status:
    | "preserved"
    | "rewritten"
    | "added"
    | "unsupported"
    | "pendingRegistration"
    | "sourceUnavailable";
  severity: "info" | "warning" | "error";
  message: string;
};

type BundleEntitlementCompatibility = {
  role: string;
  name: string;
  bundleIdentifier: string;
  signingBundleIdentifier: string;
  sourceProfileAvailable: boolean;
  targetProfileAvailable: boolean;
  blocking: boolean;
  items: EntitlementCompatibilityItem[];
};

type EntitlementCompatibilityReport = {
  ready: boolean;
  teamId: string;
  bundles: BundleEntitlementCompatibility[];
  blockingCount: number;
  warningCount: number;
};

type AutoPreflightCheck = {
  code: string;
  severity: "info" | "warning" | "error";
  passed: boolean;
  message: string;
};

type AutoIpaPreflightReport = {
  ready: boolean;
  teamId: string;
  inspection: {
    path: string;
    main: IpaBundleInspection;
    extensions: IpaBundleInspection[];
    allBundleIdsMatched: boolean;
    unmatchedBundleIds: string[];
    requiresRegistrationBundleIds: string[];
    extensionBundleIdsValid: boolean;
  };
  entitlements: EntitlementCompatibilityReport;
  checks: AutoPreflightCheck[];
};

type BatchIpaPreflightItem = {
  inputPath: string;
  report?: AutoIpaPreflightReport | null;
  error?: string | null;
};

type BatchIpaPreflightReport = {
  total: number;
  ready: number;
  blocked: number;
  failed: number;
  items: BatchIpaPreflightItem[];
};

type BatchPreflightProgress = {
  inputPath: string;
  stage: "scanning" | "ready" | "blocked" | "failed";
  ready?: boolean | null;
  error?: string | null;
};

type SignedIpaValidation = {
  valid: boolean;
  payloadApp?: string | null;
  hasInfoPlist: boolean;
  hasCodeSignature: boolean;
  hasProvisioningProfile: boolean;
  extensionCount: number;
  extensionProfiles: number;
};

type BatchSigningItemResult = {
  inputPath: string;
  status: "signed" | "failed";
  outputPath?: string | null;
  validation?: SignedIpaValidation | null;
  error?: string | null;
};

type BatchSigningReport = {
  total: number;
  signed: number;
  failed: number;
  outputDirectory: string;
  items: BatchSigningItemResult[];
};

type BatchSigningProgress = {
  inputPath: string;
  stage: "inspecting" | "signing" | "packaging" | "validating" | "signed" | "failed";
  outputPath?: string | null;
  error?: string | null;
};

type CompleteSigningBundleExportInfo = {
  archivePath: string;
  p12Password: string;
  profiles: Array<unknown>;
};

type DiagnosticBundleExportInfo = {
  archivePath: string;
  includedLogFiles: number;
  queueItems: number;
};

type QueueStage =
  | "pending"
  | "scanning"
  | "ready"
  | "blocked"
  | "inspecting"
  | "signing"
  | "packaging"
  | "validating"
  | "signed"
  | "failed";

type QueueItem = {
  path: string;
  stage: QueueStage;
  report?: AutoIpaPreflightReport;
  error?: string;
  outputPath?: string;
  validation?: SignedIpaValidation;
};

type PersistedQueueState = {
  version: 1;
  outputDirectory: string;
  queue: QueueItem[];
};

const PERSISTENCE_KEY = "iloader.signing-center.queue.v1";
const fileName = (path: string) => path.split(/[\\/]/).pop() || path;

const stageLabel: Record<QueueStage, string> = {
  pending: "Pending",
  scanning: "Scanning",
  ready: "Ready",
  blocked: "Blocked",
  inspecting: "Inspecting",
  signing: "Signing",
  packaging: "Packaging",
  validating: "Validating",
  signed: "Signed",
  failed: "Failed",
};

const restoreQueueState = (): PersistedQueueState => {
  try {
    const raw = window.localStorage.getItem(PERSISTENCE_KEY);
    if (!raw) return { version: 1, outputDirectory: "", queue: [] };
    const parsed = JSON.parse(raw) as PersistedQueueState;
    if (parsed.version !== 1 || !Array.isArray(parsed.queue)) {
      return { version: 1, outputDirectory: "", queue: [] };
    }

    return {
      version: 1,
      outputDirectory: typeof parsed.outputDirectory === "string" ? parsed.outputDirectory : "",
      queue: parsed.queue
        .filter((item) => typeof item?.path === "string" && item.path.length > 0)
        .map((item) => {
          if (item.stage === "signed" && item.outputPath) return item;
          return {
            path: item.path,
            stage: "pending" as QueueStage,
            error:
              item.stage === "pending"
                ? item.error
                : "Previous session state restored. Re-run preflight before signing.",
          };
        }),
    };
  } catch {
    return { version: 1, outputDirectory: "", queue: [] };
  }
};

export const SigningCenter = ({ deviceUdid }: SigningCenterProps) => {
  const initialState = useRef(restoreQueueState()).current;
  const [snapshot, setSnapshot] = useState<SigningCenterSnapshot | null>(null);
  const [queue, setQueue] = useState<QueueItem[]>(initialState.queue);
  const [outputDirectory, setOutputDirectory] = useState(initialState.outputDirectory);
  const [loadingSnapshot, setLoadingSnapshot] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [signing, setSigning] = useState(false);
  const [exportingBundlePath, setExportingBundlePath] = useState<string | null>(null);
  const [exportingDiagnostics, setExportingDiagnostics] = useState(false);

  useEffect(() => {
    const persisted: PersistedQueueState = { version: 1, outputDirectory, queue };
    try {
      window.localStorage.setItem(PERSISTENCE_KEY, JSON.stringify(persisted));
    } catch (error) {
      console.warn("Failed to persist Signing Center queue", error);
    }
  }, [queue, outputDirectory]);

  const loadSnapshot = useCallback(async () => {
    setLoadingSnapshot(true);
    try {
      setSnapshot(await invoke<SigningCenterSnapshot>("get_signing_center_snapshot"));
    } catch (error) {
      toast.error(`Failed to load Signing Center: ${String(error)}`);
    } finally {
      setLoadingSnapshot(false);
    }
  }, []);

  useEffect(() => {
    loadSnapshot();
  }, [loadSnapshot]);

  useEffect(() => {
    let disposed = false;
    const cleanups: Array<() => void> = [];

    const preflightListener = listen<BatchPreflightProgress>("batch_preflight_progress", (event) => {
      const progress = event.payload;
      setQueue((current) =>
        current.map((item) =>
          item.path === progress.inputPath
            ? { ...item, stage: progress.stage, error: progress.error || undefined }
            : item,
        ),
      );
    });

    const signingListener = listen<BatchSigningProgress>("batch_signing_progress", (event) => {
      const progress = event.payload;
      setQueue((current) =>
        current.map((item) =>
          item.path === progress.inputPath
            ? {
                ...item,
                stage: progress.stage,
                outputPath: progress.outputPath || item.outputPath,
                error: progress.error || undefined,
              }
            : item,
        ),
      );
    });

    Promise.all([preflightListener, signingListener]).then((unlisteners) => {
      if (disposed) unlisteners.forEach((unlisten) => unlisten());
      else cleanups.push(...unlisteners);
    });

    return () => {
      disposed = true;
      cleanups.forEach((cleanup) => cleanup());
    };
  }, []);

  const selectIpas = useCallback(async () => {
    const selected = await openDialog({
      multiple: true,
      filters: [{ name: "IPA files", extensions: ["ipa"] }],
    });
    if (!selected) return;
    const paths = Array.isArray(selected) ? selected : [selected];

    setQueue((current) => {
      const existing = new Set(current.map((item) => item.path));
      const added = paths
        .filter((path) => !existing.has(path))
        .map((path) => ({ path, stage: "pending" as QueueStage }));
      return [...current, ...added];
    });
  }, []);

  const selectOutputDirectory = useCallback(async () => {
    const selected = await openDialog({ directory: true, multiple: false });
    if (typeof selected === "string") setOutputDirectory(selected);
  }, []);

  const preflightPaths = useCallback(
    async (ipaPaths: string[]): Promise<BatchIpaPreflightReport | null> => {
      if (ipaPaths.length === 0) return null;
      setScanning(true);
      setQueue((current) =>
        current.map((item) =>
          ipaPaths.includes(item.path)
            ? { ...item, stage: "pending", report: undefined, error: undefined, validation: undefined }
            : item,
        ),
      );

      try {
        const report = await invoke<BatchIpaPreflightReport>("preflight_ipas", {
          ipaPaths,
          deviceUdid: deviceUdid || null,
        });
        setQueue((current) =>
          current.map((item) => {
            const result = report.items.find((candidate) => candidate.inputPath === item.path);
            if (!result) return item;
            if (!result.report) {
              return { ...item, stage: "failed", report: undefined, error: result.error || "Preflight failed" };
            }
            return {
              ...item,
              stage: result.report.ready ? "ready" : "blocked",
              report: result.report,
              error: result.error || undefined,
            };
          }),
        );
        return report;
      } catch (error) {
        const message = `Batch preflight failed: ${String(error)}`;
        setQueue((current) =>
          current.map((item) =>
            ipaPaths.includes(item.path) ? { ...item, stage: "failed", error: message } : item,
          ),
        );
        toast.error(message);
        return null;
      } finally {
        setScanning(false);
      }
    },
    [deviceUdid],
  );

  const scanQueue = useCallback(async () => {
    const candidates = queue.filter((item) => item.stage !== "signed").map((item) => item.path);
    if (candidates.length === 0) {
      toast.warning(queue.length === 0 ? "Select at least one IPA first." : "No unsigned IPA remains in the queue.");
      return;
    }

    const report = await preflightPaths(candidates);
    if (!report) return;
    if (report.blocked === 0 && report.failed === 0) {
      toast.success(`${report.ready} IPA(s) are ready to sign.`);
    } else {
      toast.warning(`${report.ready} ready, ${report.blocked} blocked, ${report.failed} failed inspection.`);
    }
  }, [queue, preflightPaths]);

  const signPaths = useCallback(
    async (ipaPaths: string[]) => {
      if (ipaPaths.length === 0) return;
      if (!outputDirectory) {
        toast.warning("Choose an output directory first.");
        return;
      }

      setSigning(true);
      try {
        const report = await invoke<BatchSigningReport>("batch_sign_ipas", {
          ipaPaths,
          outputDirectory,
        });
        setQueue((current) =>
          current.map((item) => {
            const result = report.items.find((candidate) => candidate.inputPath === item.path);
            if (!result) return item;
            return {
              ...item,
              stage: result.status,
              outputPath: result.outputPath || item.outputPath,
              validation: result.validation || undefined,
              error: result.error || undefined,
            };
          }),
        );

        if (report.failed === 0) toast.success(`Signed and validated ${report.signed} IPA(s).`);
        else toast.warning(`Signed and validated ${report.signed}; ${report.failed} failed.`);
        loadSnapshot();
      } catch (error) {
        toast.error(`Batch signing failed: ${String(error)}`);
      } finally {
        setSigning(false);
      }
    },
    [outputDirectory, loadSnapshot],
  );

  const readyPaths = useMemo(
    () => queue.filter((item) => item.stage === "ready").map((item) => item.path),
    [queue],
  );

  const signReady = useCallback(() => signPaths(readyPaths), [readyPaths, signPaths]);

  const retryFailed = useCallback(async () => {
    const retryPaths = queue
      .filter((item) => item.stage === "failed" || item.stage === "blocked")
      .map((item) => item.path);
    if (retryPaths.length === 0) {
      toast.info("No failed or blocked IPA needs retrying.");
      return;
    }

    const report = await preflightPaths(retryPaths);
    if (!report) return;
    const nowReady = report.items
      .filter((item) => item.report?.ready)
      .map((item) => item.inputPath);

    if (nowReady.length === 0) {
      toast.warning("Retry completed, but no IPA is currently eligible to sign.");
      return;
    }
    if (!outputDirectory) {
      toast.success(`${nowReady.length} retried IPA(s) are ready; choose an output folder to sign them.`);
      return;
    }
    await signPaths(nowReady);
  }, [queue, preflightPaths, outputDirectory, signPaths]);

  const exportSigningBundle = useCallback(async (ipaPath: string) => {
    setExportingBundlePath(ipaPath);
    try {
      const result = await invoke<CompleteSigningBundleExportInfo | null>("export_ipa_signing_bundle", {
        ipaPath,
        password: null,
      });
      if (!result) {
        toast.info("Signing bundle export canceled.");
        return;
      }
      toast.success(
        `Exported ${result.profiles.length} profile(s) to ${result.archivePath}. P12 password: ${result.p12Password}`,
      );
    } catch (error) {
      toast.error(`Failed to export signing bundle: ${String(error)}`);
    } finally {
      setExportingBundlePath(null);
    }
  }, []);

  const exportDiagnostics = useCallback(async () => {
    setExportingDiagnostics(true);
    try {
      const diagnosticQueue = queue.map((item) => ({
        inputPath: item.path,
        stage: item.stage,
        error: item.error || null,
        outputPath: item.outputPath || null,
        entitlementBlockingCount: item.report?.entitlements.blockingCount ?? null,
        entitlementWarningCount: item.report?.entitlements.warningCount ?? null,
        validationPassed: item.validation?.valid ?? null,
      }));
      const result = await invoke<DiagnosticBundleExportInfo | null>("export_signing_diagnostics", {
        queue: diagnosticQueue,
      });
      if (!result) {
        toast.info("Diagnostics export canceled.");
        return;
      }
      toast.success(
        `Sanitized diagnostics exported to ${result.archivePath} (${result.queueItems} queue item(s), ${result.includedLogFiles} log file(s)).`,
      );
    } catch (error) {
      toast.error(`Failed to export diagnostics: ${String(error)}`);
    } finally {
      setExportingDiagnostics(false);
    }
  }, [queue]);

  const removeItem = useCallback((path: string) => {
    setQueue((current) => current.filter((item) => item.path !== path));
  }, []);

  const clearCompleted = useCallback(() => {
    setQueue((current) => current.filter((item) => item.stage !== "signed"));
  }, []);

  const summary = useMemo(() => {
    const ready = queue.filter((item) => item.stage === "ready").length;
    const blocked = queue.filter((item) => item.stage === "blocked").length;
    const signed = queue.filter((item) => item.stage === "signed").length;
    const failed = queue.filter((item) => item.stage === "failed").length;
    return { ready, blocked, signed, failed };
  }, [queue]);

  const busy = scanning || signing;

  return (
    <div className="signing-center">
      <div className="signing-center-header">
        <div>
          <h2>Signing Center</h2>
          <p className="signing-center-subtitle">
            Preflight metadata, entitlements and signing assets; persist the queue across restarts; sign, validate and retry failures independently.
          </p>
        </div>
        <button onClick={loadSnapshot} disabled={loadingSnapshot || busy}>
          {loadingSnapshot ? "Refreshing…" : "Refresh assets"}
        </button>
      </div>

      <div className="signing-asset-grid">
        <div className="signing-asset-card"><span>Team</span><strong>{snapshot?.teamId || "—"}</strong><small>{snapshot?.email || "Not loaded"}</small></div>
        <div className="signing-asset-card"><span>Certificates</span><strong>{snapshot?.certificates.length ?? "—"}</strong><small>Development identities</small></div>
        <div className="signing-asset-card"><span>App IDs</span><strong>{snapshot?.appIds.length ?? "—"}</strong><small>{snapshot?.availableAppIds == null ? "Quota unavailable" : `${snapshot.availableAppIds} slots available`}</small></div>
        <div className="signing-asset-card"><span>Devices</span><strong>{snapshot?.devices.length ?? "—"}</strong><small>{deviceUdid ? "Current device linked to preflight" : "No target device selected"}</small></div>
      </div>

      <div className="signing-toolbar">
        <button onClick={selectIpas} disabled={busy}>Select IPAs</button>
        <button onClick={scanQueue} disabled={queue.length === 0 || busy}>{scanning ? "Scanning…" : "Scan & preflight"}</button>
        <button onClick={selectOutputDirectory} disabled={busy}>Choose output folder</button>
        <button className="signing-primary" onClick={signReady} disabled={readyPaths.length === 0 || busy}>
          {signing ? "Signing batch…" : `Sign ready (${readyPaths.length})`}
        </button>
        <button onClick={retryFailed} disabled={(summary.failed + summary.blocked === 0) || busy}>Retry failed</button>
        <button onClick={exportDiagnostics} disabled={exportingDiagnostics || busy}>
          {exportingDiagnostics ? "Exporting diagnostics…" : "Export diagnostics"}
        </button>
        <button onClick={clearCompleted} disabled={summary.signed === 0 || busy}>Clear completed</button>
      </div>

      <div className="signing-output-path" title={outputDirectory}>
        <span>Output</span><strong>{outputDirectory || "Choose a destination for signed IPA files"}</strong>
      </div>

      <div className="signing-summary">
        <span>{queue.length} total</span><span>{summary.ready} ready</span><span>{summary.blocked} blocked</span><span>{summary.signed} signed</span><span>{summary.failed} failed</span>
      </div>

      {queue.length === 0 ? (
        <div className="signing-empty">
          Select multiple IPA files to build a persistent signing queue. Interrupted work is restored on the next launch, but unsigned items must pass a fresh preflight before signing.
        </div>
      ) : (
        <div className="signing-queue">
          {queue.map((item) => {
            const main = item.report?.inspection.main;
            const blockingChecks = item.report?.checks.filter((check) => check.severity === "error" && !check.passed);
            const warnings = item.report?.checks.filter((check) => check.severity === "warning");
            const entitlementBlocking = item.report?.entitlements.bundles.flatMap((bundle) =>
              bundle.items.filter((entry) => entry.severity === "error").map((entry) => `${bundle.name}: ${entry.message}`),
            );
            const entitlementWarnings = item.report?.entitlements.bundles.flatMap((bundle) =>
              bundle.items.filter((entry) => entry.severity === "warning").map((entry) => `${bundle.name}: ${entry.message}`),
            );
            const canExportBundle = item.stage === "signed" && item.report?.inspection.allBundleIdsMatched === true;

            return (
              <article className="signing-queue-item" key={item.path}>
                <div className="signing-queue-row">
                  <div className="signing-file-meta">
                    <strong>{main?.name || fileName(item.path)}</strong>
                    <span>{main?.bundleIdentifier || item.path}</span>
                    {main?.signingBundleIdentifier && main.signingBundleIdentifier !== main.bundleIdentifier && (
                      <small>Signing ID: {main.signingBundleIdentifier}</small>
                    )}
                  </div>
                  <div className="signing-row-actions">
                    <span className={`signing-status status-${item.stage}`}>{stageLabel[item.stage]}</span>
                    {!busy && canExportBundle && (
                      <button onClick={() => exportSigningBundle(item.path)} disabled={exportingBundlePath !== null} title="Export P12, provisioning profiles, metadata and SHA-256 checksums">
                        {exportingBundlePath === item.path ? "Exporting…" : "Export bundle"}
                      </button>
                    )}
                    {!busy && <button className="signing-remove" onClick={() => removeItem(item.path)}>Remove</button>}
                  </div>
                </div>

                {main?.appIdMatch && (
                  <div className="signing-profile-line">
                    <span>Profile</span><strong>{main.appIdMatch.profileName || main.appIdMatch.name}</strong><span>{main.appIdMatch.profileStatus || "Pending"}</span>
                  </div>
                )}

                {item.report?.entitlements && (
                  <div className="signing-profile-line">
                    <span>Entitlements</span><strong>{item.report.entitlements.blockingCount} blocking</strong><span>{item.report.entitlements.warningCount} warning(s)</span>
                  </div>
                )}

                {(item.report?.inspection.requiresRegistrationBundleIds.length || 0) > 0 && (
                  <div className="signing-note">App IDs to register automatically: {item.report?.inspection.requiresRegistrationBundleIds.join(", ")}</div>
                )}

                {(blockingChecks?.length || 0) > 0 && (
                  <div className="signing-checks signing-checks-error">{blockingChecks?.map((check) => <div key={check.code}>{check.message}</div>)}</div>
                )}
                {(entitlementBlocking?.length || 0) > 0 && (
                  <div className="signing-checks signing-checks-error">{entitlementBlocking?.map((message, index) => <div key={`entitlement-error-${index}`}>{message}</div>)}</div>
                )}
                {(warnings?.length || 0) > 0 && (
                  <div className="signing-checks signing-checks-warning">{warnings?.map((check) => <div key={check.code}>{check.message}</div>)}</div>
                )}
                {(entitlementWarnings?.length || 0) > 0 && (
                  <div className="signing-checks signing-checks-warning">{entitlementWarnings?.map((message, index) => <div key={`entitlement-warning-${index}`}>{message}</div>)}</div>
                )}

                {item.validation && (
                  <div className="signing-note">
                    Signed IPA validation: {item.validation.valid ? "passed" : "failed"}; extensions {item.validation.extensionProfiles}/{item.validation.extensionCount} profiled.
                  </div>
                )}
                {item.outputPath && <div className="signing-result-path">Signed IPA: {item.outputPath}</div>}
                {item.error && <div className="signing-checks signing-checks-error">{item.error}</div>}
              </article>
            );
          })}
        </div>
      )}
    </div>
  );
};
