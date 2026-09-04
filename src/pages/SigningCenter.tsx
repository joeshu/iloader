import "./SigningCenter.css";

import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { open as openDialog } from "@tauri-apps/plugin-dialog";
import { useCallback, useEffect, useMemo, useState } from "react";
import { toast } from "sonner";

export type SigningCenterProps = {
  deviceUdid?: string | null;
};

type SigningCenterSnapshot = {
  email: string;
  teamId: string;
  certificates: Array<{
    name?: string | null;
    certificateId?: string | null;
    serialNumber?: string | null;
    machineName?: string | null;
    machineId?: string | null;
  }>;
  appIds: Array<{
    appIdId: string;
    identifier: string;
    name: string;
    featureKeys: string[];
    expirationDate?: string | null;
  }>;
  devices: Array<{
    name?: string | null;
    deviceId?: string | null;
    udid: string;
    status?: string | null;
  }>;
  maxAppIds?: number | null;
  availableAppIds?: number | null;
};

type IpaProfileMatch = {
  appIdId: string;
  identifier: string;
  name: string;
  profileUuid?: string | null;
  profileName?: string | null;
  profileStatus?: string | null;
  profileExpirationDate?: string | null;
  isFreeProvisioningProfile?: boolean | null;
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
  checks: AutoPreflightCheck[];
};

type BatchSigningItemResult = {
  inputPath: string;
  appName?: string | null;
  bundleIdentifier?: string | null;
  status: "signed" | "failed";
  outputPath?: string | null;
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
  stage: "inspecting" | "signing" | "packaging" | "signed" | "failed";
  appName?: string | null;
  bundleIdentifier?: string | null;
  outputPath?: string | null;
  error?: string | null;
};

type QueueStage =
  | "pending"
  | "scanning"
  | "ready"
  | "blocked"
  | "inspecting"
  | "signing"
  | "packaging"
  | "signed"
  | "failed";

type QueueItem = {
  path: string;
  stage: QueueStage;
  report?: AutoIpaPreflightReport;
  error?: string;
  outputPath?: string;
};

const fileName = (path: string) => path.split(/[\\/]/).pop() || path;

const stageLabel: Record<QueueStage, string> = {
  pending: "Pending",
  scanning: "Scanning",
  ready: "Ready",
  blocked: "Blocked",
  inspecting: "Inspecting",
  signing: "Signing",
  packaging: "Packaging",
  signed: "Signed",
  failed: "Failed",
};

export const SigningCenter = ({ deviceUdid }: SigningCenterProps) => {
  const [snapshot, setSnapshot] = useState<SigningCenterSnapshot | null>(null);
  const [queue, setQueue] = useState<QueueItem[]>([]);
  const [outputDirectory, setOutputDirectory] = useState("");
  const [loadingSnapshot, setLoadingSnapshot] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [signing, setSigning] = useState(false);

  const loadSnapshot = useCallback(async () => {
    setLoadingSnapshot(true);
    try {
      const next = await invoke<SigningCenterSnapshot>("get_signing_center_snapshot");
      setSnapshot(next);
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
    let cleanup: (() => void) | undefined;

    listen<BatchSigningProgress>("batch_signing_progress", (event) => {
      const progress = event.payload;
      setQueue((current) =>
        current.map((item) =>
          item.path === progress.inputPath
            ? {
                ...item,
                stage: progress.stage,
                outputPath: progress.outputPath || item.outputPath,
                error: progress.error || item.error,
              }
            : item,
        ),
      );
    }).then((unlisten) => {
      if (disposed) {
        unlisten();
      } else {
        cleanup = unlisten;
      }
    });

    return () => {
      disposed = true;
      cleanup?.();
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
    const selected = await openDialog({
      directory: true,
      multiple: false,
    });
    if (typeof selected === "string") {
      setOutputDirectory(selected);
    }
  }, []);

  const scanQueue = useCallback(async () => {
    if (queue.length === 0) {
      toast.warning("Select at least one IPA first.");
      return;
    }

    setScanning(true);
    try {
      for (const item of queue) {
        setQueue((current) =>
          current.map((candidate) =>
            candidate.path === item.path
              ? { ...candidate, stage: "scanning", report: undefined, error: undefined }
              : candidate,
          ),
        );

        try {
          const report = await invoke<AutoIpaPreflightReport>("preflight_ipa", {
            ipaPath: item.path,
            deviceUdid: deviceUdid || null,
          });
          setQueue((current) =>
            current.map((candidate) =>
              candidate.path === item.path
                ? {
                    ...candidate,
                    stage: report.ready ? "ready" : "blocked",
                    report,
                    error: undefined,
                  }
                : candidate,
            ),
          );
        } catch (error) {
          setQueue((current) =>
            current.map((candidate) =>
              candidate.path === item.path
                ? { ...candidate, stage: "failed", error: String(error) }
                : candidate,
            ),
          );
        }
      }
    } finally {
      setScanning(false);
    }
  }, [queue, deviceUdid]);

  const readyPaths = useMemo(
    () => queue.filter((item) => item.stage === "ready").map((item) => item.path),
    [queue],
  );

  const signReady = useCallback(async () => {
    if (readyPaths.length === 0) {
      toast.warning("No preflight-ready IPA is available to sign.");
      return;
    }
    if (!outputDirectory) {
      toast.warning("Choose an output directory first.");
      return;
    }

    setSigning(true);
    try {
      const report = await invoke<BatchSigningReport>("batch_sign_ipas", {
        ipaPaths: readyPaths,
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
            error: result.error || undefined,
          };
        }),
      );

      if (report.failed === 0) {
        toast.success(`Signed ${report.signed} IPA(s).`);
      } else {
        toast.warning(`Signed ${report.signed}; ${report.failed} failed.`);
      }
    } catch (error) {
      toast.error(`Batch signing failed: ${String(error)}`);
    } finally {
      setSigning(false);
    }
  }, [readyPaths, outputDirectory]);

  const removeItem = useCallback((path: string) => {
    setQueue((current) => current.filter((item) => item.path !== path));
  }, []);

  const summary = useMemo(() => {
    const ready = queue.filter((item) => item.stage === "ready").length;
    const blocked = queue.filter((item) => item.stage === "blocked").length;
    const signed = queue.filter((item) => item.stage === "signed").length;
    const failed = queue.filter((item) => item.stage === "failed").length;
    return { ready, blocked, signed, failed };
  }, [queue]);

  return (
    <div className="signing-center">
      <div className="signing-center-header">
        <div>
          <h2>Signing Center</h2>
          <p className="signing-center-subtitle">
            Inspect IPA metadata, validate signing prerequisites, match provisioning assets and sign batches without one failed IPA blocking the rest.
          </p>
        </div>
        <button onClick={loadSnapshot} disabled={loadingSnapshot || scanning || signing}>
          {loadingSnapshot ? "Refreshing…" : "Refresh assets"}
        </button>
      </div>

      <div className="signing-asset-grid">
        <div className="signing-asset-card">
          <span>Team</span>
          <strong>{snapshot?.teamId || "—"}</strong>
          <small>{snapshot?.email || "Not loaded"}</small>
        </div>
        <div className="signing-asset-card">
          <span>Certificates</span>
          <strong>{snapshot?.certificates.length ?? "—"}</strong>
          <small>Development identities</small>
        </div>
        <div className="signing-asset-card">
          <span>App IDs</span>
          <strong>{snapshot?.appIds.length ?? "—"}</strong>
          <small>
            {snapshot?.availableAppIds == null
              ? "Quota unavailable"
              : `${snapshot.availableAppIds} slots available`}
          </small>
        </div>
        <div className="signing-asset-card">
          <span>Devices</span>
          <strong>{snapshot?.devices.length ?? "—"}</strong>
          <small>{deviceUdid ? "Current device linked to preflight" : "No target device selected"}</small>
        </div>
      </div>

      <div className="signing-toolbar">
        <button onClick={selectIpas} disabled={scanning || signing}>Select IPAs</button>
        <button onClick={scanQueue} disabled={queue.length === 0 || scanning || signing}>
          {scanning ? "Scanning…" : "Scan & preflight"}
        </button>
        <button onClick={selectOutputDirectory} disabled={scanning || signing}>
          Choose output folder
        </button>
        <button
          className="signing-primary"
          onClick={signReady}
          disabled={readyPaths.length === 0 || scanning || signing}
        >
          {signing ? "Signing batch…" : `Sign ready (${readyPaths.length})`}
        </button>
      </div>

      <div className="signing-output-path" title={outputDirectory}>
        <span>Output</span>
        <strong>{outputDirectory || "Choose a destination for signed IPA files"}</strong>
      </div>

      <div className="signing-summary">
        <span>{queue.length} total</span>
        <span>{summary.ready} ready</span>
        <span>{summary.blocked} blocked</span>
        <span>{summary.signed} signed</span>
        <span>{summary.failed} failed</span>
      </div>

      {queue.length === 0 ? (
        <div className="signing-empty">
          Select multiple IPA files to build a signing queue. Each IPA is isolated so inspection or signing failures do not stop the remaining batch.
        </div>
      ) : (
        <div className="signing-queue">
          {queue.map((item) => {
            const main = item.report?.inspection.main;
            const blockingChecks = item.report?.checks.filter(
              (check) => check.severity === "error" && !check.passed,
            );
            const warnings = item.report?.checks.filter(
              (check) => check.severity === "warning",
            );

            return (
              <article className="signing-queue-item" key={item.path}>
                <div className="signing-queue-row">
                  <div className="signing-file-meta">
                    <strong>{main?.name || fileName(item.path)}</strong>
                    <span>{main?.bundleIdentifier || item.path}</span>
                    {main?.signingBundleIdentifier &&
                      main.signingBundleIdentifier !== main.bundleIdentifier && (
                        <small>Signing ID: {main.signingBundleIdentifier}</small>
                      )}
                  </div>
                  <div className="signing-row-actions">
                    <span className={`signing-status status-${item.stage}`}>
                      {stageLabel[item.stage]}
                    </span>
                    {!signing && (
                      <button className="signing-remove" onClick={() => removeItem(item.path)}>
                        Remove
                      </button>
                    )}
                  </div>
                </div>

                {main?.appIdMatch && (
                  <div className="signing-profile-line">
                    <span>Profile</span>
                    <strong>{main.appIdMatch.profileName || main.appIdMatch.name}</strong>
                    <span>{main.appIdMatch.profileStatus || "Pending"}</span>
                  </div>
                )}

                {(item.report?.inspection.requiresRegistrationBundleIds.length || 0) > 0 && (
                  <div className="signing-note">
                    App IDs to register automatically: {item.report?.inspection.requiresRegistrationBundleIds.join(", ")}
                  </div>
                )}

                {(blockingChecks?.length || 0) > 0 && (
                  <div className="signing-checks signing-checks-error">
                    {blockingChecks?.map((check) => (
                      <div key={check.code}>{check.message}</div>
                    ))}
                  </div>
                )}

                {(warnings?.length || 0) > 0 && (
                  <div className="signing-checks signing-checks-warning">
                    {warnings?.map((check) => (
                      <div key={check.code}>{check.message}</div>
                    ))}
                  </div>
                )}

                {item.outputPath && (
                  <div className="signing-result-path">Signed IPA: {item.outputPath}</div>
                )}
                {item.error && <div className="signing-checks signing-checks-error">{item.error}</div>}
              </article>
            );
          })}
        </div>
      )}
    </div>
  );
};
