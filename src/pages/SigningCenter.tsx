import "./SigningCenter.css";

import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { open as openDialog } from "@tauri-apps/plugin-dialog";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";
import i18n from "../i18next";

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

type AssetHealthStatus = "healthy" | "warning" | "error";

type AssetHealthCheck = {
  code: string;
  status: AssetHealthStatus;
  title: string;
  message: string;
};

type SigningAssetHealthReport = {
  generatedAtUtc: string;
  cached: boolean;
  cacheTtlSeconds: number;
  teamId: string;
  email: string;
  overallStatus: AssetHealthStatus;
  certificateCount: number;
  appIdCount: number;
  deviceCount: number;
  maxAppIds?: number | null;
  availableAppIds?: number | null;
  checks: AssetHealthCheck[];
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

type BatchSigningStageTimings = {
  inspectionMs: number;
  signingMs: number;
  packagingMs: number;
  validationMs: number;
};

type BatchSigningItemResult = {
  inputPath: string;
  status: "signed" | "failed";
  outputPath?: string | null;
  validation?: SignedIpaValidation | null;
  error?: string | null;
  durationMs: number;
  stageTimings: BatchSigningStageTimings;
};

type BatchSigningReport = {
  total: number;
  signed: number;
  failed: number;
  outputDirectory: string;
  batchDurationMs: number;
  reportPath?: string | null;
  reportError?: string | null;
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

type SigningBundleImportCheck = {
  code: string;
  severity: "info" | "warning" | "error";
  passed: boolean;
  message: string;
};

type SigningBundleImportedProfile = {
  role: string;
  name: string;
  bundleIdentifier: string;
  signingBundleIdentifier: string;
  profileUuid: string;
  profileName: string;
  profileExpirationDate: string;
  isFreeProvisioningProfile?: boolean | null;
  archivePath: string;
};

type SigningBundleImportReport = {
  valid: boolean;
  canActivate: boolean;
  archivePath: string;
  sourceIpa: string;
  teamId: string;
  currentTeamId: string;
  certificateSerialNumber: string;
  profileCount: number;
  profiles: SigningBundleImportedProfile[];
  checks: SigningBundleImportCheck[];
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
const formatDuration = (milliseconds: number) => {
  if (milliseconds < 1000) return `${milliseconds} ms`;
  return `${(milliseconds / 1000).toFixed(milliseconds < 10_000 ? 2 : 1)} s`;
};

const formatInvokeError = (error: unknown): string => {
  if (typeof error === "string") return error;
  if (error instanceof Error) return error.message;
  if (error && typeof error === "object") {
    const candidate = error as { message?: unknown; type?: unknown };
    if (typeof candidate.message === "string") return candidate.message;
    if (typeof candidate.type === "string") return candidate.type;
    try {
      return JSON.stringify(error);
    } catch {
      return "Unknown error";
    }
  }
  return String(error);
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
                : i18n.t("signing_center.restored_queue"),
          };
        }),
    };
  } catch {
    return { version: 1, outputDirectory: "", queue: [] };
  }
};

export const SigningCenter = ({ deviceUdid }: SigningCenterProps) => {
  const { t } = useTranslation();
  const initialState = useRef(restoreQueueState()).current;
  const [snapshot, setSnapshot] = useState<SigningCenterSnapshot | null>(null);
  const [assetHealth, setAssetHealth] = useState<SigningAssetHealthReport | null>(null);
  const [queue, setQueue] = useState<QueueItem[]>(initialState.queue);
  const [outputDirectory, setOutputDirectory] = useState(initialState.outputDirectory);
  const [loadingSnapshot, setLoadingSnapshot] = useState(false);
  const [loadingHealth, setLoadingHealth] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [signing, setSigning] = useState(false);
  const [exportingBundlePath, setExportingBundlePath] = useState<string | null>(null);
  const [exportingDiagnostics, setExportingDiagnostics] = useState(false);
  const [inspectingImport, setInspectingImport] = useState(false);
  const [importReport, setImportReport] = useState<SigningBundleImportReport | null>(null);
  const [lastSigningReport, setLastSigningReport] = useState<BatchSigningReport | null>(null);

  const stageLabel = useCallback((stage: QueueStage) => t(`signing_center.stage.${stage}`), [t]);
  const healthLabel = useCallback(
    (status: AssetHealthStatus) =>
      status === "healthy"
        ? t("signing_center.healthy")
        : status === "warning"
          ? t("signing_center.attention")
          : t("signing_center.blocked"),
    [t],
  );

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
      toast.error(`${t("signing_center.load_failed")}: ${formatInvokeError(error)}`);
    } finally {
      setLoadingSnapshot(false);
    }
  }, [t]);

  const loadAssetHealth = useCallback(async (forceRefresh = false) => {
    setLoadingHealth(true);
    try {
      setAssetHealth(
        await invoke<SigningAssetHealthReport>("get_signing_asset_health", { forceRefresh }),
      );
    } catch (error) {
      toast.error(`${t("signing_center.asset_health_failed")}: ${formatInvokeError(error)}`);
    } finally {
      setLoadingHealth(false);
    }
  }, [t]);

  const refreshAssets = useCallback(async () => {
    await Promise.all([loadSnapshot(), loadAssetHealth(true)]);
  }, [loadSnapshot, loadAssetHealth]);

  useEffect(() => {
    void Promise.all([loadSnapshot(), loadAssetHealth(false)]);
  }, [loadSnapshot, loadAssetHealth]);

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
      filters: [{ name: t("signing_center.ipa_files"), extensions: ["ipa"] }],
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
  }, [t]);

  const inspectSigningBundle = useCallback(async () => {
    const selected = await openDialog({
      multiple: false,
      filters: [{ name: t("signing_center.signing_bundle"), extensions: ["zip"] }],
    });
    if (typeof selected !== "string") return;

    setInspectingImport(true);
    setImportReport(null);
    try {
      const report = await invoke<SigningBundleImportReport>("inspect_signing_bundle_import", {
        archivePath: selected,
      });
      setImportReport(report);
      if (report.valid) {
        toast.success(t("signing_center.import_success", { count: report.profileCount }));
      } else {
        toast.warning(t("signing_center.import_blocked"));
      }
    } catch (error) {
      toast.error(t("signing_center.import_failed", { error: formatInvokeError(error) }));
    } finally {
      setInspectingImport(false);
    }
  }, [t]);

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
              return {
                ...item,
                stage: "failed",
                report: undefined,
                error: result.error || t("signing_center.preflight_failed"),
              };
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
        const message = t("signing_center.batch_preflight_failed", {
          error: formatInvokeError(error),
        });
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
    [deviceUdid, t],
  );

  const scanQueue = useCallback(async () => {
    const candidates = queue.filter((item) => item.stage !== "signed").map((item) => item.path);
    if (candidates.length === 0) {
      toast.warning(
        queue.length === 0
          ? t("signing_center.select_ipa_first")
          : t("signing_center.no_unsigned"),
      );
      return;
    }

    const report = await preflightPaths(candidates);
    if (!report) return;
    if (report.blocked === 0 && report.failed === 0) {
      toast.success(t("signing_center.ready_to_sign", { count: report.ready }));
    } else {
      toast.warning(
        t("signing_center.preflight_summary", {
          ready: report.ready,
          blocked: report.blocked,
          failed: report.failed,
        }),
      );
    }
  }, [queue, preflightPaths, t]);

  const signPaths = useCallback(
    async (ipaPaths: string[]) => {
      if (ipaPaths.length === 0) return;
      if (!outputDirectory) {
        toast.warning(t("signing_center.choose_output_first"));
        return;
      }

      setSigning(true);
      setLastSigningReport(null);
      try {
        const report = await invoke<BatchSigningReport>("batch_sign_ipas", {
          ipaPaths,
          outputDirectory,
        });
        setLastSigningReport(report);
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

        const reportSuffix = report.reportPath
          ? t("signing_center.report_suffix", { name: fileName(report.reportPath) })
          : "";
        if (report.failed === 0) {
          toast.success(
            t("signing_center.signed_success", {
              signed: report.signed,
              duration: formatDuration(report.batchDurationMs),
              report: reportSuffix,
            }),
          );
        } else {
          toast.warning(
            t("signing_center.signed_partial", {
              signed: report.signed,
              failed: report.failed,
              duration: formatDuration(report.batchDurationMs),
              report: reportSuffix,
            }),
          );
        }
        if (report.reportError) toast.warning(report.reportError);
        void Promise.all([loadSnapshot(), loadAssetHealth(true)]);
      } catch (error) {
        toast.error(t("signing_center.batch_signing_failed", { error: formatInvokeError(error) }));
      } finally {
        setSigning(false);
      }
    },
    [outputDirectory, loadSnapshot, loadAssetHealth, t],
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
      toast.info(t("signing_center.no_retry_items"));
      return;
    }

    const report = await preflightPaths(retryPaths);
    if (!report) return;
    const nowReady = report.items
      .filter((item) => item.report?.ready)
      .map((item) => item.inputPath);

    if (nowReady.length === 0) {
      toast.warning(t("signing_center.retry_none_ready"));
      return;
    }
    if (!outputDirectory) {
      toast.success(t("signing_center.retry_ready_choose_output", { count: nowReady.length }));
      return;
    }
    await signPaths(nowReady);
  }, [queue, preflightPaths, outputDirectory, signPaths, t]);

  const exportSigningBundle = useCallback(async (ipaPath: string) => {
    setExportingBundlePath(ipaPath);
    try {
      const result = await invoke<CompleteSigningBundleExportInfo | null>("export_ipa_signing_bundle", {
        ipaPath,
        password: null,
      });
      if (!result) {
        toast.info(t("signing_center.bundle_export_canceled"));
        return;
      }
      toast.success(
        t("signing_center.bundle_export_success", {
          count: result.profiles.length,
          path: result.archivePath,
          password: result.p12Password,
        }),
      );
    } catch (error) {
      toast.error(t("signing_center.bundle_export_failed", { error: formatInvokeError(error) }));
    } finally {
      setExportingBundlePath(null);
    }
  }, [t]);

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
        toast.info(t("signing_center.diagnostics_export_canceled"));
        return;
      }
      toast.success(
        t("signing_center.diagnostics_export_success", {
          path: result.archivePath,
          queueItems: result.queueItems,
          logFiles: result.includedLogFiles,
        }),
      );
    } catch (error) {
      toast.error(t("signing_center.diagnostics_export_failed", { error: formatInvokeError(error) }));
    } finally {
      setExportingDiagnostics(false);
    }
  }, [queue, t]);

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

  const stageTotals = useMemo(() => {
    const totals: BatchSigningStageTimings = {
      inspectionMs: 0,
      signingMs: 0,
      packagingMs: 0,
      validationMs: 0,
    };
    for (const item of lastSigningReport?.items || []) {
      totals.inspectionMs += item.stageTimings.inspectionMs;
      totals.signingMs += item.stageTimings.signingMs;
      totals.packagingMs += item.stageTimings.packagingMs;
      totals.validationMs += item.stageTimings.validationMs;
    }
    return totals;
  }, [lastSigningReport]);

  const busy = scanning || signing || inspectingImport;
  const assetBusy = loadingSnapshot || loadingHealth;

  return (
    <div className="signing-center">
      <div className="signing-center-header">
        <div>
          <h2>{t("signing_center.title")}</h2>
          <p className="signing-center-subtitle">{t("signing_center.subtitle")}</p>
        </div>
        <button onClick={refreshAssets} disabled={assetBusy || busy}>
          {assetBusy ? t("signing_center.refreshing") : t("signing_center.refresh_assets")}
        </button>
      </div>

      {assetHealth && (
        <section className={`signing-health-panel health-${assetHealth.overallStatus}`}>
          <div className="signing-health-header">
            <div>
              <span className="signing-health-kicker">{t("signing_center.asset_health")}</span>
              <div className="signing-health-title-row">
                <strong>{healthLabel(assetHealth.overallStatus)}</strong>
                <span className={`signing-health-badge health-${assetHealth.overallStatus}`}>
                  {healthLabel(assetHealth.overallStatus)}
                </span>
              </div>
            </div>
            <small>
              {assetHealth.cached
                ? t("signing_center.cached_ttl", { seconds: assetHealth.cacheTtlSeconds })
                : t("signing_center.live_refresh")}
            </small>
          </div>
          <div className="signing-health-checks">
            {assetHealth.checks.map((check) => (
              <div className={`signing-health-check health-${check.status}`} key={check.code}>
                <div className="signing-health-check-title">
                  <strong>{check.title}</strong>
                  <span>{healthLabel(check.status)}</span>
                </div>
                <small>{check.message}</small>
              </div>
            ))}
          </div>
        </section>
      )}

      <div className="signing-asset-grid">
        <div className="signing-asset-card">
          <span>{t("signing_center.team")}</span>
          <strong>{snapshot?.teamId || assetHealth?.teamId || "—"}</strong>
          <small>{snapshot?.email || assetHealth?.email || t("signing_center.not_loaded")}</small>
        </div>
        <div className="signing-asset-card">
          <span>{t("signing_center.certificates")}</span>
          <strong>{assetHealth?.certificateCount ?? snapshot?.certificates.length ?? "—"}</strong>
          <small>{t("signing_center.development_identities")}</small>
        </div>
        <div className="signing-asset-card">
          <span>{t("signing_center.app_ids")}</span>
          <strong>{assetHealth?.appIdCount ?? snapshot?.appIds.length ?? "—"}</strong>
          <small>
            {assetHealth?.availableAppIds == null
              ? snapshot?.availableAppIds == null
                ? t("signing_center.quota_unavailable")
                : t("signing_center.slots_available", { count: snapshot.availableAppIds })
              : t("signing_center.slots_available", { count: assetHealth.availableAppIds })}
          </small>
        </div>
        <div className="signing-asset-card">
          <span>{t("signing_center.devices")}</span>
          <strong>{assetHealth?.deviceCount ?? snapshot?.devices.length ?? "—"}</strong>
          <small>
            {deviceUdid
              ? t("signing_center.current_device_linked")
              : t("signing_center.no_target_device")}
          </small>
        </div>
      </div>

      <div className="signing-toolbar">
        <button onClick={selectIpas} disabled={busy}>{t("signing_center.select_ipas")}</button>
        <button onClick={scanQueue} disabled={queue.length === 0 || busy}>
          {scanning ? t("signing_center.scanning") : t("signing_center.scan_preflight")}
        </button>
        <button onClick={inspectSigningBundle} disabled={busy}>
          {inspectingImport
            ? t("signing_center.inspecting_bundle")
            : t("signing_center.inspect_bundle")}
        </button>
        <button onClick={selectOutputDirectory} disabled={busy}>{t("signing_center.choose_output")}</button>
        <button className="signing-primary" onClick={signReady} disabled={readyPaths.length === 0 || busy}>
          {signing
            ? t("signing_center.signing_batch")
            : t("signing_center.sign_ready", { count: readyPaths.length })}
        </button>
        <button onClick={retryFailed} disabled={(summary.failed + summary.blocked === 0) || busy}>
          {t("signing_center.retry_failed")}
        </button>
        <button onClick={exportDiagnostics} disabled={exportingDiagnostics || busy}>
          {exportingDiagnostics
            ? t("signing_center.exporting_diagnostics")
            : t("signing_center.export_diagnostics")}
        </button>
        <button onClick={clearCompleted} disabled={summary.signed === 0 || busy}>
          {t("signing_center.clear_completed")}
        </button>
      </div>

      {importReport && (
        <section className={`signing-health-panel health-${importReport.valid ? "healthy" : "error"}`}>
          <div className="signing-health-header">
            <div>
              <span className="signing-health-kicker">{t("signing_center.import_title")}</span>
              <div className="signing-health-title-row">
                <strong>
                  {importReport.valid
                    ? t("signing_center.validated_staging")
                    : t("signing_center.blocked")}
                </strong>
                <span className={`signing-health-badge health-${importReport.valid ? "healthy" : "error"}`}>
                  {importReport.valid ? t("signing_center.staged") : t("signing_center.invalid")}
                </span>
              </div>
            </div>
            <small>{fileName(importReport.archivePath)}</small>
          </div>
          <div className="signing-asset-grid">
            <div className="signing-asset-card">
              <span>{t("signing_center.source_ipa")}</span>
              <strong>{importReport.sourceIpa || "—"}</strong>
              <small>{t("signing_center.bundle_metadata")}</small>
            </div>
            <div className="signing-asset-card">
              <span>{t("signing_center.team")}</span>
              <strong>{importReport.teamId || "—"}</strong>
              <small>
                {importReport.teamId === importReport.currentTeamId
                  ? t("signing_center.matches_active_team")
                  : t("signing_center.active_team", { team: importReport.currentTeamId })}
              </small>
            </div>
            <div className="signing-asset-card">
              <span>{t("signing_center.certificate")}</span>
              <strong>{importReport.certificateSerialNumber || "—"}</strong>
              <small>{t("signing_center.serial_number")}</small>
            </div>
            <div className="signing-asset-card">
              <span>{t("signing_center.profiles")}</span>
              <strong>{importReport.profileCount}</strong>
              <small>
                {importReport.valid
                  ? t("signing_center.validated_staging_only")
                  : t("signing_center.staging_blocked")}
              </small>
            </div>
          </div>
          <div className="signing-health-checks">
            {importReport.checks.map((check) => {
              const status: AssetHealthStatus = check.passed
                ? check.severity === "warning"
                  ? "warning"
                  : "healthy"
                : "error";
              return (
                <div className={`signing-health-check health-${status}`} key={check.code}>
                  <div className="signing-health-check-title">
                    <strong>{check.code}</strong>
                    <span>{check.passed ? t("signing_center.passed") : t("signing_center.blocked")}</span>
                  </div>
                  <small>{check.message}</small>
                </div>
              );
            })}
          </div>
          <div className="signing-note">
            {importReport.valid
              ? t("signing_center.import_valid_note")
              : t("signing_center.import_blocked_note")}
          </div>
        </section>
      )}

      {lastSigningReport && (
        <section className={`signing-health-panel health-${lastSigningReport.failed === 0 ? "healthy" : "warning"}`}>
          <div className="signing-health-header">
            <div>
              <span className="signing-health-kicker">{t("signing_center.latest_performance")}</span>
              <div className="signing-health-title-row">
                <strong>{formatDuration(lastSigningReport.batchDurationMs)}</strong>
                <span className={`signing-health-badge health-${lastSigningReport.failed === 0 ? "healthy" : "warning"}`}>
                  {t("signing_center.signed", { count: lastSigningReport.signed })} / {lastSigningReport.total}
                </span>
              </div>
            </div>
            <small>
              {lastSigningReport.reportPath
                ? fileName(lastSigningReport.reportPath)
                : t("signing_center.report_unavailable")}
            </small>
          </div>
          <div className="signing-health-checks">
            <div className="signing-health-check health-healthy">
              <div className="signing-health-check-title">
                <strong>{t("signing_center.inspection")}</strong>
                <span>{formatDuration(stageTotals.inspectionMs)}</span>
              </div>
              <small>{t("signing_center.inspection_desc")}</small>
            </div>
            <div className="signing-health-check health-healthy">
              <div className="signing-health-check-title">
                <strong>{t("signing_center.signing")}</strong>
                <span>{formatDuration(stageTotals.signingMs)}</span>
              </div>
              <small>{t("signing_center.signing_desc")}</small>
            </div>
            <div className="signing-health-check health-healthy">
              <div className="signing-health-check-title">
                <strong>{t("signing_center.packaging")}</strong>
                <span>{formatDuration(stageTotals.packagingMs)}</span>
              </div>
              <small>{t("signing_center.packaging_desc")}</small>
            </div>
            <div className="signing-health-check health-healthy">
              <div className="signing-health-check-title">
                <strong>{t("signing_center.validation")}</strong>
                <span>{formatDuration(stageTotals.validationMs)}</span>
              </div>
              <small>{t("signing_center.validation_desc")}</small>
            </div>
          </div>
          {lastSigningReport.reportPath && (
            <div className="signing-result-path">
              {t("signing_center.signing_report", { path: lastSigningReport.reportPath })}
            </div>
          )}
          {lastSigningReport.reportError && (
            <div className="signing-checks signing-checks-warning">{lastSigningReport.reportError}</div>
          )}
        </section>
      )}

      <div className="signing-output-path" title={outputDirectory}>
        <span>{t("signing_center.output")}</span>
        <strong>{outputDirectory || t("signing_center.choose_destination")}</strong>
      </div>

      <div className="signing-summary">
        <span>{t("signing_center.total", { count: queue.length })}</span>
        <span>{t("signing_center.ready", { count: summary.ready })}</span>
        <span>{t("signing_center.blocked_count", { count: summary.blocked })}</span>
        <span>{t("signing_center.signed", { count: summary.signed })}</span>
        <span>{t("signing_center.failed", { count: summary.failed })}</span>
      </div>

      {queue.length === 0 ? (
        <div className="signing-empty">{t("signing_center.empty")}</div>
      ) : (
        <div className="signing-queue">
          {queue.map((item) => {
            const main = item.report?.inspection.main;
            const blockingChecks = item.report?.checks.filter(
              (check) => check.severity === "error" && !check.passed,
            );
            const warnings = item.report?.checks.filter((check) => check.severity === "warning");
            const entitlementBlocking = item.report?.entitlements.bundles.flatMap((bundle) =>
              bundle.items
                .filter((entry) => entry.severity === "error")
                .map((entry) => `${bundle.name}: ${entry.message}`),
            );
            const entitlementWarnings = item.report?.entitlements.bundles.flatMap((bundle) =>
              bundle.items
                .filter((entry) => entry.severity === "warning")
                .map((entry) => `${bundle.name}: ${entry.message}`),
            );
            const canExportBundle = item.stage === "signed";

            return (
              <article className="signing-queue-item" key={item.path}>
                <div className="signing-queue-row">
                  <div className="signing-file-meta">
                    <strong>{main?.name || fileName(item.path)}</strong>
                    <span>{main?.bundleIdentifier || item.path}</span>
                    {main?.signingBundleIdentifier &&
                      main.signingBundleIdentifier !== main.bundleIdentifier && (
                        <small>
                          {t("signing_center.signing_id", { id: main.signingBundleIdentifier })}
                        </small>
                      )}
                  </div>
                  <div className="signing-row-actions">
                    <span className={`signing-status status-${item.stage}`}>{stageLabel(item.stage)}</span>
                    {!busy && canExportBundle && (
                      <button
                        onClick={() => exportSigningBundle(item.path)}
                        disabled={exportingBundlePath !== null}
                        title={t("signing_center.export_bundle_title")}
                      >
                        {exportingBundlePath === item.path
                          ? t("signing_center.exporting")
                          : t("signing_center.export_bundle")}
                      </button>
                    )}
                    {!busy && (
                      <button className="signing-remove" onClick={() => removeItem(item.path)}>
                        {t("signing_center.remove")}
                      </button>
                    )}
                  </div>
                </div>

                {main?.appIdMatch && (
                  <div className="signing-profile-line">
                    <span>{t("signing_center.profile")}</span>
                    <strong>{main.appIdMatch.profileName || main.appIdMatch.name}</strong>
                    <span>{main.appIdMatch.profileStatus || t("signing_center.pending")}</span>
                  </div>
                )}

                {item.report?.entitlements && (
                  <div className="signing-profile-line">
                    <span>{t("signing_center.entitlements")}</span>
                    <strong>
                      {t("signing_center.blocking", {
                        count: item.report.entitlements.blockingCount,
                      })}
                    </strong>
                    <span>
                      {t("signing_center.warnings", {
                        count: item.report.entitlements.warningCount,
                      })}
                    </span>
                  </div>
                )}

                {(item.report?.inspection.requiresRegistrationBundleIds.length || 0) > 0 && (
                  <div className="signing-note">
                    {t("signing_center.auto_register_app_ids", {
                      ids: item.report?.inspection.requiresRegistrationBundleIds.join(", "),
                    })}
                  </div>
                )}
                {(blockingChecks?.length || 0) > 0 && (
                  <div className="signing-checks signing-checks-error">
                    {blockingChecks?.map((check) => <div key={check.code}>{check.message}</div>)}
                  </div>
                )}
                {(entitlementBlocking?.length || 0) > 0 && (
                  <div className="signing-checks signing-checks-error">
                    {entitlementBlocking?.map((message, index) => (
                      <div key={`entitlement-error-${index}`}>{message}</div>
                    ))}
                  </div>
                )}
                {(warnings?.length || 0) > 0 && (
                  <div className="signing-checks signing-checks-warning">
                    {warnings?.map((check) => <div key={check.code}>{check.message}</div>)}
                  </div>
                )}
                {(entitlementWarnings?.length || 0) > 0 && (
                  <div className="signing-checks signing-checks-warning">
                    {entitlementWarnings?.map((message, index) => (
                      <div key={`entitlement-warning-${index}`}>{message}</div>
                    ))}
                  </div>
                )}

                {item.validation && (
                  <div className="signing-note">
                    {t("signing_center.validation_result", {
                      result: item.validation.valid
                        ? t("signing_center.validation_passed")
                        : t("signing_center.validation_failed"),
                      profiled: item.validation.extensionProfiles,
                      total: item.validation.extensionCount,
                    })}
                  </div>
                )}
                {item.outputPath && (
                  <div className="signing-result-path">
                    {t("signing_center.signed_ipa", { path: item.outputPath })}
                  </div>
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
