import "./Certificates.css";
import { invoke } from "@tauri-apps/api/core";
import { open as openFileDialog } from "@tauri-apps/plugin-dialog";
import { useCallback, useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import { useError } from "../ErrorContext";
import { useTranslation } from "react-i18next";

export type Certificate = {
  name: string;
  certificateId: string;
  serialNumber: string;
  machineName: string;
  machineId: string;
};

type AppId = {
  appIdId: string;
  identifier: string;
  name: string;
};

type AppIdsResponse = {
  appIds: AppId[];
};

type SigningExportInfo = {
  directory: string;
  p12Password: string;
  teamId: string;
  certificateSerialNumber: string;
  appIdentifier: string;
  profileExpirationDate: string;
};

type CompleteSigningBundleExportInfo = {
  archivePath: string;
  p12Password: string;
  teamId: string;
  certificateSerialNumber: string;
  profiles: Array<{
    role: string;
    name: string;
    bundleIdentifier: string;
    signingBundleIdentifier: string;
    profileUuid: string;
    profileName: string;
    profileExpirationDate: string;
    isFreeProvisioningProfile?: boolean | null;
    archivePath: string;
  }>;
  checksums: string[];
};

const fileName = (path: string) => path.split(/[\\/]/).pop() || path;

export const Certificates = () => {
  const { t } = useTranslation();
  const [certificates, setCertificates] = useState<Certificate[]>([]);
  const [appIds, setAppIds] = useState<AppId[]>([]);
  const [selectedAppId, setSelectedAppId] = useState("");
  const [password, setPassword] = useState("");
  const [completeBundleIpa, setCompleteBundleIpa] = useState("");
  const [exportingCompleteBundle, setExportingCompleteBundle] = useState(false);
  const [loading, setLoading] = useState<boolean>(false);
  const loadingRef = useRef<boolean>(false);
  const { err } = useError();

  const loadCertificates = useCallback(async () => {
    if (loadingRef.current) return;
    const promise = async () => {
      loadingRef.current = true;
      setLoading(true);
      try {
        const [certs, apps] = await Promise.all([
          invoke<Certificate[]>("get_certificates"),
          invoke<AppIdsResponse>("list_app_ids"),
        ]);
        setCertificates(certs);
        setAppIds(apps.appIds);
        setSelectedAppId((current) => current || apps.appIds[0]?.appIdId || "");
      } finally {
        setLoading(false);
        loadingRef.current = false;
      }
    };
    toast.promise(promise, {
      loading: t("certificates.loading"),
      success: t("certificates.loaded_success"),
      error: (e) => err(t("certificates.failed_load"), e),
    });
  }, [t, err]);

  const revokeCertificate = useCallback(
    async (serialNumber: string) => {
      const promise = invoke<void>("revoke_certificate", {
        serialNumber,
      });
      promise.then(loadCertificates);
      toast.promise(promise, {
        loading: t("certificates.revoking"),
        success: t("certificates.revoked_success"),
        error: (e) => err(t("certificates.failed_revoke"), e),
      });
    },
    [loadCertificates, t, err],
  );

  const exportBundle = useCallback(async () => {
    if (!selectedAppId) {
      toast.warning("Choose an App ID before exporting.");
      return;
    }

    const promise = invoke<SigningExportInfo | null>("export_signing_bundle", {
      appIdId: selectedAppId,
      password: password.trim() || null,
    });

    toast.promise(promise, {
      loading: "Exporting signing bundle…",
      success: (result) =>
        result
          ? `Exported to ${result.directory}. P12 password: ${result.p12Password}`
          : "Export canceled",
      error: (e) => err("Failed to export signing bundle", e),
    });
  }, [selectedAppId, password, err]);

  const chooseCompleteBundleIpa = useCallback(async () => {
    const selected = await openFileDialog({
      multiple: false,
      filters: [{ name: "IPA files", extensions: ["ipa"] }],
    });
    if (typeof selected === "string") {
      setCompleteBundleIpa(selected);
    }
  }, []);

  const exportCompleteBundle = useCallback(async () => {
    if (!completeBundleIpa) {
      toast.warning("Choose an IPA before exporting the complete signing bundle.");
      return;
    }

    setExportingCompleteBundle(true);
    try {
      const result = await invoke<CompleteSigningBundleExportInfo | null>(
        "export_ipa_signing_bundle",
        {
          ipaPath: completeBundleIpa,
          password: password.trim() || null,
        },
      );
      if (!result) {
        toast.info("Export canceled");
        return;
      }
      toast.success(
        `Exported ${result.profiles.length} provisioning profile(s) to ${result.archivePath}. P12 password: ${result.p12Password}`,
      );
    } catch (e) {
      toast.error(err("Failed to export complete signing bundle", e));
    } finally {
      setExportingCompleteBundle(false);
    }
  }, [completeBundleIpa, password, err]);

  useEffect(() => {
    loadCertificates();
  }, []);

  return (
    <>
      <h2>{t("certificates.manage")}</h2>
      {certificates.length === 0 ? (
        <div>{loading ? t("certificates.loading") : t("certificates.none_found")}</div>
      ) : (
        <div className="card">
          <div className="certificate-table-container">
            <table className="certificate-table">
              <thead>
                <tr className="certificate-item">
                  <th className="cert-item-part">{t("certificates.name")}</th>
                  <th className="cert-item-part">{t("certificates.serial_number")}</th>
                  <th className="cert-item-part">{t("certificates.machine_name")}</th>
                  <th className="cert-item-part">{t("certificates.machine_id")}</th>
                  <th>{t("certificates.revoke")}</th>
                </tr>
              </thead>
              <tbody>
                {certificates.map((cert, i) => (
                  <tr
                    key={cert.certificateId}
                    className={
                      "certificate-item" +
                      (i === certificates.length - 1 ? " cert-item-last" : "")
                    }
                  >
                    <td className="cert-item-part">{cert.name}</td>
                    <td className="cert-item-part">{cert.serialNumber}</td>
                    <td className="cert-item-part">{cert.machineName}</td>
                    <td className="cert-item-part">{cert.machineId}</td>
                    <td
                      className="cert-item-revoke"
                      role="button"
                      tabIndex={0}
                      onClick={() => revokeCertificate(cert.serialNumber)}
                    >
                      {t("certificates.revoke")}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
      <div className="card" style={{ marginTop: "1em", padding: "1em" }}>
        <h3 style={{ marginTop: 0 }}>Export signing bundle</h3>
        <p className="settings-hint">
          Exports development.p12, development.mobileprovision and certificate.json.
          Provisioning profiles are App-ID specific.
        </p>
        <select
          value={selectedAppId}
          onChange={(e) => setSelectedAppId(e.target.value)}
          style={{ width: "100%", marginBottom: "0.75em" }}
        >
          <option value="">Choose App ID</option>
          {appIds.map((app) => (
            <option key={app.appIdId} value={app.appIdId}>
              {app.name} — {app.identifier}
            </option>
          ))}
        </select>
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="P12 password (blank = certificate Machine ID)"
          style={{ width: "100%", boxSizing: "border-box", marginBottom: "0.75em" }}
        />
        <button style={{ width: "100%" }} onClick={exportBundle} disabled={!selectedAppId}>
          Export P12 + mobileprovision
        </button>
      </div>

      <div className="card" style={{ marginTop: "1em", padding: "1em" }}>
        <h3 style={{ marginTop: 0 }}>Export complete IPA signing bundle</h3>
        <p className="settings-hint">
          Creates one ZIP containing the P12 identity, the main provisioning profile, every
          extension provisioning profile, metadata.json and SHA-256 checksums. The P12 password
          is returned after export and is never written into the ZIP.
        </p>
        <button
          style={{ width: "100%", marginBottom: "0.75em" }}
          onClick={chooseCompleteBundleIpa}
          disabled={exportingCompleteBundle}
        >
          {completeBundleIpa ? `IPA: ${fileName(completeBundleIpa)}` : "Choose IPA"}
        </button>
        <button
          style={{ width: "100%" }}
          onClick={exportCompleteBundle}
          disabled={!completeBundleIpa || exportingCompleteBundle}
        >
          {exportingCompleteBundle ? "Exporting complete bundle…" : "Export complete signing bundle ZIP"}
        </button>
      </div>

      <button
        style={{ marginTop: "1em", width: "100%" }}
        onClick={loadCertificates}
        disabled={loading}
      >
        {t("common.refresh")}
      </button>
    </>
  );
};
