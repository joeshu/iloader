import i18n from "./i18next";

const exactTranslations = new Map<string, string>([
  ["Signing Center", "签名中心"],
  ["Preflight metadata, entitlements and signing assets; persist the queue across restarts; sign, validate and retry failures independently.", "预检应用元数据、权限和签名资产；支持签名队列持久化、签名验证及失败项独立重试。"],
  ["Refreshing…", "正在刷新…"],
  ["Refresh assets", "刷新签名资产"],
  ["Signing asset health", "签名资产状态"],
  ["Healthy", "正常"],
  ["Attention", "注意"],
  ["Blocked", "已阻塞"],
  ["Live refresh", "实时刷新"],
  ["Team", "团队"],
  ["Certificates", "证书"],
  ["Development identities", "开发者签名身份"],
  ["App IDs", "App ID"],
  ["Quota unavailable", "配额信息不可用"],
  ["Devices", "设备"],
  ["Current device linked to preflight", "当前设备已用于预检"],
  ["No target device selected", "未选择目标设备"],
  ["Select IPAs", "选择 IPA"],
  ["Scanning…", "正在扫描…"],
  ["Scan & preflight", "扫描并预检"],
  ["Inspecting bundle…", "正在检查签名包…"],
  ["Inspect signing bundle", "检查签名包"],
  ["Choose output folder", "选择输出文件夹"],
  ["Signing batch…", "正在批量签名…"],
  ["Retry failed", "重试失败项"],
  ["Exporting diagnostics…", "正在导出诊断信息…"],
  ["Export diagnostics", "导出诊断信息"],
  ["Clear completed", "清除已完成"],
  ["Signing Bundle validated staging", "签名包验证暂存"],
  ["Validated staging", "已验证暂存"],
  ["staged", "已暂存"],
  ["invalid", "无效"],
  ["Source IPA", "源 IPA"],
  ["Bundle metadata", "签名包元数据"],
  ["Matches active team", "与当前团队一致"],
  ["Certificate", "证书"],
  ["Serial number", "序列号"],
  ["Profiles", "描述文件"],
  ["Validated for staging only", "仅完成验证暂存"],
  ["Staging blocked", "暂存被阻止"],
  ["Passed", "已通过"],
  ["Integrity, team and profile checks passed. The bundle is validated staging only: no private key or PKCS#12 password is persisted, and the current signing engine does not activate imported credentials.", "完整性、团队和描述文件检查已通过。当前仅完成验证暂存：不会持久化私钥或 PKCS#12 密码，现有签名引擎也不会激活导入的凭据。"],
  ["The bundle cannot enter validated staging until every blocking import check passes.", "所有阻断性导入检查通过后，签名包才能进入验证暂存状态。"],
  ["Latest signing performance", "最近一次签名性能"],
  ["Report unavailable", "报告不可用"],
  ["Inspection", "检查"],
  ["IPA structure and metadata loading", "加载 IPA 结构和元数据"],
  ["Signing", "签名"],
  ["Apple assets, bundle mutation and code signing", "Apple 签名资产、Bundle 修改和代码签名"],
  ["Packaging", "打包"],
  ["Payload ZIP creation and atomic publication", "创建 Payload ZIP 并原子写入输出"],
  ["Validation", "验证"],
  ["Signed IPA structural validation", "已签名 IPA 结构验证"],
  ["Output", "输出位置"],
  ["Choose a destination for signed IPA files", "选择已签名 IPA 的保存位置"],
  ["Select multiple IPA files to build a persistent signing queue. Interrupted work is restored on the next launch, but unsigned items must pass a fresh preflight before signing.", "选择多个 IPA 文件建立持久化签名队列。中断的任务会在下次启动时恢复，但未签名项目在重新签名前必须再次完成预检。"],
  ["Pending", "待处理"],
  ["Scanning", "扫描中"],
  ["Ready", "就绪"],
  ["Inspecting", "检查中"],
  ["Packaging", "打包中"],
  ["Validating", "验证中"],
  ["Signed", "已签名"],
  ["Failed", "失败"],
  ["Export bundle", "导出签名包"],
  ["Exporting…", "正在导出…"],
  ["Remove", "移除"],
  ["Profile", "描述文件"],
  ["Entitlements", "权限"],
  ["Pending", "待处理"],
  ["Export P12, provisioning profiles, metadata and SHA-256 checksums", "导出 P12、Provisioning Profile、元数据和 SHA-256 校验值"],
]);

const dynamicTranslations: Array<[RegExp, (match: RegExpMatchArray) => string]> = [
  [/^Cached · TTL (\d+)s$/, (m) => `缓存 · TTL ${m[1]} 秒`],
  [/^(\d+) slots available$/, (m) => `剩余 ${m[1]} 个可用名额`],
  [/^Sign ready \((\d+)\)$/, (m) => `签名就绪项（${m[1]}）`],
  [/^(\d+) total$/, (m) => `共 ${m[1]} 个`],
  [/^(\d+) ready$/, (m) => `就绪 ${m[1]}`],
  [/^(\d+) blocked$/, (m) => `阻塞 ${m[1]}`],
  [/^(\d+) signed$/, (m) => `已签名 ${m[1]}`],
  [/^(\d+) failed$/, (m) => `失败 ${m[1]}`],
  [/^(\d+) blocking$/, (m) => `阻断 ${m[1]}`],
  [/^(\d+) warning\(s\)$/, (m) => `警告 ${m[1]}`],
  [/^Active: (.+)$/, (m) => `当前团队：${m[1]}`],
  [/^(\d+)\/(\d+) signed$/, (m) => `已签名 ${m[1]}/${m[2]}`],
  [/^Signing report: (.+)$/, (m) => `签名报告：${m[1]}`],
  [/^Signing ID: (.+)$/, (m) => `签名 ID：${m[1]}`],
  [/^App IDs to register automatically: (.+)$/, (m) => `将自动注册的 App ID：${m[1]}`],
  [/^Signed IPA: (.+)$/, (m) => `已签名 IPA：${m[1]}`],
  [/^Signed IPA validation: passed; extensions (\d+)\/(\d+) profiled\.$/, (m) => `已签名 IPA 验证：通过；扩展描述文件 ${m[1]}/${m[2]}。`],
  [/^Signed IPA validation: failed; extensions (\d+)\/(\d+) profiled\.$/, (m) => `已签名 IPA 验证：失败；扩展描述文件 ${m[1]}/${m[2]}。`],
  [/^Failed to load Signing Center: (.+)$/, (m) => `加载签名中心失败：${formatError(m[1])}`],
  [/^Failed to load signing asset health: (.+)$/, (m) => `加载签名资产状态失败：${formatError(m[1])}`],
  [/^Batch preflight failed: (.+)$/, (m) => `批量预检失败：${formatError(m[1])}`],
  [/^Batch signing failed: (.+)$/, (m) => `批量签名失败：${formatError(m[1])}`],
  [/^Failed to inspect signing bundle: (.+)$/, (m) => `检查签名包失败：${formatError(m[1])}`],
  [/^Failed to export signing bundle: (.+)$/, (m) => `导出签名包失败：${formatError(m[1])}`],
  [/^Failed to export diagnostics: (.+)$/, (m) => `导出诊断信息失败：${formatError(m[1])}`],
];

const originalText = new WeakMap<Text, string>();
const originalTitle = new WeakMap<HTMLElement, string>();

function isSimplifiedChinese() {
  const language = i18n.resolvedLanguage || i18n.language || "";
  return language.toLowerCase().replace("-", "_") === "zh_cn";
}

function formatError(value: string) {
  if (value === "[object Object]") return "签名会话暂时被占用，请稍后重试";
  if (/NotLoggedIn|Not logged in/i.test(value)) return "当前 Apple ID 会话暂时不可用，请稍后重试";
  return value;
}

function translateText(value: string) {
  const trimmed = value.trim();
  if (!trimmed) return value;
  const exact = exactTranslations.get(trimmed);
  if (exact) return value.replace(trimmed, exact);
  for (const [pattern, build] of dynamicTranslations) {
    const match = trimmed.match(pattern);
    if (match) return value.replace(trimmed, build(match));
  }
  return value;
}

function processTextNode(node: Text) {
  if (!originalText.has(node)) originalText.set(node, node.nodeValue || "");
  const source = originalText.get(node) || "";
  node.nodeValue = isSimplifiedChinese() ? translateText(source) : source;
}

function processElement(element: HTMLElement) {
  if (element.title) {
    if (!originalTitle.has(element)) originalTitle.set(element, element.title);
    const source = originalTitle.get(element) || "";
    element.title = isSimplifiedChinese() ? translateText(source) : source;
  }
  const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT);
  let current = walker.nextNode();
  while (current) {
    processTextNode(current as Text);
    current = walker.nextNode();
  }
}

function refresh() {
  document.querySelectorAll<HTMLElement>(".signing-center, [data-sonner-toast]").forEach(processElement);
}

let installed = false;
export function installSigningCenterLocalization() {
  if (installed) return;
  installed = true;
  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      mutation.addedNodes.forEach((node) => {
        if (node.nodeType === Node.TEXT_NODE) {
          const parent = node.parentElement;
          if (parent?.closest(".signing-center, [data-sonner-toast]")) processTextNode(node as Text);
          return;
        }
        if (node instanceof HTMLElement) {
          if (node.matches(".signing-center, [data-sonner-toast]") || node.closest(".signing-center, [data-sonner-toast]")) {
            processElement(node);
          } else {
            node.querySelectorAll<HTMLElement>(".signing-center, [data-sonner-toast]").forEach(processElement);
          }
        }
      });
    }
  });
  observer.observe(document.documentElement, { childList: true, subtree: true });
  i18n.on("languageChanged", refresh);
  queueMicrotask(refresh);
}
