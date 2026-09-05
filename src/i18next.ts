import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import LanguageDetector from "i18next-browser-languagedetector";

const languages = [
  ["az", "Azərbaycan"],
  ["en", "English"],
  ["am", "Հայերեն"],
  ["es", "Español"],
  ["it", "Italiano"],
  ["de", "Deutsch"],
  ["fr", "Français"],
  ["pl", "Polski"],
  ["nl", "Nederlands"],
  ["vi", "Tiếng Việt"],
  ["ru", "Русский"],
  ["ro", "Română"],
  ["ar", "العربية"],
  ["tr", "Türkçe"],
  ["zh_tw", "Traditional Chinese （繁體中文)"],
  ["zh_cn", "Simplified Chinese （简体中文)"],
  ["ko", "한국어"],
  ["zh_hk", "Cantonese （粵語)"],
  ["ja", "日本語"],
  ["cs_cz", "Čeština"],
  ["sv", "Svenska"],
  ["hu", "Magyar"],
  ["kh", "ភាសាខ្មែរ"],
  ["id", "Bahasa Indonesia"],
  ["pt_br", "Português (Brasileiro)"]
] as const;

export const sortedLanguages = [...languages].sort((a, b) =>
  a[0].localeCompare(b[0]),
);

type TranslationResource = Record<string, unknown>;

const localeModules = import.meta.glob<{ default: TranslationResource }>(
  "./locales/*.json",
  {
    eager: true,
  },
);

const isRecord = (value: unknown): value is TranslationResource =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const deepMerge = (
  target: TranslationResource,
  source: TranslationResource,
): TranslationResource => {
  const merged: TranslationResource = { ...target };
  for (const [key, value] of Object.entries(source)) {
    if (isRecord(value) && isRecord(merged[key])) {
      merged[key] = deepMerge(merged[key] as TranslationResource, value);
    } else {
      merged[key] = value;
    }
  }
  return merged;
};

const translationsByLanguage: Record<string, TranslationResource> = {};
for (const [path, module] of Object.entries(localeModules)) {
  const fileName = path.split("/").pop()?.replace(/\.json$/, "");
  if (!fileName) continue;
  const lang = fileName.split(".")[0];
  translationsByLanguage[lang] = deepMerge(
    translationsByLanguage[lang] || {},
    module.default,
  );
}

const resources = Object.fromEntries(
  Object.entries(translationsByLanguage).map(([lang, translation]) => [
    lang,
    { translation },
  ]),
);

i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    fallbackLng: "en",
    interpolation: {
      escapeValue: false,
    },
    resources,
  });

export default i18n;
