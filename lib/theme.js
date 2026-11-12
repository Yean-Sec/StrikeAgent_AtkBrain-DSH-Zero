/**
 * Decide whether the report should use the dark template as-is or the
 * color-adjusted light variant. The DSH theme preference lives in the Host
 * `ui-theme` settings namespace, so the report team can read the same value
 * the Web UI uses instead of guessing from the graph.
 */
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createRequire } from 'node:module';

const execFileAsync = promisify(execFile);

function validTheme(value) {
  return value === 'light' || value === 'dark' ? value : null;
}

function nativeThemeChoice() {
  try {
    const require = createRequire(import.meta.url);
    const electron = require('electron');
    const nativeTheme = electron?.nativeTheme;
    if (nativeTheme !== null && nativeTheme !== undefined && typeof nativeTheme.shouldUseDarkColors === 'boolean') {
      return nativeTheme.shouldUseDarkColors ? 'dark' : 'light';
    }
  } catch {
    /* not running under Electron, or Electron is unavailable */
  }
  return null;
}

async function systemThemeChoice() {
  if (process.platform !== 'darwin') return null;
  try {
    const { stdout } = await execFileAsync('defaults', ['read', '-g', 'AppleInterfaceStyle'], { timeout: 1500 });
    return String(stdout).trim().toLowerCase() === 'dark' ? 'dark' : 'light';
  } catch {
    // `defaults` exits non-zero on the default light appearance.
    return 'light';
  }
}

async function settingsTheme(ctx) {
  const settings = (() => {
    try {
      return ctx.get('settings');
    } catch {
      return undefined;
    }
  })();
  if (settings === undefined || settings === null || typeof settings.describe !== 'function') return null;
  try {
    const descriptors = await settings.describe({ redactSecrets: true });
    const entry = descriptors.find((item) => String(item?.ns ?? '') === 'ui-theme');
    const preference = entry?.value?.preference;
    if (preference === 'light' || preference === 'dark') return { theme: preference, preference };
    if (preference === 'system') {
      const native = nativeThemeChoice();
      if (native !== null) return { theme: native, preference };
      const system = await systemThemeChoice();
      if (system !== null) return { theme: system, preference };
      return { theme: 'light', preference, systemFallback: true };
    }
    return preference === undefined || preference === null ? null : { theme: null, preference };
  } catch {
    return null;
  }
}

/**
 * Resolve the report theme.
 *
 * @param {object} options `{ ctx, config, explicit }`
 * @returns {Promise<{theme:'light'|'dark', source:string, preference?:string}>}
 */
export async function detectReportTheme({ ctx, config, explicit }) {
  const forced = validTheme(explicit);
  if (forced !== null) return { theme: forced, source: 'argument' };
  const env = validTheme(process.env.ATKBRAIN_REPORT_THEME ?? process.env.PENTEST_REPORT_THEME ?? '');
  if (env !== null) return { theme: env, source: 'environment' };
  if (explicit === undefined || explicit === 'auto') {
    const configured = validTheme(config?.reportTheme);
    if (configured !== null) return { theme: configured, source: 'config' };
    const fromSettings = await settingsTheme(ctx);
    if (fromSettings !== null && validTheme(fromSettings.theme) !== null) {
      return {
        theme: fromSettings.theme,
        source: fromSettings.systemFallback === true ? 'ui-theme:system-light-fallback' : (fromSettings.preference === 'system' ? 'ui-theme:system' : 'ui-theme'),
        preference: fromSettings.preference,
      };
    }
    const native = nativeThemeChoice();
    if (native !== null) return { theme: native, source: 'electron-native-theme' };
  }
  return { theme: 'light', source: 'default-light' };
}
