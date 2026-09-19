/**
 * Build mode.
 * - 'local': the dashboard served by the local AdminSecOps API (apps/api) on 127.0.0.1.
 * - 'hosted': a static, browser-only build published at /tools/adminsecops/app/ on
 *   www.palanikumar.net. There is no server API: parsing, validation, control evaluation,
 *   prioritisation and report generation run in the visitor's browser.
 */
export type AppMode = 'local' | 'hosted';

export const APP_MODE: AppMode = import.meta.env.VITE_ADMINSECOPS_MODE === 'hosted' ? 'hosted' : 'local';
export const IS_HOSTED = APP_MODE === 'hosted';

/** Public AdminSecOps overview page (hosted mode "Return to AdminSecOps overview"). */
export const OVERVIEW_URL = '/tools/adminsecops';
