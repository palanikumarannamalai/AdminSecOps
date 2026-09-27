/**
 * Build mode.
 * - 'local': the dashboard served by the local ConfigReview API (apps/api) on 127.0.0.1.
 * - 'hosted': a static, browser-only build published at /tools/configreview/app/ on
 *   www.palanikumar.net. There is no server API: parsing, validation, control evaluation,
 *   prioritisation and report generation run in the visitor's browser.
 */
export type AppMode = 'local' | 'hosted' | 'online';

export const APP_MODE: AppMode = import.meta.env.VITE_ADMINSECOPS_MODE === 'online' ? 'online' : import.meta.env.VITE_ADMINSECOPS_MODE === 'hosted' ? 'hosted' : 'local';
export const IS_HOSTED = APP_MODE === 'hosted';
export const IS_ONLINE = APP_MODE === 'online';

/** Public ConfigReview overview page (hosted mode "Return to ConfigReview overview"). */
export const OVERVIEW_URL = '/tools/configreview';
