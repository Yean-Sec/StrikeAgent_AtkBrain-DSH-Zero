/**
 * Settings health for the proxy and survey providers.
 *
 * Skills, dictionaries and external pentest tools are not part of this build.
 */
import { publicSettings, surveyStatus } from './settings.js';

/**
 * @param {{checkTools?:boolean, settings?:object}} options
 */
export async function checkResourceHealth({ settings } = {}) {
  const survey = surveyStatus(settings ?? {});
  return {
    checkedAt: new Date().toISOString(),
    resources: {},
    survey,
  };
}

export { publicSettings };
