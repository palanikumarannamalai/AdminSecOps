/** Version of the AdminSecOps assessment engine and data contracts. */
export const ENGINE_VERSION = '0.3.0';

/** Evidence package format understood by this build (see docs/EVIDENCE-MODEL.md). */
export const SUPPORTED_MANIFEST_VERSIONS = ['1.0'] as const;
export const SUPPORTED_EVIDENCE_SCHEMA_VERSIONS = ['1.0'] as const;

/** Version of the assessment result / report format produced by this build. */
export const RESULT_SCHEMA_VERSION = '1.0';

export const PRODUCT_NAME = 'ConfigReview';
export const PRODUCT_TAGLINE = "Evidence-based security configuration review for Microsoft environments.";
export const PRODUCT_DESCRIPTION =
  'Security assessment and remediation guidance for Microsoft administrators.';
