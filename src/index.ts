export { createScanner, applyRedaction, dedupeFindings, masks } from './scanner';
export type { Scanner, ScannerOptions, RedactOptions, RedactResult, Masker } from './scanner';

export { secrets, isPlaceholder } from './detectors/secrets';
export type { SecretRule, SecretsOptions, SecretMatchContext, ValidateResult } from './detectors/secrets';
export { BUILTIN_SECRET_RULES } from './rules/secrets';

export { pii, isValidCnIdCard, isValidUscc, luhn } from './detectors/pii';
export type { PiiOptions, PiiType } from './detectors/pii';

export { keywords } from './detectors/keywords';
export type { KeywordsOptions, KeywordList } from './detectors/keywords';

export { regexDetector } from './detectors/regex';
export type { RegexRule } from './detectors/regex';

export { normalize, DEFAULT_IGNORE } from './normalize';
export type { NormalizeOptions, NormalizedText } from './normalize';

export { AhoCorasick } from './aho-corasick';
export type { AcMatch } from './aho-corasick';

export { shannonEntropy, maskPreview } from './utils';

export { SEVERITY_RANK } from './types';
export type {
  Finding,
  RawFinding,
  Severity,
  Category,
  Detector,
  SyncDetector,
  AsyncDetector,
  DetectContext,
} from './types';
