import type { ControlDefinition } from '@adminsecops/controls';
import { evaluateControl } from '@adminsecops/engine';
import { createInventoryFromData, type FromDataOptions } from '@adminsecops/inventory';
import type { ControlResult, DatasetId } from '@adminsecops/schemas';

/**
 * Evaluate a control against collector-shaped test data using the real engine
 * semantics (schema validation, NOT_ASSESSED on missing evidence, partial handling).
 */
export function run(
  control: ControlDefinition,
  data: Partial<Record<DatasetId, unknown>>,
  options: FromDataOptions = {},
): ControlResult {
  return evaluateControl(control, createInventoryFromData(data, options));
}
