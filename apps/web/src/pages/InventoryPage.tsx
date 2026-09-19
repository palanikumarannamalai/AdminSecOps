import type { Technology } from '@adminsecops/core';
import { TECHNOLOGIES, TECHNOLOGY_LABELS } from '@adminsecops/core/vocabulary';
import type { InventoryItem } from '@adminsecops/schemas';
import { useAssessment } from '../app/AssessmentLayout';
import { PageHeader, Panel } from '../components/PageHeader';
import { EmptyState } from '../components/States';

export function groupInventory(items: readonly InventoryItem[]): [Technology, InventoryItem[]][] {
  return TECHNOLOGIES.map((t): [Technology, InventoryItem[]] => [t, items.filter((i) => i.technology === t)]).filter(
    ([, group]) => group.length > 0,
  );
}

export function InventoryPage() {
  const result = useAssessment();
  const groups = groupInventory(result.inventory);

  return (
    <div className="page">
      <PageHeader
        eyebrow="Inventory"
        title="Environment inventory"
        description={
          <p>
            Object counts derived from the collected evidence. "Not collected" means the dataset was not available, not
            that the count is zero.
          </p>
        }
      />
      {groups.length === 0 ? (
        <EmptyState title="No inventory">
          <p>The evidence package did not contain datasets that produce inventory counts.</p>
        </EmptyState>
      ) : (
        <div className="grid grid--3">
          {groups.map(([technology, items]) => (
            <Panel key={technology} title={TECHNOLOGY_LABELS[technology]} id={`inv-${technology}`}>
              <dl className="inventory">
                {items.map((item) => (
                  <div key={item.key} className="inventory__row">
                    <dt>{item.label}</dt>
                    <dd className={item.count === null ? 'muted' : 'num'}>
                      {item.count === null ? 'Not collected' : item.count.toLocaleString()}
                    </dd>
                  </div>
                ))}
              </dl>
            </Panel>
          ))}
        </div>
      )}
    </div>
  );
}
