import type { ReactNode } from 'react';

export function PageHeader({
  title,
  titleId,
  description,
  actions,
  eyebrow,
}: {
  title: string;
  titleId?: string;
  description?: ReactNode;
  actions?: ReactNode;
  eyebrow?: ReactNode;
}) {
  return (
    <header className="page-header">
      <div className="page-header__text">
        {eyebrow !== undefined ? <p className="page-header__eyebrow">{eyebrow}</p> : null}
        <h1 id={titleId} className="page-header__title">{title}</h1>
        {description !== undefined ? <div className="page-header__description">{description}</div> : null}
      </div>
      {actions !== undefined ? <div className="page-header__actions">{actions}</div> : null}
    </header>
  );
}

export function Panel({
  title,
  children,
  actions,
  id,
  className,
}: {
  title?: string;
  children: ReactNode;
  actions?: ReactNode;
  id?: string;
  className?: string;
}) {
  const headingId = id !== undefined ? `${id}-heading` : undefined;
  return (
    <section className={`panel ${className ?? ''}`} id={id} aria-labelledby={title !== undefined ? headingId : undefined}>
      {title !== undefined || actions !== undefined ? (
        <div className="panel__header">
          {title !== undefined ? (
            <h2 className="panel__title" id={headingId}>
              {title}
            </h2>
          ) : null}
          {actions !== undefined ? <div className="panel__actions">{actions}</div> : null}
        </div>
      ) : null}
      <div className="panel__body">{children}</div>
    </section>
  );
}
