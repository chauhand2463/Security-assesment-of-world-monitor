import React from 'react';
import { EmptyState } from './EmptyState';
import { SkeletonTable } from './Skeleton';

interface Column<T> {
  key: string;
  label: string;
  render: (row: T) => React.ReactNode;
  className?: string;
  headerClassName?: string;
}

interface DataTableProps<T> {
  columns: Column<T>[];
  rows: T[] | null;
  keyField: (row: T) => string;
  empty?: { title: string; description?: string; action?: React.ReactNode };
  loading?: boolean;
  error?: string;
  onRowClick?: (row: T) => void;
  onRetry?: () => void;
  /** When false the outer border/radius shell is omitted so the table can sit inside a Card. */
  bordered?: boolean;
}

export const DataTable = <T,>({
  columns,
  rows,
  keyField,
  empty,
  loading,
  error,
  onRowClick,
  onRetry,
  bordered = true,
}: DataTableProps<T>): React.ReactElement => {
  if (error) {
    return (
      <div className="rounded-2xl border border-critical/25 bg-critical/[0.05] py-8 text-center text-[12px] text-critical">
        {error}
      </div>
    );
  }

  if (loading || rows === null) {
    return <SkeletonTable rows={4} cols={columns.length} />;
  }

  if (rows.length === 0) {
    return empty ? (
      <EmptyState title={empty.title} description={empty.description} action={empty.action} />
    ) : (
      <div className="py-10 text-center text-[12.5px] text-muted">No records.</div>
    );
  }

  return (
    <div className={`${bordered ? 'overflow-hidden rounded-2xl border border-line' : ''}`}>
      <div className="overflow-x-auto">
        <table className="tbl w-full border-collapse">
          <thead>
            <tr>
              {columns.map((c) => (
                <th key={c.key} className={c.headerClassName}>
                  {c.label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr
                key={keyField(row)}
                onClick={onRowClick ? () => onRowClick(row) : undefined}
                className={onRowClick ? 'cursor-pointer' : ''}
              >
                {columns.map((c) => (
                  <td key={c.key} className={c.className}>
                    {c.render(row)}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
