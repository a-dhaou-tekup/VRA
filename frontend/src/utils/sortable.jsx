/**
 * Reusable sort utility for tables.
 *
 * Usage:
 *   const { sorted, col, dir, toggle } = useSortable(rows, 'hostname')
 *
 *   <SortTh col="hostname" sortCol={col} sortDir={dir} onSort={toggle}>Hostname</SortTh>
 */
import { useState, useMemo } from 'react'

export function useSortable(data, defaultCol = null, defaultDir = 'asc') {
  const [col, setCol] = useState(defaultCol)
  const [dir, setDir] = useState(defaultDir)

  const sorted = useMemo(() => {
    if (!col || !data?.length) return data ?? []
    return [...data].sort((a, b) => {
      const av = a[col] ?? ''
      const bv = b[col] ?? ''
      const cmp = String(av).localeCompare(String(bv), undefined, {
        numeric: true, sensitivity: 'base',
      })
      return dir === 'asc' ? cmp : -cmp
    })
  }, [data, col, dir])

  const toggle = (key) => {
    if (col === key) {
      setDir(d => (d === 'asc' ? 'desc' : 'asc'))
    } else {
      setCol(key)
      setDir('asc')
    }
  }

  return { sorted, col, dir, toggle }
}

export function SortTh({ col, sortCol, sortDir, onSort, children, style = {}, className = '' }) {
  const active = sortCol === col
  return (
    <th
      onClick={() => onSort(col)}
      className={className}
      style={{
        cursor: 'pointer',
        userSelect: 'none',
        whiteSpace: 'nowrap',
        ...style,
      }}
    >
      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
        {children}
        <span style={{
          fontSize: 10,
          opacity: active ? 1 : 0.2,
          color: active ? 'var(--amber)' : 'inherit',
          transition: 'opacity 0.15s',
        }}>
          {active ? (sortDir === 'asc' ? '↑' : '↓') : '↕'}
        </span>
      </span>
    </th>
  )
}
