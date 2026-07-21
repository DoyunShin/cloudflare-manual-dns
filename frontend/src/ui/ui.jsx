import { createContext, useCallback, useContext, useEffect, useState } from 'react'
import { createPortal } from 'react-dom'

/**
 * Primary action button. Variants: default | accent | danger | ghost.
 *
 * Args:
 *     variant(string, optional): visual style, defaults to "default"
 *     children(ReactNode): button label
 */
export function Button({ variant = 'default', className = '', children, ...rest }) {
  const variantClass =
    variant === 'accent' ? 'btn-accent' : variant === 'danger' ? 'btn-danger' : variant === 'ghost' ? 'btn-ghost' : ''
  return (
    <button className={`btn ${variantClass} ${className}`.trim()} {...rest}>
      {children}
    </button>
  )
}

/**
 * Bordered, labeled instrument panel used as the base container for
 * every section of the console.
 *
 * Args:
 *     title(string, optional): panel header label
 *     actions(ReactNode, optional): controls rendered top-right of the header
 *     children(ReactNode): panel body
 */
export function Panel({ title, actions, children, className = '', style }) {
  return (
    <section className={`panel ${className}`.trim()} style={style}>
      {(title || actions) && (
        <header className="panel-head">
          {title && <h3 className="label">{title}</h3>}
          {actions && <div className="panel-actions">{actions}</div>}
        </header>
      )}
      <div className="panel-body">{children}</div>
    </section>
  )
}

/**
 * Label + control wrapper used across all forms.
 *
 * Args:
 *     label(string): field label text
 *     hint(string, optional): helper text below the control
 *     children(ReactNode): the control itself
 */
export function Field({ label, hint, children, className = '' }) {
  return (
    <div className={`field ${className}`.trim()}>
      {label && <label className="field-label label">{label}</label>}
      {children}
      {hint && <p className="field-hint">{hint}</p>}
    </div>
  )
}

export function Input({ className = '', ...rest }) {
  return <input className={`input ${className}`.trim()} {...rest} />
}

export function Select({ className = '', children, ...rest }) {
  return (
    <select className={`select ${className}`.trim()} {...rest}>
      {children}
    </select>
  )
}

export function TextArea({ className = '', ...rest }) {
  return <textarea className={`textarea ${className}`.trim()} {...rest} />
}

/**
 * Binary switch used for allow_read / allow_create / allow_write /
 * allow_delete style flags.
 *
 * Args:
 *     checked(bool): current state
 *     onChange(function): called with the new boolean state
 *     label(string, optional): inline label rendered next to the switch
 */
export function Toggle({ checked, onChange, label, disabled = false }) {
  return (
    <label className={`toggle ${disabled ? 'toggle-disabled' : ''}`}>
      <input
        type="checkbox"
        checked={checked}
        disabled={disabled}
        onChange={(e) => onChange && onChange(e.target.checked)}
      />
      <span className="toggle-track">
        <span className="toggle-thumb" />
      </span>
      {label && <span className="toggle-label">{label}</span>}
    </label>
  )
}

/**
 * State badge. Variants: ok | bad | muted | accent.
 *
 * Args:
 *     variant(string, optional): visual state, defaults to "muted"
 *     children(ReactNode): badge text
 */
export function Badge({ variant = 'muted', children }) {
  return <span className={`badge badge-${variant}`}>{children}</span>
}

/**
 * Minimal data table. Pass columns and rows explicitly for full control,
 * or just children for a custom <thead>/<tbody>.
 *
 * Args:
 *     columns(array, optional): [{key, header, render?}]
 *     rows(array, optional): row data objects, one per <tr>
 *     rowKey(function, optional): (row, index) => key
 *     empty(ReactNode, optional): rendered when rows is empty
 */
export function Table({ columns, rows, rowKey, empty, children, className = '' }) {
  if (children) {
    return (
      <div className="table-wrap">
        <table className={`table ${className}`.trim()}>{children}</table>
      </div>
    )
  }

  if (!rows || rows.length === 0) {
    return empty || <EmptyState message="No records" />
  }

  return (
    <div className="table-wrap">
      <table className={`table ${className}`.trim()}>
        <thead>
          <tr>
            {columns.map((col) => (
              <th key={col.key}>{col.header}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={rowKey ? rowKey(row, i) : i}>
              {columns.map((col) => (
                <td key={col.key}>{col.render ? col.render(row) : row[col.key]}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

/**
 * Overlay modal rendered via portal, dismissible via backdrop click or
 * the close control.
 *
 * Args:
 *     open(bool): whether the modal is visible
 *     onClose(function): called to dismiss the modal
 *     title(string, optional): modal header label
 *     children(ReactNode): modal body
 */
export function Modal({ open, onClose, title, children, actions }) {
  useEffect(() => {
    if (!open) return
    const onKey = (e) => {
      if (e.key === 'Escape') onClose && onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open, onClose])

  if (!open) return null

  return createPortal(
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose && onClose()}>
      <div className="modal-panel panel" role="dialog" aria-modal="true">
        <header className="panel-head">
          {title && <h3 className="label">{title}</h3>}
          <button className="modal-close" aria-label="Close" onClick={onClose}>
            &times;
          </button>
        </header>
        <div className="panel-body">{children}</div>
        {actions && <footer className="modal-actions">{actions}</footer>}
      </div>
    </div>,
    document.body,
  )
}

/**
 * Small button that copies the given text to the clipboard and shows a
 * transient "copied" acknowledgement.
 *
 * Args:
 *     text(string): value to copy
 *     label(string, optional): button label, defaults to "Copy"
 */
export function CopyButton({ text, label = 'Copy' }) {
  const [copied, setCopied] = useState(false)

  const handleCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(text ?? '')
      setCopied(true)
      setTimeout(() => setCopied(false), 1400)
    } catch {
      setCopied(false)
    }
  }, [text])

  return (
    <button type="button" className="copy-btn" onClick={handleCopy}>
      {copied ? 'Copied' : label}
    </button>
  )
}

/**
 * Monospace block for tokens, ids, and other raw technical values.
 *
 * Args:
 *     children(ReactNode): content to render in monospace
 */
export function Code({ children, className = '' }) {
  return <pre className={`code ${className}`.trim()}>{children}</pre>
}

/**
 * Page-level header with title, optional subtitle, and right-aligned
 * actions.
 *
 * Args:
 *     title(string): page title
 *     subtitle(string, optional): supporting description
 *     actions(ReactNode, optional): buttons rendered top-right
 */
export function PageHeader({ title, subtitle, actions }) {
  return (
    <div className="page-header">
      <div>
        <h1 className="page-title">{title}</h1>
        {subtitle && <p className="page-subtitle">{subtitle}</p>}
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </div>
  )
}

/**
 * Placeholder shown when a list or table has no data.
 *
 * Args:
 *     message(string, optional): text to display
 */
export function EmptyState({ message = 'Nothing here yet.', action }) {
  return (
    <div className="empty-state">
      <p>{message}</p>
      {action}
    </div>
  )
}

/**
 * Small inline loading indicator.
 */
export function Spinner({ label }) {
  return (
    <span className="spinner-wrap">
      <span className="spinner" aria-hidden="true" />
      {label && <span className="spinner-label">{label}</span>}
    </span>
  )
}

const ToastContext = createContext(null)

let toastId = 0

/**
 * Provide toast.success/toast.error notifications to the tree via
 * useToast().
 *
 * Args:
 *     children(ReactNode): wrapped application tree
 */
export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([])

  const remove = useCallback((id) => {
    setToasts((prev) => prev.filter((t) => t.id !== id))
  }, [])

  const push = useCallback(
    (variant, message) => {
      const id = ++toastId
      setToasts((prev) => [...prev, { id, variant, message }])
      setTimeout(() => remove(id), 4000)
    },
    [remove],
  )

  const toast = {
    success: (message) => push('ok', message),
    error: (message) => push('bad', message),
  }

  return (
    <ToastContext.Provider value={toast}>
      {children}
      {createPortal(
        <div className="toast-stack">
          {toasts.map((t) => (
            <div key={t.id} className={`toast toast-${t.variant}`} onClick={() => remove(t.id)}>
              {t.message}
            </div>
          ))}
        </div>,
        document.body,
      )}
    </ToastContext.Provider>
  )
}

/**
 * Access the toast API.
 *
 * Return:
 *     toast(object): {success(message), error(message)}
 */
export function useToast() {
  const ctx = useContext(ToastContext)
  if (!ctx) {
    throw new Error('useToast must be used within a ToastProvider')
  }
  return ctx
}
