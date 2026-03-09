export const markdownComponents = {
  p: ({ children }: any) => <p className="mb-2 last:mb-0">{children}</p>,
  ul: ({ children }: any) => <ul className="my-2 list-disc pl-5 space-y-1">{children}</ul>,
  ol: ({ children }: any) => <ol className="my-2 list-decimal pl-5 space-y-1">{children}</ol>,
  li: ({ children }: any) => <li>{children}</li>,
  a: ({ href, children }: any) => (
    <a
      href={href}
      target="_blank"
      rel="noreferrer noopener"
      className="text-primary underline underline-offset-2 break-all"
    >
      {children}
    </a>
  ),
  code: ({ inline, className, children, ...props }: any) => {
    if (inline) {
      return (
        <code className="px-1 py-0.5 rounded bg-muted text-foreground text-[0.9em] font-mono" {...props}>
          {children}
        </code>
      )
    }
    return (
      <pre className="my-2 rounded-lg border border-border bg-muted/60 p-3 overflow-x-auto">
        <code className={`${className || ''} font-mono text-ui-sm`} {...props}>
          {children}
        </code>
      </pre>
    )
  },
  blockquote: ({ children }: any) => (
    <blockquote className="my-2 border-l-2 border-primary/30 pl-3 text-muted-foreground italic">{children}</blockquote>
  ),
  table: ({ children }: any) => (
    <div className="my-2 overflow-x-auto rounded-lg border border-border">
      <table className="w-full text-sm border-collapse">{children}</table>
    </div>
  ),
  th: ({ children }: any) => (
    <th className="px-3 py-2 text-left text-ui-xs font-semibold uppercase tracking-wide text-muted-foreground bg-muted/40 border-b border-border">{children}</th>
  ),
  td: ({ children }: any) => (
    <td className="px-3 py-2 border-b border-border/50">{children}</td>
  ),
}
