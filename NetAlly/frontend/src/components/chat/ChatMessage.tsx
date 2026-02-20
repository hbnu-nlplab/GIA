import { Bot, Link2, Loader2, User } from 'lucide-react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import type { VizPayload } from '../../store'
import type { Message, MessageCitation } from './types'
import { buildContextLabel, citationStatusClass } from './types'
import { markdownComponents } from './markdown'

interface ChatMessageProps {
  message: Message
  isActiveViz: boolean
  onVizClick: (viz: VizPayload, messageId: string) => void
  onCitationClick: (evidenceId: string) => void
}

export default function ChatMessage({ message: msg, isActiveViz, onVizClick, onCitationClick }: ChatMessageProps) {
  if (msg.role === 'system') {
    return (
      <div className="flex items-center gap-3 py-1">
        <div className="h-px flex-1 bg-border/40" />
        <span className="text-ui-xs text-muted-foreground/70 shrink-0">{msg.content}</span>
        <div className="h-px flex-1 bg-border/40" />
      </div>
    )
  }

  const isUser = msg.role === 'user'
  const assistantHasViz = !isUser && Boolean(msg.viz)

  return (
    <div className="group">
      {/* Role indicator */}
      <div className="flex items-center gap-2 mb-1.5 px-1">
        {isUser ? (
          <User className="w-3.5 h-3.5 text-muted-foreground" />
        ) : (
          <Bot className="w-3.5 h-3.5 text-primary" />
        )}
        <span className="text-ui-xs font-semibold text-muted-foreground">
          {isUser ? 'You' : 'NetAlly'}
        </span>
        {msg.contextDevice && (
          <span className="text-ui-xs text-primary/70">
            &rarr; {buildContextLabel(msg.contextDevice)}
          </span>
        )}
      </div>

      {/* Message content */}
      {isUser ? (
        <div className="rounded-xl bg-muted/40 px-4 py-3">
          <div className="text-sm leading-relaxed">{msg.content}</div>
          {msg.attachments && msg.attachments.length > 0 && (
            <div className="mt-2 flex flex-wrap gap-2">
              {msg.attachments.map((a) =>
                a.dataUrl ? (
                  <img
                    key={a.id}
                    src={a.dataUrl}
                    alt={a.name}
                    className="rounded-lg border border-border w-20 h-20 object-cover"
                  />
                ) : (
                  <div
                    key={a.id}
                    className="rounded-lg border border-border w-20 h-20 bg-muted flex items-center justify-center text-ui-xs text-muted-foreground p-1.5 text-center"
                  >
                    {a.name}
                  </div>
                )
              )}
            </div>
          )}
        </div>
      ) : (
        <div
          className={`rounded-xl px-4 py-3 transition-all ${
            isActiveViz ? 'bg-primary/5 border border-primary/20' : ''
          } ${assistantHasViz ? 'cursor-pointer hover:bg-muted/20' : ''}`}
          onClick={() => {
            if (msg.viz) onVizClick(msg.viz, msg.id)
          }}
        >
          {msg.content ? (
            <div className="text-sm leading-relaxed text-foreground">
              <ReactMarkdown remarkPlugins={[remarkGfm]} components={markdownComponents}>
                {msg.content}
              </ReactMarkdown>
            </div>
          ) : msg.type === 'streaming' ? (
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="w-4 h-4 animate-spin text-primary" />
              Generating...
            </div>
          ) : (
            <div className="text-sm text-muted-foreground">No answer content</div>
          )}

          {/* Citations & Grounding */}
          {(msg.grounding || (msg.citations && msg.citations.length > 0)) && (
            <div className="mt-3 pt-3 border-t border-border/40 space-y-2">
              {msg.grounding && (
                <div
                  className={`text-ui-xs px-2.5 py-1.5 rounded-lg border inline-flex items-center gap-1.5 ${
                    msg.grounding.supportedByTools
                      ? 'border-emerald-500/30 bg-emerald-500/8 text-emerald-500'
                      : 'border-amber-500/30 bg-amber-500/8 text-amber-500'
                  }`}
                >
                  {msg.grounding.supportedByTools
                    ? `Verified by ${msg.grounding.citationCount} tool(s)`
                    : msg.grounding.note || 'No tool evidence'}
                </div>
              )}
              {msg.citations && msg.citations.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {msg.citations.map((citation: MessageCitation) => (
                    <button
                      key={citation.id}
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation()
                        if (citation.evidenceId) onCitationClick(citation.evidenceId)
                      }}
                      disabled={!citation.evidenceId}
                      className={`text-ui-xs px-2 py-1 rounded border transition-colors ${citationStatusClass(citation.status)} ${
                        citation.evidenceId ? 'hover:brightness-110 cursor-pointer' : 'cursor-default opacity-80'
                      }`}
                      title={citation.summary}
                    >
                      {citation.tool}
                      {citation.callId != null ? `#${citation.callId}` : ''}
                    </button>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Viz link */}
          {assistantHasViz && (
            <div className="mt-2 flex items-center gap-1.5 text-ui-xs text-primary/70">
              <Link2 className="w-3 h-3" />
              {isActiveViz ? 'Viewing topology overlay' : 'Click to view topology overlay'}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
