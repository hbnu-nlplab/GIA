import { ChangeEvent, FormEvent, KeyboardEvent, useEffect, useRef } from 'react'
import { ArrowUp, Bot, ImagePlus, RotateCcw, Square, X } from 'lucide-react'
import type { TopologyDeviceSummary, ChatContextDevice } from '../../store'
import type { AttachmentDraft, SlashTokenMatch } from './types'
import { buildContextLabel } from './types'

interface ChatInputProps {
  input: string
  setInput: (value: string) => void
  isStreaming: boolean
  attachments: AttachmentDraft[]
  setAttachments: React.Dispatch<React.SetStateAction<AttachmentDraft[]>>
  chatContextDevice: ChatContextDevice | null
  clearChatContextDevice: () => void
  slashToken: SlashTokenMatch | null
  slashCandidates: TopologyDeviceSummary[]
  slashFocusIndex: number
  slashListId: string
  selectedNode: string | null
  runtimeDegraded: boolean
  runtimeNote: string
  hasRetry: boolean
  onSubmit: (e: FormEvent) => void
  onCancel: () => void
  onRetry: () => void
  onPickImages: (event: ChangeEvent<HTMLInputElement>) => void
  onChooseSlashDevice: (device: TopologyDeviceSummary) => void
  onKeyDown: (e: KeyboardEvent<HTMLTextAreaElement>) => void
}

export default function ChatInput({
  input,
  setInput,
  isStreaming,
  attachments,
  setAttachments,
  chatContextDevice,
  clearChatContextDevice,
  slashToken,
  slashCandidates,
  slashFocusIndex,
  slashListId,
  selectedNode,
  runtimeDegraded,
  runtimeNote,
  hasRetry,
  onSubmit,
  onCancel,
  onRetry,
  onPickImages,
  onChooseSlashDevice,
  onKeyDown,
}: ChatInputProps) {
  const fileInputRef = useRef<HTMLInputElement>(null)
  const textareaRef = useRef<HTMLTextAreaElement>(null)
  const slashQuery = slashToken ? slashToken.query : null

  // Auto-resize textarea
  useEffect(() => {
    const el = textareaRef.current
    if (!el) return
    el.style.height = 'auto'
    el.style.height = `${Math.min(el.scrollHeight, 200)}px`
  }, [input])

  const canSend = input.trim().length > 0 || attachments.length > 0

  return (
    <div className="p-3 bg-card border-t border-border">
      {/* Context device chip */}
      {chatContextDevice && (
        <div className="mb-2 flex items-center gap-2">
          <span className="text-ui-xs px-2.5 py-1 rounded-lg border border-primary/30 bg-primary/8 text-primary inline-flex items-center gap-1.5">
            <Bot className="w-3 h-3" />
            {buildContextLabel(chatContextDevice)}
            <button
              type="button"
              onClick={clearChatContextDevice}
              className="hover:text-primary/60 ml-0.5"
            >
              <X className="w-3 h-3" />
            </button>
          </span>
        </div>
      )}

      {/* Degraded mode warning */}
      {runtimeDegraded && (
        <div className="mb-2 text-ui-xs px-2.5 py-1.5 rounded-lg border border-amber-500/30 bg-amber-500/8 text-amber-500">
          Degraded: {runtimeNote || 'Some backends limited'}
        </div>
      )}

      {/* Attachments preview */}
      {attachments.length > 0 && (
        <div className="mb-2 flex flex-wrap gap-2">
          {attachments.map((a) => (
            <div
              key={a.id}
              className="relative w-16 h-16 rounded-lg overflow-hidden border border-border"
            >
              <img src={a.dataUrl} alt={a.name} className="w-full h-full object-cover" />
              <button
                type="button"
                onClick={() => setAttachments((prev) => prev.filter((item) => item.id !== a.id))}
                className="absolute top-0.5 right-0.5 w-4 h-4 rounded-full bg-black/70 text-white flex items-center justify-center hover:bg-black/90"
              >
                <X className="w-2.5 h-2.5" />
              </button>
            </div>
          ))}
        </div>
      )}

      <form onSubmit={onSubmit}>
        <div className="relative flex items-end gap-2 rounded-xl border border-border bg-background px-3 py-2 focus-within:border-primary/40 focus-within:ring-2 focus-within:ring-primary/15 transition-all">
          {/* Image upload */}
          <input
            ref={fileInputRef}
            type="file"
            accept="image/*"
            multiple
            className="hidden"
            onChange={onPickImages}
          />
          <button
            type="button"
            onClick={() => fileInputRef.current?.click()}
            disabled={isStreaming}
            className="shrink-0 w-8 h-8 flex items-center justify-center rounded-lg text-muted-foreground hover:text-foreground hover:bg-muted transition-colors disabled:opacity-40"
            title="Attach image"
          >
            <ImagePlus className="w-4 h-4" />
          </button>

          {/* Textarea */}
          <textarea
            ref={textareaRef}
            rows={1}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={onKeyDown}
            aria-label="Message input"
            aria-autocomplete={slashQuery !== null ? 'list' : 'none'}
            aria-controls={slashQuery !== null ? slashListId : undefined}
            aria-expanded={slashQuery !== null}
            aria-activedescendant={
              slashQuery !== null && slashCandidates.length > 0
                ? `${slashListId}-opt-${slashFocusIndex}`
                : undefined
            }
            placeholder={
              chatContextDevice
                ? `Ask about ${buildContextLabel(chatContextDevice)}...`
                : 'Message NetAlly... (/ to select device)'
            }
            className="flex-1 bg-transparent text-sm text-foreground placeholder:text-muted-foreground/60 resize-none focus:outline-none py-1.5 max-h-[200px]"
          />

          {/* Send / Cancel / Retry */}
          <div className="shrink-0 flex items-center gap-1">
            {hasRetry && !isStreaming && (
              <button
                type="button"
                onClick={onRetry}
                className="w-8 h-8 flex items-center justify-center rounded-lg text-amber-500 hover:bg-amber-500/10 transition-colors"
                title="Retry last request"
              >
                <RotateCcw className="w-4 h-4" />
              </button>
            )}
            <button
              type={isStreaming ? 'button' : 'submit'}
              onClick={isStreaming ? onCancel : undefined}
              disabled={!isStreaming && !canSend}
              className={`w-8 h-8 flex items-center justify-center rounded-lg transition-all ${
                isStreaming
                  ? 'bg-foreground text-background hover:opacity-80'
                  : canSend
                    ? 'bg-primary text-primary-foreground hover:brightness-110'
                    : 'bg-muted text-muted-foreground/40 cursor-not-allowed'
              }`}
              title={isStreaming ? 'Stop generating' : 'Send message'}
            >
              {isStreaming ? <Square className="w-3.5 h-3.5" /> : <ArrowUp className="w-4 h-4" />}
            </button>
          </div>
        </div>

        {/* Hint text */}
        <div className="mt-1.5 px-1 flex items-center justify-between text-ui-xs text-muted-foreground/50">
          <span>Enter to send, Shift+Enter for new line</span>
          {selectedNode && <span>Selected: {selectedNode}</span>}
        </div>

        {/* Slash command autocomplete */}
        {slashQuery !== null && (
          <div
            id={slashListId}
            role="listbox"
            className="absolute left-3 right-3 bottom-full mb-2 max-h-56 overflow-y-auto rounded-xl border border-border bg-card shadow-elevation-3 z-20"
          >
            {slashCandidates.length > 0 ? (
              slashCandidates.map((device, idx) => (
                <button
                  id={`${slashListId}-opt-${idx}`}
                  key={device.id}
                  type="button"
                  role="option"
                  aria-selected={idx === slashFocusIndex}
                  onClick={() => onChooseSlashDevice(device)}
                  className={`w-full text-left px-3 py-2 border-b last:border-b-0 border-border/40 text-sm transition-colors ${
                    idx === slashFocusIndex
                      ? 'bg-primary/10 text-foreground'
                      : 'hover:bg-muted/40 text-foreground'
                  }`}
                >
                  <span className="font-medium">{device.label || device.id}</span>
                  <span className="ml-2 text-ui-xs text-muted-foreground">
                    {device.platform || device.id}
                  </span>
                </button>
              ))
            ) : (
              <div className="px-3 py-3 text-sm text-muted-foreground">No matching devices</div>
            )}
          </div>
        )}
      </form>
    </div>
  )
}
