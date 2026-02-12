/**
 * ChatPanel - modern conversational UI with explainable overlays and answer-linked snapshots.
 */
import { ChangeEvent, FormEvent, KeyboardEvent, useEffect, useMemo, useRef, useState } from 'react'
import { Bot, ImagePlus, Link2, Loader2, Sparkles, User, X } from 'lucide-react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import {
  useAppStore,
  VizPayload,
  TopologyDeviceSummary,
  ChatContextDevice,
} from '../store'

interface MessageAttachment {
  id: string
  name: string
  mimeType: string
  dataUrl: string
}

interface AttachmentDraft extends MessageAttachment {
  size: number
}

interface Message {
  id: string
  role: 'user' | 'assistant' | 'system'
  content: string
  type?: string
  viz?: VizPayload | null
  attachments?: MessageAttachment[]
  contextDevice?: ChatContextDevice | null
}

interface ChatPanelProps {
  selectedNode: string | null
}

const MAX_ATTACHMENTS = 4
const MAX_IMAGE_SIZE_BYTES = 5 * 1024 * 1024
const ANSWER_REVEAL_MIN_STEP = 8
const ANSWER_REVEAL_MAX_STEP = 36
const ANSWER_REVEAL_INTERVAL_MS = 14

interface SlashTokenMatch {
  query: string
  start: number
  end: number
}

const toVizPayload = (
  rawViz: any,
  callId: number | null,
  query: string
): VizPayload | null => {
  if (!rawViz || typeof rawViz !== 'object') return null

  const nodes = Array.isArray(rawViz.nodes)
    ? rawViz.nodes.map((n: any) => String(n))
    : []
  const edges = Array.isArray(rawViz.edges)
    ? rawViz.edges
        .map((e: any) => ({
          source: String(e?.source ?? '').trim(),
          target: String(e?.target ?? '').trim(),
        }))
        .filter((e: any) => e.source && e.target)
    : []

  if (nodes.length === 0 && edges.length === 0) return null

  return {
    nodes,
    edges,
    mode: rawViz.mode === 'path' ? 'path' : 'focus',
    title: typeof rawViz.title === 'string' ? rawViz.title : undefined,
    callId: typeof callId === 'number' ? callId : undefined,
    query: query || undefined,
  }
}

const readFileAsDataUrl = (file: File): Promise<string> => {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => resolve(String(reader.result || ''))
    reader.onerror = reject
    reader.readAsDataURL(file)
  })
}

const buildContextLabel = (context: ChatContextDevice | null): string => {
  if (!context) return ''
  return context.label || context.id
}

const markdownComponents = {
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
        <code className="px-1 py-0.5 rounded bg-muted text-foreground text-[0.9em]" {...props}>
          {children}
        </code>
      )
    }
    return (
      <pre className="my-2 rounded-lg border border-border bg-muted/60 p-3 overflow-x-auto">
        <code className={className} {...props}>
          {children}
        </code>
      </pre>
    )
  },
  blockquote: ({ children }: any) => (
    <blockquote className="my-2 border-l-2 border-border pl-3 text-muted-foreground">{children}</blockquote>
  ),
}

export default function ChatPanel({ selectedNode }: ChatPanelProps) {
  const [messages, setMessages] = useState<Message[]>([])
  const [input, setInput] = useState('')
  const [isStreaming, setIsStreaming] = useState(false)
  const [activeVizMessageId, setActiveVizMessageId] = useState<string | null>(null)
  const [attachments, setAttachments] = useState<AttachmentDraft[]>([])
  const [slashFocusIndex, setSlashFocusIndex] = useState(0)

  const messagesEndRef = useRef<HTMLDivElement>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)
  const messageSeqRef = useRef(0)
  const latestVizRef = useRef<VizPayload | null>(null)
  const currentQuestionRef = useRef('')
  const assistantDraftIdRef = useRef<string | null>(null)
  const answerRevealTimerRef = useRef<number | null>(null)
  const slashListIdRef = useRef(`chat-slash-list-${Math.random().toString(36).slice(2, 8)}`)

  const addEvidence = useAppStore((state) => state.addEvidence)
  const setViz = useAppStore((state) => state.setViz)
  const clearViz = useAppStore((state) => state.clearViz)
  const topologyDevices = useAppStore((state) => state.topologyDevices)
  const chatContextDevice = useAppStore((state) => state.chatContextDevice)
  const setChatContextDevice = useAppStore((state) => state.setChatContextDevice)
  const clearChatContextDevice = useAppStore((state) => state.clearChatContextDevice)

  const nextMessageId = () => {
    messageSeqRef.current += 1
    return `msg-${Date.now()}-${messageSeqRef.current}`
  }

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, isStreaming, attachments.length])

  useEffect(() => {
    const handleAskAgent = (e: any) => {
      const message = e.detail?.message
      if (message) setInput(String(message))
    }
    window.addEventListener('ask-agent', handleAskAgent)
    return () => window.removeEventListener('ask-agent', handleAskAgent)
  }, [])

  useEffect(() => {
    return () => {
      if (answerRevealTimerRef.current !== null) {
        window.clearTimeout(answerRevealTimerRef.current)
        answerRevealTimerRef.current = null
      }
    }
  }, [])

  const slashToken = useMemo<SlashTokenMatch | null>(() => {
    const matched = input.match(/(^|\s)\/([^\s]*)$/)
    if (!matched || typeof matched.index !== 'number') return null

    const full = matched[0] || ''
    const prefix = matched[1] || ''
    const query = (matched[2] || '').toLowerCase()
    const start = matched.index + prefix.length
    const end = start + (full.length - prefix.length)
    return { query, start, end }
  }, [input])

  const slashQuery = slashToken ? slashToken.query : null

  const slashCandidates = useMemo(() => {
    if (slashQuery === null) return []

    const normalized = slashQuery.trim().toLowerCase()
    const sorted = [...topologyDevices].sort((a, b) =>
      String(a.label || a.id).localeCompare(String(b.label || b.id))
    )

    if (!normalized) return sorted

    return sorted.filter((d) => {
      const id = String(d.id || '').toLowerCase()
      const label = String(d.label || '').toLowerCase()
      return id.includes(normalized) || label.includes(normalized)
    })
  }, [slashQuery, topologyDevices])

  useEffect(() => {
    setSlashFocusIndex(0)
  }, [slashQuery, slashCandidates.length])

  const chooseSlashDevice = (device: TopologyDeviceSummary) => {
    setChatContextDevice({
      id: String(device.id),
      label: device.label,
      platform: device.platform,
      deviceType: device.deviceType,
      source: 'slash',
    })
    setInput((prev) => {
      if (!slashToken) return prev
      const before = prev.slice(0, slashToken.start)
      const spaced = before.length > 0 && !/\s$/.test(before) ? `${before} ` : before
      return spaced
    })
  }

  const applyViz = (rawViz: any, callId: number | null): VizPayload | null => {
    const payload = toVizPayload(rawViz, callId, currentQuestionRef.current)
    if (!payload) return null
    latestVizRef.current = payload
    setViz(payload)
    return payload
  }

  const pushSystemMessage = (content: string, type: string) => {
    setMessages((prev) => [
      ...prev,
      {
        id: nextMessageId(),
        role: 'system',
        content,
        type,
      },
    ])
  }

  const clearAnswerRevealTimer = () => {
    if (answerRevealTimerRef.current !== null) {
      window.clearTimeout(answerRevealTimerRef.current)
      answerRevealTimerRef.current = null
    }
  }

  const ensureAssistantDraft = (): string => {
    if (assistantDraftIdRef.current) return assistantDraftIdRef.current
    const draftId = nextMessageId()
    assistantDraftIdRef.current = draftId
    setMessages((prev) => [
      ...prev,
      {
        id: draftId,
        role: 'assistant',
        content: '',
        type: 'streaming',
      },
    ])
    return draftId
  }

  const updateAssistantDraft = (
    messageId: string,
    updater: (message: Message) => Message
  ) => {
    setMessages((prev) => prev.map((msg) => (msg.id === messageId ? updater(msg) : msg)))
  }

  const discardAssistantDraftIfEmpty = () => {
    const draftId = assistantDraftIdRef.current
    assistantDraftIdRef.current = null
    if (!draftId) return

    setMessages((prev) =>
      prev.filter((msg) => !(msg.id === draftId && msg.role === 'assistant' && !msg.content.trim()))
    )
  }

  const revealAssistantAnswer = (answer: string, viz: VizPayload | null) => {
    clearAnswerRevealTimer()
    const draftId = ensureAssistantDraft()
    const fullText = String(answer || '')

    if (!fullText) {
      updateAssistantDraft(draftId, (msg) => ({ ...msg, type: 'answer', viz }))
      if (viz) setActiveVizMessageId(draftId)
      assistantDraftIdRef.current = null
      return
    }

    const stepSize = Math.max(
      ANSWER_REVEAL_MIN_STEP,
      Math.min(ANSWER_REVEAL_MAX_STEP, Math.ceil(fullText.length / 70))
    )
    let cursor = 0

    const tick = () => {
      cursor = Math.min(fullText.length, cursor + stepSize)
      const partial = fullText.slice(0, cursor)
      updateAssistantDraft(draftId, (msg) => ({
        ...msg,
        content: partial,
        type: cursor >= fullText.length ? 'answer' : 'streaming',
        viz: cursor >= fullText.length ? viz : undefined,
      }))

      if (cursor < fullText.length) {
        answerRevealTimerRef.current = window.setTimeout(tick, ANSWER_REVEAL_INTERVAL_MS)
        return
      }

      answerRevealTimerRef.current = null
      assistantDraftIdRef.current = null
      if (viz) setActiveVizMessageId(draftId)
    }

    tick()
  }

  const onPickImages = async (event: ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(event.target.files || [])
    if (files.length === 0) return

    const availableSlots = Math.max(0, MAX_ATTACHMENTS - attachments.length)
    const selected = files.slice(0, availableSlots)

    const next: AttachmentDraft[] = []
    for (const file of selected) {
      if (!file.type.startsWith('image/')) continue
      if (file.size > MAX_IMAGE_SIZE_BYTES) {
        pushSystemMessage(`${file.name} is too large (max 5MB).`, 'error')
        continue
      }
      try {
        const dataUrl = await readFileAsDataUrl(file)
        next.push({
          id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
          name: file.name,
          mimeType: file.type,
          size: file.size,
          dataUrl,
        })
      } catch {
        pushSystemMessage(`Failed to read ${file.name}.`, 'error')
      }
    }

    if (next.length > 0) {
      setAttachments((prev) => [...prev, ...next].slice(0, MAX_ATTACHMENTS))
    }

    event.target.value = ''
  }

  const submitCurrentMessage = async () => {
    if ((!input.trim() && attachments.length === 0) || isStreaming) return

    const userMessage = input.trim() || 'Please analyze attached image(s).'
    currentQuestionRef.current = userMessage
    latestVizRef.current = null
    clearAnswerRevealTimer()
    assistantDraftIdRef.current = null

    const userAttachments: MessageAttachment[] = attachments.map((a) => ({
      id: a.id,
      name: a.name,
      mimeType: a.mimeType,
      dataUrl: a.dataUrl,
    }))

    setInput('')
    setActiveVizMessageId(null)
    setMessages((prev) => [
      ...prev,
      {
        id: nextMessageId(),
        role: 'user',
        content: userMessage,
        contextDevice: chatContextDevice ? { ...chatContextDevice } : null,
        attachments: userAttachments,
      },
    ])
    clearViz()
    setIsStreaming(true)

    try {
      const response = await fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: userMessage,
          context_device: chatContextDevice
            ? {
                id: chatContextDevice.id,
                label: chatContextDevice.label,
                platform: chatContextDevice.platform,
                device_type: chatContextDevice.deviceType,
              }
            : null,
          attachments: attachments.map((a) => ({
            name: a.name,
            mime_type: a.mimeType,
            size: a.size,
            data_url: a.dataUrl,
          })),
        }),
      })

      if (!response.ok) {
        throw new Error(`Chat request failed (${response.status})`)
      }

      const reader = response.body?.getReader()
      const decoder = new TextDecoder()

      if (reader) {
        let currentTool: string | null = null
        let currentCallId: number | null = null
        let sseBuffer = ''

        const handleSseEvent = (eventName: string, rawData: string) => {
          try {
            let data: any = null
            try {
              data = JSON.parse(rawData)
            } catch {
              data = { type: eventName, content: rawData }
            }
            if (!data || typeof data !== 'object') {
              data = { type: eventName, content: String(rawData || '') }
            }
            const resolvedType = typeof data.type === 'string' ? data.type : eventName

            if (resolvedType === 'planning') {
              pushSystemMessage(data.reasoning || 'Planning next step...', 'planning')
            } else if (resolvedType === 'tool_call') {
              currentTool = data.tool
              currentCallId = typeof data.call_id === 'number' ? data.call_id : null
              applyViz(data.viz, currentCallId)
              pushSystemMessage(`Running ${String(data.tool || 'tool')}...`, 'tool')
            } else if (resolvedType === 'tool_output') {
              applyViz(data.viz, currentCallId)
              const contentText = typeof data.content === 'string'
                ? data.content
                : JSON.stringify(data.content ?? '')
              addEvidence({
                type: currentTool || 'general',
                status: contentText.toLowerCase().includes('error') ? 'error' : 'success',
                title: currentTool ? `Verification: ${currentTool}` : 'System Check',
                summary: contentText ? `${contentText.substring(0, 100)}...` : 'Result received',
                details: data.content,
              })
            } else if (resolvedType === 'answer_delta' || resolvedType === 'token') {
              const delta = typeof data.content === 'string'
                ? data.content
                : String(data.delta || '')
              if (delta) {
                const draftId = ensureAssistantDraft()
                updateAssistantDraft(draftId, (msg) => ({
                  ...msg,
                  content: `${msg.content || ''}${delta}`,
                  type: 'streaming',
                }))
              }
            } else if (resolvedType === 'answer') {
              const answerViz =
                applyViz(data.viz, currentCallId) ||
                (latestVizRef.current ? { ...latestVizRef.current } : null)
              const finalAnswer = String(data.content || '')
              const draftId = assistantDraftIdRef.current
              if (draftId) {
                clearAnswerRevealTimer()
                updateAssistantDraft(draftId, (msg) => ({
                  ...msg,
                  content: finalAnswer || msg.content,
                  type: 'answer',
                  viz: answerViz,
                }))
                assistantDraftIdRef.current = null
                if (answerViz) setActiveVizMessageId(draftId)
              } else {
                revealAssistantAnswer(finalAnswer, answerViz)
              }
            } else if (resolvedType === 'error') {
              pushSystemMessage(String(data.message || 'Stream error'), 'error')
            }
          } catch {
            // ignore malformed partial events
          }
        }

        while (true) {
          const { done, value } = await reader.read()
          if (done) break

          sseBuffer += decoder.decode(value, { stream: true })

          while (true) {
            const lfSep = sseBuffer.indexOf('\n\n')
            const crlfSep = sseBuffer.indexOf('\r\n\r\n')
            let sepIdx = -1
            let sepLen = 2

            if (lfSep >= 0 && crlfSep >= 0) {
              if (lfSep < crlfSep) {
                sepIdx = lfSep
                sepLen = 2
              } else {
                sepIdx = crlfSep
                sepLen = 4
              }
            } else if (lfSep >= 0) {
              sepIdx = lfSep
              sepLen = 2
            } else if (crlfSep >= 0) {
              sepIdx = crlfSep
              sepLen = 4
            }

            if (sepIdx < 0) break

            const rawEvent = sseBuffer.slice(0, sepIdx)
            sseBuffer = sseBuffer.slice(sepIdx + sepLen)

            let eventName = 'message'
            const dataLines = rawEvent
              .split(/\r?\n/)
              .reduce<string[]>((acc, line) => {
                if (line.startsWith('event:')) {
                  eventName = line.slice(6).trim() || 'message'
                } else if (line.startsWith('data:')) {
                  acc.push(line.slice(5).trimStart())
                }
                return acc
              }, [])

            if (dataLines.length > 0) {
              handleSseEvent(eventName, dataLines.join('\n'))
            }
          }
        }

        const tail = sseBuffer.trim()
        if (tail.includes('data:')) {
          let tailEventName = 'message'
          const tailData = tail
            .split(/\r?\n/)
            .reduce<string[]>((acc, line) => {
              if (line.startsWith('event:')) {
                tailEventName = line.slice(6).trim() || 'message'
              } else if (line.startsWith('data:')) {
                acc.push(line.slice(5).trimStart())
              }
              return acc
            }, [])
            .join('\n')
          if (tailData) handleSseEvent(tailEventName, tailData)
        }
      }

      setAttachments([])
    } catch (err) {
      clearAnswerRevealTimer()
      discardAssistantDraftIfEmpty()
      setMessages((prev) => [
        ...prev,
        {
          id: nextMessageId(),
          role: 'system',
          content: `Error: ${err}`,
          type: 'error',
        },
      ])
    } finally {
      setIsStreaming(false)
    }
  }

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    await submitCurrentMessage()
  }

  const handleInputKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if ((e.nativeEvent as any).isComposing || e.keyCode === 229) return

    if (slashQuery !== null && slashCandidates.length > 0) {
      if (e.key === 'ArrowDown') {
        e.preventDefault()
        setSlashFocusIndex((prev) => (prev + 1) % slashCandidates.length)
        return
      }
      if (e.key === 'ArrowUp') {
        e.preventDefault()
        setSlashFocusIndex((prev) => (prev - 1 + slashCandidates.length) % slashCandidates.length)
        return
      }
      if (e.key === 'Escape') {
        e.preventDefault()
        setInput((prev) => prev.slice(0, slashToken?.start ?? prev.length))
        return
      }
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault()
        chooseSlashDevice(slashCandidates[slashFocusIndex] || slashCandidates[0])
        return
      }
    }

    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      void submitCurrentMessage()
    }
  }

  return (
    <div className="flex-1 flex flex-col min-h-0 bg-gradient-to-b from-card via-card to-muted/30">
      <div className="px-4 py-3 border-b border-border/70 bg-card/70 backdrop-blur-md">
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <div className="w-7 h-7 rounded-lg bg-primary/15 border border-primary/30 flex items-center justify-center">
              <Sparkles className="w-3.5 h-3.5 text-primary" />
            </div>
            <div>
              <p className="text-[11px] uppercase tracking-[0.15em] text-muted-foreground">Assistant</p>
              <p className="text-sm font-semibold text-foreground">NetAlly Copilot</p>
            </div>
          </div>

          <div className="flex items-center gap-1.5">
            {selectedNode && (
              <span className="text-[10px] px-2 py-1 rounded-full border border-border bg-muted/40 text-muted-foreground">
                Selected: {selectedNode}
              </span>
            )}
          </div>
        </div>

        {chatContextDevice && (
          <div className="mt-2 flex items-center gap-2">
            <span className="text-[10px] px-2 py-1 rounded-full border border-primary/30 bg-primary/10 text-primary">
              Context: {buildContextLabel(chatContextDevice)}
            </span>
            <button
              type="button"
              onClick={clearChatContextDevice}
              className="text-[10px] px-2 py-1 rounded-md border border-border bg-card hover:bg-muted text-muted-foreground transition-colors"
            >
              Clear
            </button>
          </div>
        )}
      </div>

      <div className="flex-1 overflow-y-auto px-4 py-5 space-y-5">
        {messages.length === 0 && (
          <div className="h-full min-h-[260px] flex items-center justify-center">
            <div className="w-full max-w-md rounded-2xl border border-border/70 bg-card/70 backdrop-blur-sm p-5 text-center shadow-xl">
              <p className="text-sm font-semibold text-foreground">Ask anything about topology verification</p>
              <p className="text-xs text-muted-foreground mt-2">
                Use `/` to pick a device context, then ask about reachability, routes, and configs.
              </p>
            </div>
          </div>
        )}

        {messages.map((msg) => {
          if (msg.role === 'system') {
            return (
              <div key={msg.id} className="flex justify-center">
                <div className="text-[11px] px-3 py-1.5 rounded-full border border-border/60 bg-muted/30 text-muted-foreground">
                  {msg.content}
                </div>
              </div>
            )
          }

          const isUser = msg.role === 'user'
          const assistantHasViz = !isUser && Boolean(msg.viz)
          const isActiveViz = assistantHasViz && activeVizMessageId === msg.id

          return (
            <div key={msg.id} className={`flex gap-2.5 ${isUser ? 'justify-end' : 'justify-start'}`}>
              {!isUser && (
                <div className="w-7 h-7 mt-1 rounded-full border border-border bg-card flex items-center justify-center shrink-0">
                  <Bot className="w-3.5 h-3.5 text-muted-foreground" />
                </div>
              )}

              <div className={`max-w-[90%] ${isUser ? 'items-end' : 'items-start'} flex flex-col gap-1.5`}>
                {isUser ? (
                  <div className="px-4 py-2.5 rounded-2xl bg-primary text-primary-foreground shadow-md text-[14px] leading-relaxed">
                    {msg.contextDevice && (
                      <div className="mb-1.5 text-[11px] text-primary-foreground/90">
                        Context: {buildContextLabel(msg.contextDevice)}
                      </div>
                    )}
                    <div>{msg.content}</div>
                    {msg.attachments && msg.attachments.length > 0 && (
                      <div className="mt-2 grid grid-cols-2 gap-2">
                        {msg.attachments.map((a) => (
                          <img
                            key={a.id}
                            src={a.dataUrl}
                            alt={a.name}
                            className="rounded-lg border border-white/30 w-full h-24 object-cover"
                          />
                        ))}
                      </div>
                    )}
                  </div>
                ) : (
                  <button
                    type="button"
                    onClick={() => {
                      if (!msg.viz) return
                      setViz(msg.viz)
                      setActiveVizMessageId(msg.id)
                    }}
                    className={`
                      text-left px-4 py-3 rounded-2xl border text-[14px] leading-relaxed transition-all
                      ${assistantHasViz
                        ? 'bg-card/95 border-border hover:border-primary/40 hover:shadow-md cursor-pointer'
                        : 'bg-card/70 border-border/70 cursor-default'
                      }
                      ${isActiveViz ? 'ring-2 ring-primary/45 border-primary/40 shadow-md' : ''}
                    `}
                    disabled={!assistantHasViz}
                    title={assistantHasViz ? 'Click to restore this answer\'s topology overlay' : undefined}
                  >
                    {msg.content ? (
                      <div className="text-foreground leading-relaxed">
                        <ReactMarkdown remarkPlugins={[remarkGfm]} components={markdownComponents}>
                          {msg.content}
                        </ReactMarkdown>
                      </div>
                    ) : msg.type === 'streaming' ? (
                      <div className="text-muted-foreground text-sm flex items-center gap-2">
                        <Loader2 className="w-3.5 h-3.5 animate-spin text-primary" />
                        Generating answer...
                      </div>
                    ) : (
                      <div className="text-muted-foreground text-sm">No answer content</div>
                    )}
                    {assistantHasViz && (
                      <div className="mt-2 pt-2 border-t border-border/60 flex items-center gap-1.5 text-[11px] text-primary font-medium">
                        <Link2 className="w-3 h-3" />
                        Restore topology snapshot for this answer
                      </div>
                    )}
                  </button>
                )}

                <span className="text-[10px] uppercase tracking-[0.14em] text-muted-foreground/60 px-1 flex items-center gap-1.5">
                  {isUser ? <User className="w-3 h-3" /> : <Bot className="w-3 h-3" />}
                  {isUser ? 'You' : 'Assistant'}
                </span>
              </div>
            </div>
          )
        })}

        {isStreaming && (
          <div className="flex gap-2.5 justify-start">
            <div className="w-7 h-7 mt-1 rounded-full border border-border bg-card flex items-center justify-center shrink-0">
              <Bot className="w-3.5 h-3.5 text-primary" />
            </div>
            <div className="px-4 py-3 rounded-2xl border border-border bg-card/80 text-sm text-muted-foreground flex items-center gap-2">
              <Loader2 className="w-4 h-4 animate-spin text-primary" />
              [Thinking..]
            </div>
          </div>
        )}

        <div ref={messagesEndRef} className="h-1" />
      </div>

      <div className="p-4 border-t border-border/70 bg-card/75 backdrop-blur-md">
        <form onSubmit={handleSubmit} className="relative">
          {attachments.length > 0 && (
            <div className="mb-3 flex flex-wrap gap-2">
              {attachments.map((a) => (
                <div key={a.id} className="relative w-20 h-20 rounded-lg overflow-hidden border border-border bg-muted/30">
                  <img src={a.dataUrl} alt={a.name} className="w-full h-full object-cover" />
                  <button
                    type="button"
                    onClick={() => setAttachments((prev) => prev.filter((item) => item.id !== a.id))}
                    className="absolute top-1 right-1 w-5 h-5 rounded-full bg-black/60 text-white flex items-center justify-center"
                  >
                    <X className="w-3 h-3" />
                  </button>
                </div>
              ))}
            </div>
          )}

          <div className="relative">
            <textarea
              rows={2}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleInputKeyDown}
              aria-label="Message input"
              aria-autocomplete={slashQuery !== null ? 'list' : 'none'}
              aria-controls={slashQuery !== null ? slashListIdRef.current : undefined}
              aria-expanded={slashQuery !== null}
              aria-activedescendant={
                slashQuery !== null && slashCandidates.length > 0
                  ? `${slashListIdRef.current}-opt-${slashFocusIndex}`
                  : undefined
              }
              placeholder={
                chatContextDevice
                  ? `Ask about ${buildContextLabel(chatContextDevice)}...`
                  : 'Type message... (use / to select a device)'
              }
              className="
                w-full pl-4 pr-24 py-3 rounded-2xl
                bg-background/75 border border-border
                text-[14px] text-foreground placeholder-muted-foreground/70
                focus:outline-none focus:ring-2 focus:ring-primary/30 focus:border-primary/40
                resize-none transition-all
              "
            />

            <div className="absolute right-2.5 bottom-2.5 flex items-center gap-1.5">
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
                className="h-9 w-9 rounded-xl border border-border bg-card text-muted-foreground hover:text-foreground hover:bg-muted transition-colors"
                title="Upload image"
              >
                <ImagePlus className="w-4 h-4 mx-auto" />
              </button>
              <button
                type="submit"
                disabled={isStreaming || (!input.trim() && attachments.length === 0)}
                className="
                  h-9 px-3 rounded-xl bg-primary text-primary-foreground text-xs font-semibold
                  disabled:opacity-35 disabled:cursor-not-allowed
                  hover:brightness-110 active:scale-[0.98] transition-all
                "
              >
                Send
              </button>
            </div>

            {slashQuery !== null && (
              <div
                id={slashListIdRef.current}
                role="listbox"
                className="absolute left-0 right-0 bottom-[calc(100%+8px)] max-h-56 overflow-y-auto rounded-xl border border-border bg-card shadow-2xl z-20"
              >
                {slashCandidates.length > 0 ? (
                  slashCandidates.map((device, idx) => (
                    <button
                      id={`${slashListIdRef.current}-opt-${idx}`}
                      key={device.id}
                      type="button"
                      role="option"
                      aria-selected={idx === slashFocusIndex}
                      onClick={() => chooseSlashDevice(device)}
                      className={`w-full text-left px-3 py-2.5 border-b last:border-b-0 border-border/50 text-sm transition-colors ${
                        idx === slashFocusIndex ? 'bg-primary/10 text-foreground' : 'hover:bg-muted/50 text-foreground'
                      }`}
                    >
                      <div className="font-medium">{device.label || device.id}</div>
                      <div className="text-[11px] text-muted-foreground">{device.platform || device.id}</div>
                    </button>
                  ))
                ) : (
                  <div className="px-3 py-3 text-sm text-muted-foreground">No matching devices</div>
                )}
              </div>
            )}
          </div>
        </form>
      </div>
    </div>
  )
}
