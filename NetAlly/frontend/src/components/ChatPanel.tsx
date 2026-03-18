/**
 * ChatPanel - modern conversational UI (ChatGPT/Claude style).
 * Business logic preserved; rendering delegated to sub-components.
 */
import { ChangeEvent, FormEvent, KeyboardEvent, useEffect, useMemo, useRef, useState } from 'react'
import { Trash2 } from 'lucide-react'
import {
  useAppStore,
  VizPayload,
  TopologyDeviceSummary,
  ChatContextDevice,
} from '../store'
import type {
  Message,
  AttachmentDraft,
  MessageAttachment,
  MessageCitation,
  MessageGrounding,
  SlashTokenMatch,
  PersistedChatSession,
  RetryRequestPayload,
  ChatPanelProps,
} from './chat/types'
import {
  MAX_ATTACHMENTS,
  MAX_IMAGE_SIZE_BYTES,
  ANSWER_REVEAL_MIN_STEP,
  ANSWER_REVEAL_MAX_STEP,
  ANSWER_REVEAL_INTERVAL_MS,
  CHAT_SESSION_STORAGE_KEY,
  MAX_PERSISTED_MESSAGES,
  CHAT_STREAM_TOTAL_TIMEOUT_MS,
  CHAT_STREAM_IDLE_TIMEOUT_MS,
  toVizPayload,
  readFileAsDataUrl,
  toMessageCitation,
  toMessageGrounding,
  normalizePersistedMessage,
} from './chat/types'
import ChatEmptyState from './chat/ChatEmptyState'
import ChatMessage from './chat/ChatMessage'
import ChatInput from './chat/ChatInput'

export default function ChatPanel({ selectedNode }: ChatPanelProps) {
  const [messages, setMessages] = useState<Message[]>([])
  const [input, setInput] = useState('')
  const [isStreaming, setIsStreaming] = useState(false)
  const [activeVizMessageId, setActiveVizMessageId] = useState<string | null>(null)
  const [attachments, setAttachments] = useState<AttachmentDraft[]>([])
  const [slashFocusIndex, setSlashFocusIndex] = useState(0)
  const [lastFailedRequest, setLastFailedRequest] = useState<RetryRequestPayload | null>(null)

  const messagesEndRef = useRef<HTMLDivElement>(null)
  const messageSeqRef = useRef(0)
  const latestVizRef = useRef<VizPayload | null>(null)
  const currentQuestionRef = useRef('')
  const assistantDraftIdRef = useRef<string | null>(null)
  const answerRevealTimerRef = useRef<number | null>(null)
  const slashListIdRef = useRef(`chat-slash-list-${Math.random().toString(36).slice(2, 8)}`)
  const evidenceIdByCallRef = useRef<Record<number, string>>({})
  const hydratedRef = useRef(false)
  const streamAbortRef = useRef<AbortController | null>(null)
  const streamHardTimeoutRef = useRef<number | null>(null)
  const streamIdleTimeoutRef = useRef<number | null>(null)

  const addEvidence = useAppStore((state) => state.addEvidence)
  const openDetail = useAppStore((state) => state.openDetail)
  const setViz = useAppStore((state) => state.setViz)
  const clearViz = useAppStore((state) => state.clearViz)
  const topologyDevices = useAppStore((state) => state.topologyDevices)
  const chatContextDevice = useAppStore((state) => state.chatContextDevice)
  const setChatContextDevice = useAppStore((state) => state.setChatContextDevice)
  const clearChatContextDevice = useAppStore((state) => state.clearChatContextDevice)
  const runtimeHealth = useAppStore((state) => state.runtimeHealth)

  const nextMessageId = () => {
    messageSeqRef.current += 1
    return `msg-${Date.now()}-${messageSeqRef.current}`
  }

  // ── Auto-scroll ──
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, isStreaming, attachments.length])

  // ── External ask-agent event ──
  useEffect(() => {
    const handleAskAgent = (e: any) => {
      const message = e.detail?.message
      if (message) setInput(String(message))
    }
    window.addEventListener('ask-agent', handleAskAgent)
    return () => window.removeEventListener('ask-agent', handleAskAgent)
  }, [])

  // ── Cleanup timers on unmount ──
  useEffect(() => {
    return () => {
      if (answerRevealTimerRef.current !== null) {
        window.clearTimeout(answerRevealTimerRef.current)
        answerRevealTimerRef.current = null
      }
      clearStreamTimers()
      if (streamAbortRef.current && !streamAbortRef.current.signal.aborted) {
        streamAbortRef.current.abort('unmount')
      }
    }
  }, [])

  // ── Hydrate from localStorage ──
  useEffect(() => {
    try {
      const raw = localStorage.getItem(CHAT_SESSION_STORAGE_KEY)
      if (!raw) {
        hydratedRef.current = true
        return
      }
      const parsed = JSON.parse(raw) as Partial<PersistedChatSession>
      const restoredMessages = Array.isArray(parsed.messages)
        ? parsed.messages
            .map((m) => normalizePersistedMessage(m))
            .filter(Boolean) as Message[]
        : []

      if (restoredMessages.length > 0) {
        setMessages(restoredMessages.slice(-MAX_PERSISTED_MESSAGES))
      }
      if (typeof parsed.input === 'string') {
        setInput(parsed.input.slice(0, 1200))
      }
      if (parsed.chatContextDevice && typeof parsed.chatContextDevice === 'object') {
        setChatContextDevice(parsed.chatContextDevice as ChatContextDevice)
      }
      if (typeof parsed.activeVizMessageId === 'string' && parsed.activeVizMessageId.trim()) {
        const activeId = parsed.activeVizMessageId
        setActiveVizMessageId(activeId)
        const activeMessage = restoredMessages.find((m) => m.id === activeId)
        if (activeMessage?.viz) {
          setViz(activeMessage.viz)
        }
      }
    } catch {
      // ignore broken persisted session payload
    } finally {
      hydratedRef.current = true
    }
  }, [setChatContextDevice, setViz])

  // ── Persist to localStorage ──
  useEffect(() => {
    if (!hydratedRef.current) return
    try {
      const hasMeaningfulState =
        messages.length > 0 ||
        Boolean(input.trim()) ||
        Boolean(chatContextDevice) ||
        Boolean(activeVizMessageId)

      if (!hasMeaningfulState) {
        localStorage.removeItem(CHAT_SESSION_STORAGE_KEY)
        return
      }

      const compactMessages = messages
        .slice(-MAX_PERSISTED_MESSAGES)
        .map((msg) => ({
          id: msg.id,
          role: msg.role,
          content: String(msg.content || '').slice(0, 12000),
          type: msg.type,
          viz: msg.viz ? { ...msg.viz } : null,
          contextDevice: msg.contextDevice ? { ...msg.contextDevice } : null,
          citations: msg.citations ? msg.citations.slice(0, 8).map((c) => ({ ...c })) : undefined,
          grounding: msg.grounding ? { ...msg.grounding } : null,
        }))

      const payload: PersistedChatSession = {
        messages: compactMessages,
        activeVizMessageId,
        input: input.slice(0, 1200),
        chatContextDevice: chatContextDevice ? { ...chatContextDevice } : null,
      }
      localStorage.setItem(CHAT_SESSION_STORAGE_KEY, JSON.stringify(payload))
    } catch {
      // ignore storage quota and serialization failures
    }
  }, [messages, input, activeVizMessageId, chatContextDevice])

  // ── Slash command logic ──
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

  // ── Viz helpers ──
  const applyViz = (rawViz: any, callId: number | null): VizPayload | null => {
    const payload = toVizPayload(rawViz, callId, currentQuestionRef.current)
    if (!payload) return null
    latestVizRef.current = payload
    setViz(payload)
    return payload
  }

  // ── System messages ──
  const pushSystemMessage = (content: string, type: string) => {
    setMessages((prev) => [
      ...prev,
      { id: nextMessageId(), role: 'system', content, type },
    ])
  }

  // ── Timer helpers ──
  const clearAnswerRevealTimer = () => {
    if (answerRevealTimerRef.current !== null) {
      window.clearTimeout(answerRevealTimerRef.current)
      answerRevealTimerRef.current = null
    }
  }

  const clearStreamTimers = () => {
    if (streamHardTimeoutRef.current !== null) {
      window.clearTimeout(streamHardTimeoutRef.current)
      streamHardTimeoutRef.current = null
    }
    if (streamIdleTimeoutRef.current !== null) {
      window.clearTimeout(streamIdleTimeoutRef.current)
      streamIdleTimeoutRef.current = null
    }
  }

  const scheduleStreamIdleTimeout = () => {
    if (!streamAbortRef.current) return
    if (streamIdleTimeoutRef.current !== null) {
      window.clearTimeout(streamIdleTimeoutRef.current)
    }
    streamIdleTimeoutRef.current = window.setTimeout(() => {
      if (!streamAbortRef.current || streamAbortRef.current.signal.aborted) return
      streamAbortRef.current.abort('timeout_idle')
    }, CHAT_STREAM_IDLE_TIMEOUT_MS)
  }

  const cancelStreaming = (reason: 'user_cancel' | 'timeout_total' | 'timeout_idle' = 'user_cancel') => {
    const ctrl = streamAbortRef.current
    if (!ctrl || ctrl.signal.aborted) return
    ctrl.abort(reason)
  }

  // ── Assistant draft management ──
  const ensureAssistantDraft = (): string => {
    if (assistantDraftIdRef.current) return assistantDraftIdRef.current
    const draftId = nextMessageId()
    assistantDraftIdRef.current = draftId
    setMessages((prev) => [
      ...prev,
      { id: draftId, role: 'assistant', content: '', type: 'streaming' },
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

  const revealAssistantAnswer = (
    answer: string,
    viz: VizPayload | null,
    citations: MessageCitation[] = [],
    grounding: MessageGrounding | null = null
  ) => {
    clearAnswerRevealTimer()
    const draftId = ensureAssistantDraft()
    const fullText = String(answer || '')

    if (!fullText) {
      updateAssistantDraft(draftId, (msg) => ({
        ...msg,
        type: 'answer',
        viz,
        citations,
        grounding,
      }))
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
        citations: cursor >= fullText.length ? citations : undefined,
        grounding: cursor >= fullText.length ? grounding : undefined,
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

  // ── Image attachment ──
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

  // ── Core chat request ──
  const executeChatRequest = async (requestPayload: RetryRequestPayload) => {
    if (isStreaming) return

    const userMessage = String(requestPayload.message || '').trim()
      || 'Please analyze attached image(s).'
    const requestContext = requestPayload.contextDevice
      ? { ...requestPayload.contextDevice }
      : null
    const requestAttachments = requestPayload.attachments.map((a) => ({ ...a }))

    currentQuestionRef.current = userMessage
    latestVizRef.current = null
    evidenceIdByCallRef.current = {}
    clearAnswerRevealTimer()
    assistantDraftIdRef.current = null
    clearStreamTimers()
    setLastFailedRequest(null)

    const userAttachments: MessageAttachment[] = requestAttachments.map((a) => ({
      id: a.id,
      name: a.name,
      mimeType: a.mimeType,
      dataUrl: a.dataUrl,
    }))

    setActiveVizMessageId(null)
    setMessages((prev) => [
      ...prev,
      {
        id: nextMessageId(),
        role: 'user',
        content: userMessage,
        contextDevice: requestContext,
        attachments: userAttachments,
      },
    ])
    clearViz()
    setIsStreaming(true)

    const controller = new AbortController()
    streamAbortRef.current = controller
    streamHardTimeoutRef.current = window.setTimeout(() => {
      cancelStreaming('timeout_total')
    }, CHAT_STREAM_TOTAL_TIMEOUT_MS)

    const fetchChatStream = async (): Promise<Response> => {
      const payloadBody = {
        message: userMessage,
        context_device: requestContext
          ? {
              id: requestContext.id,
              label: requestContext.label,
              platform: requestContext.platform,
              device_type: requestContext.deviceType,
            }
          : null,
        attachments: requestAttachments.map((a) => ({
          name: a.name,
          mime_type: a.mimeType,
          size: a.size,
          data_url: a.dataUrl,
        })),
      }

      for (let attempt = 0; attempt < 2; attempt += 1) {
        if (controller.signal.aborted) {
          throw new DOMException('Aborted', 'AbortError')
        }
        try {
          const response = await fetch('/api/chat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payloadBody),
            signal: controller.signal,
          })

          if (!response.ok) {
            const retryable = response.status === 408 || response.status === 429 || response.status >= 500
            if (retryable && attempt === 0) {
              await new Promise((resolve) => window.setTimeout(resolve, 600))
              continue
            }
            throw new Error(`Chat request failed (${response.status})`)
          }
          return response
        } catch (err: any) {
          const aborted = controller.signal.aborted || err?.name === 'AbortError'
          if (aborted) throw err
          if (attempt === 0) {
            await new Promise((resolve) => window.setTimeout(resolve, 600))
            continue
          }
          throw err
        }
      }
      throw new Error('Chat request failed after retry')
    }

    // TODO: health check could be added here before initiating the stream,
    // e.g. GET /api/health to display backend status before sending the request.
    try {
      const response = await fetchChatStream()
      const reader = response.body?.getReader()
      const decoder = new TextDecoder()

      if (reader) {
        let currentTool: string | null = null
        let currentCallId: number | null = null
        let sseBuffer = ''
        scheduleStreamIdleTimeout()

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
              const resolvedCallId = typeof data.call_id === 'number' ? data.call_id : currentCallId
              applyViz(data.viz, resolvedCallId)
              const contentText = typeof data.content === 'string'
                ? data.content
                : JSON.stringify(data.content ?? '')

              const citation = toMessageCitation(data.citation)
              const evidenceStatus = citation?.status
                || (contentText.toLowerCase().includes('error') ? 'error' : 'success')
              const evidenceSummary = citation?.summary
                || (contentText ? `${contentText.substring(0, 100)}...` : 'Result received')
              const evidenceType = citation?.tool || currentTool || 'general'

              const evidenceId = addEvidence({
                id: citation?.id,
                type: evidenceType,
                status: evidenceStatus,
                title: evidenceType ? `Verification: ${evidenceType}` : 'System Check',
                summary: evidenceSummary,
                details: data.content,
              })
              if (citation?.callId != null) {
                evidenceIdByCallRef.current[citation.callId] = evidenceId
              }
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

              const citations = Array.isArray(data.citations)
                ? data.citations
                    .map((item: any) => toMessageCitation(item))
                    .filter(Boolean)
                    .map((item: any) => {
                      const evidenceId =
                        item.evidenceId
                        || (item.callId != null ? evidenceIdByCallRef.current[item.callId] : undefined)
                      return { ...item, evidenceId } as MessageCitation
                    })
                : []
              const grounding = toMessageGrounding(data.grounding)

              const finalAnswer = String(data.content || '')
              const draftId = assistantDraftIdRef.current
              if (draftId) {
                clearAnswerRevealTimer()
                updateAssistantDraft(draftId, (msg) => ({
                  ...msg,
                  content: finalAnswer || msg.content,
                  type: 'answer',
                  viz: answerViz,
                  citations,
                  grounding,
                }))
                assistantDraftIdRef.current = null
                if (answerViz) setActiveVizMessageId(draftId)
              } else {
                revealAssistantAnswer(finalAnswer, answerViz, citations, grounding)
              }
            } else if (resolvedType === 'tool_error') {
              const toolName = data.tool || 'unknown'
              const errorMsg = data.error || 'Tool execution failed'
              pushSystemMessage(`⚠ Tool "${toolName}" failed: ${errorMsg}`, 'error')
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
          scheduleStreamIdleTimeout()

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
      setLastFailedRequest(null)
    } catch (err: any) {
      clearAnswerRevealTimer()
      discardAssistantDraftIfEmpty()

      const abortReason = String(streamAbortRef.current?.signal?.reason || '')
      const isAbort = err?.name === 'AbortError' || abortReason.length > 0
      let systemMessage = `Error: ${String(err)}`
      let systemType = 'error'

      if (isAbort && abortReason === 'user_cancel') {
        systemMessage = 'Request cancelled.'
        systemType = 'info'
      } else if (isAbort && abortReason === 'timeout_total') {
        systemMessage = 'Request timed out (overall timeout). You can retry.'
        systemType = 'warning'
      } else if (isAbort && abortReason === 'timeout_idle') {
        systemMessage = 'Request timed out (no stream activity). You can retry.'
        systemType = 'warning'
      }

      setMessages((prev) => [
        ...prev,
        { id: nextMessageId(), role: 'system', content: systemMessage, type: systemType },
      ])

      if (abortReason !== 'user_cancel') {
        setLastFailedRequest({
          message: userMessage,
          contextDevice: requestContext,
          attachments: requestAttachments,
        })
      }
    } finally {
      clearStreamTimers()
      streamAbortRef.current = null
      setIsStreaming(false)
    }
  }

  const submitCurrentMessage = async () => {
    if ((!input.trim() && attachments.length === 0) || isStreaming) return
    const payload: RetryRequestPayload = {
      message: input.trim() || 'Please analyze attached image(s).',
      contextDevice: chatContextDevice ? { ...chatContextDevice } : null,
      attachments: attachments.map((a) => ({ ...a })),
    }
    setInput('')
    await executeChatRequest(payload)
  }

  const retryLastRequest = async () => {
    if (!lastFailedRequest || isStreaming) return
    await executeChatRequest({
      message: lastFailedRequest.message,
      contextDevice: lastFailedRequest.contextDevice ? { ...lastFailedRequest.contextDevice } : null,
      attachments: lastFailedRequest.attachments.map((a) => ({ ...a })),
    })
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

  // ── Callbacks for sub-components ──
  const handleVizClick = (viz: VizPayload, messageId: string) => {
    setViz(viz)
    setActiveVizMessageId(messageId)
  }

  const handleCitationClick = (evidenceId: string) => {
    openDetail('evidence', evidenceId)
  }

  const clearChat = () => {
    setMessages([])
    setActiveVizMessageId(null)
    clearViz()
    localStorage.removeItem(CHAT_SESSION_STORAGE_KEY)
  }

  // ── Render ──
  return (
    <div className="flex-1 flex flex-col min-h-0 bg-background">
      {/* Message area */}
      <div className="flex-1 overflow-y-auto px-4 py-4">
        {messages.length === 0 ? (
          <ChatEmptyState onSuggestionClick={setInput} />
        ) : (
          <div className="max-w-2xl mx-auto space-y-5">
            {/* Clear chat */}
            <div className="flex justify-end">
              <button
                type="button"
                onClick={clearChat}
                className="text-ui-xs text-muted-foreground/50 hover:text-muted-foreground flex items-center gap-1 transition-colors"
                title="Clear chat"
              >
                <Trash2 className="w-3 h-3" />
                Clear
              </button>
            </div>

            {messages.map((msg) => (
              <ChatMessage
                key={msg.id}
                message={msg}
                isActiveViz={Boolean(msg.viz) && activeVizMessageId === msg.id}
                onVizClick={handleVizClick}
                onCitationClick={handleCitationClick}
              />
            ))}

            {/* Thinking indicator */}
            {isStreaming && !assistantDraftIdRef.current && (
              <div className="flex items-center gap-2 px-1">
                <div className="flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-primary animate-bounce [animation-delay:0ms]" />
                  <span className="w-1.5 h-1.5 rounded-full bg-primary animate-bounce [animation-delay:150ms]" />
                  <span className="w-1.5 h-1.5 rounded-full bg-primary animate-bounce [animation-delay:300ms]" />
                </div>
                <span className="text-sm text-muted-foreground">Thinking...</span>
              </div>
            )}

            <div ref={messagesEndRef} className="h-1" />
          </div>
        )}
      </div>

      {/* Input area */}
      <ChatInput
        input={input}
        setInput={setInput}
        isStreaming={isStreaming}
        attachments={attachments}
        setAttachments={setAttachments}
        chatContextDevice={chatContextDevice}
        clearChatContextDevice={clearChatContextDevice}
        slashToken={slashToken}
        slashCandidates={slashCandidates}
        slashFocusIndex={slashFocusIndex}
        slashListId={slashListIdRef.current}
        selectedNode={selectedNode}
        runtimeDegraded={runtimeHealth.overall === 'degraded'}
        runtimeNote={runtimeHealth.notes[0] || ''}
        hasRetry={Boolean(lastFailedRequest) && !isStreaming}
        onSubmit={handleSubmit}
        onCancel={() => cancelStreaming('user_cancel')}
        onRetry={() => void retryLastRequest()}
        onPickImages={onPickImages}
        onChooseSlashDevice={chooseSlashDevice}
        onKeyDown={handleInputKeyDown}
      />
    </div>
  )
}
