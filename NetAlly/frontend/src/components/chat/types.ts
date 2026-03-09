import type { VizPayload, ChatContextDevice } from '../../store'

/* ── Attachment ── */
export interface MessageAttachment {
  id: string
  name: string
  mimeType: string
  dataUrl?: string
}

export interface AttachmentDraft extends MessageAttachment {
  size: number
}

/* ── Message ── */
export interface Message {
  id: string
  role: 'user' | 'assistant' | 'system'
  content: string
  type?: string
  viz?: VizPayload | null
  attachments?: MessageAttachment[]
  contextDevice?: ChatContextDevice | null
  citations?: MessageCitation[]
  grounding?: MessageGrounding | null
}

export interface ChatPanelProps {
  selectedNode: string | null
}

export interface SlashTokenMatch {
  query: string
  start: number
  end: number
}

export interface MessageCitation {
  id: string
  type: string
  tool: string
  summary: string
  status: 'success' | 'warning' | 'error' | 'info'
  callId?: number
  evidenceId?: string
}

export interface MessageGrounding {
  supportedByTools: boolean
  citationCount: number
  coverage?: string
  note?: string
}

export interface PersistedChatMessage {
  id: string
  role: 'user' | 'assistant' | 'system'
  content: string
  type?: string
  viz?: VizPayload | null
  contextDevice?: ChatContextDevice | null
  citations?: MessageCitation[]
  grounding?: MessageGrounding | null
}

export interface PersistedChatSession {
  messages: PersistedChatMessage[]
  activeVizMessageId: string | null
  input: string
  chatContextDevice: ChatContextDevice | null
}

export interface RetryRequestPayload {
  message: string
  contextDevice: ChatContextDevice | null
  attachments: AttachmentDraft[]
}

/* ── Constants ── */
export const MAX_ATTACHMENTS = 4
export const MAX_IMAGE_SIZE_BYTES = 5 * 1024 * 1024
export const ANSWER_REVEAL_MIN_STEP = 8
export const ANSWER_REVEAL_MAX_STEP = 36
export const ANSWER_REVEAL_INTERVAL_MS = 14
export const CHAT_SESSION_STORAGE_KEY = 'netally_chat_session_v1'
export const MAX_PERSISTED_MESSAGES = 60
export const CHAT_STREAM_TOTAL_TIMEOUT_MS = 5 * 60_000
export const CHAT_STREAM_IDLE_TIMEOUT_MS = 60_000

export const SUGGESTIONS = [
  'Show all BGP session status',
  'Is PE1 reachable from PE2?',
  'What OSPF areas are configured?',
  'Check MTU consistency across interfaces',
]

/* ── Utility functions ── */

export const toVizPayload = (
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

  const resolvedCallId =
    typeof callId === 'number'
      ? callId
      : (typeof rawViz.call_id === 'number' ? rawViz.call_id : (typeof rawViz.callId === 'number' ? rawViz.callId : undefined))

  return {
    nodes,
    edges,
    mode: rawViz.mode === 'path' ? 'path' : 'focus',
    title: typeof rawViz.title === 'string' ? rawViz.title : undefined,
    callId: resolvedCallId,
    query: (typeof rawViz.query === 'string' ? rawViz.query : query) || undefined,
    reason: typeof rawViz.reason === 'string' ? rawViz.reason : undefined,
    source: typeof rawViz.source === 'string' ? rawViz.source : undefined,
    schemaVersion: typeof rawViz.schema_version === 'number' ? rawViz.schema_version : (typeof rawViz.schemaVersion === 'number' ? rawViz.schemaVersion : undefined),
    diagnostics: rawViz.diagnostics && typeof rawViz.diagnostics === 'object'
      ? {
          requestedNodes: typeof rawViz.diagnostics.requestedNodes === 'number' ? rawViz.diagnostics.requestedNodes : undefined,
          requestedEdges: typeof rawViz.diagnostics.requestedEdges === 'number' ? rawViz.diagnostics.requestedEdges : undefined,
          normalizedNodes: typeof rawViz.diagnostics.normalizedNodes === 'number' ? rawViz.diagnostics.normalizedNodes : undefined,
          normalizedEdges: typeof rawViz.diagnostics.normalizedEdges === 'number' ? rawViz.diagnostics.normalizedEdges : undefined,
          truncated: typeof rawViz.diagnostics.truncated === 'boolean' ? rawViz.diagnostics.truncated : undefined,
        }
      : undefined,
  }
}

export const readFileAsDataUrl = (file: File): Promise<string> => {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => resolve(String(reader.result || ''))
    reader.onerror = reject
    reader.readAsDataURL(file)
  })
}

export const buildContextLabel = (context: ChatContextDevice | null): string => {
  if (!context) return ''
  return context.label || context.id
}

export const toMessageCitation = (raw: any): MessageCitation | null => {
  if (!raw || typeof raw !== 'object') return null
  const summary = String(raw.summary || '').trim()
  const tool = String(raw.tool || '').trim()
  if (!summary || !tool) return null
  const statusRaw = String(raw.status || 'info').toLowerCase()
  const status: MessageCitation['status'] =
    statusRaw === 'success' || statusRaw === 'warning' || statusRaw === 'error'
      ? statusRaw
      : 'info'
  return {
    id: String(raw.id || `${tool}-${summary.slice(0, 12)}`),
    type: String(raw.type || 'tool_output'),
    tool,
    summary,
    status,
    callId: typeof raw.call_id === 'number' ? raw.call_id : (typeof raw.callId === 'number' ? raw.callId : undefined),
    evidenceId: typeof raw.evidence_id === 'string' ? raw.evidence_id : (typeof raw.evidenceId === 'string' ? raw.evidenceId : undefined),
  }
}

export const toMessageGrounding = (raw: any): MessageGrounding | null => {
  if (!raw || typeof raw !== 'object') return null
  const citationCount = typeof raw.citation_count === 'number'
    ? raw.citation_count
    : (typeof raw.citationCount === 'number' ? raw.citationCount : 0)
  const supportedByTools = Boolean(
    typeof raw.supported_by_tools === 'boolean'
      ? raw.supported_by_tools
      : raw.supportedByTools
  )
  return {
    supportedByTools,
    citationCount: Number.isFinite(citationCount) ? citationCount : 0,
    coverage: typeof raw.coverage === 'string' ? raw.coverage : undefined,
    note: typeof raw.note === 'string' ? raw.note : undefined,
  }
}

export const citationStatusClass = (status: MessageCitation['status']) => {
  if (status === 'success') return 'border-emerald-500/30 bg-emerald-500/10 text-emerald-500'
  if (status === 'warning') return 'border-amber-500/30 bg-amber-500/10 text-amber-500'
  if (status === 'error') return 'border-rose-500/30 bg-rose-500/10 text-rose-500'
  return 'border-border/70 bg-muted/40 text-muted-foreground'
}

export const normalizePersistedMessage = (raw: any): Message | null => {
  if (!raw || typeof raw !== 'object') return null
  const role = String(raw.role || '')
  if (role !== 'user' && role !== 'assistant' && role !== 'system') return null
  const id = String(raw.id || '').trim()
  if (!id) return null
  return {
    id,
    role,
    content: String(raw.content || ''),
    type: typeof raw.type === 'string' ? raw.type : undefined,
    viz: raw.viz && typeof raw.viz === 'object' ? (raw.viz as VizPayload) : null,
    contextDevice: raw.contextDevice && typeof raw.contextDevice === 'object'
      ? (raw.contextDevice as ChatContextDevice)
      : null,
    citations: Array.isArray(raw.citations)
      ? raw.citations.map((c: any) => toMessageCitation(c)).filter(Boolean) as MessageCitation[]
      : undefined,
    grounding: toMessageGrounding(raw.grounding),
    attachments: [],
  }
}
