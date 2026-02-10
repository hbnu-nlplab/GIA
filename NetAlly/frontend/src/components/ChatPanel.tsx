/**
 * ChatPanel - LangChain/ChatGPT style minimalist interface
 */
import { useState, useRef, useEffect, FormEvent } from 'react'
import { useAppStore } from '../store'

interface Message {
  role: 'user' | 'assistant' | 'system'
  content: string
  type?: string
}

interface ChatPanelProps {
  selectedNode: string | null
}

export default function ChatPanel({ selectedNode }: ChatPanelProps) {
  const [messages, setMessages] = useState<Message[]>([])
  const [input, setInput] = useState('')
  const [isStreaming, setIsStreaming] = useState(false)
  const messagesEndRef = useRef<HTMLDivElement>(null)
  
  const addEvidence = useAppStore(state => state.addEvidence)
  const setViz = useAppStore(state => state.setViz)
  const clearViz = useAppStore(state => state.clearViz)

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  useEffect(() => {
    const handleAskAgent = (e: any) => {
      const message = e.detail?.message;
      if (message) {
        setInput(message);
        // Optional: auto-submit or just set input
      }
    };
    window.addEventListener('ask-agent', handleAskAgent);
    return () => window.removeEventListener('ask-agent', handleAskAgent);
  }, []);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    if (!input.trim() || isStreaming) return

    const userMessage = input.trim()
    setInput('')
    setMessages(prev => [...prev, { role: 'user', content: userMessage }])
    clearViz() // new question => clear any previous overlay
    setIsStreaming(true)

    try {
      const response = await fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: userMessage }),
      })

      const reader = response.body?.getReader()
      const decoder = new TextDecoder()

      if (reader) {
        let currentTool: string | null = null;
        let currentCallId: number | null = null;
        
        while (true) {
          const { done, value } = await reader.read()
          if (done) break

          const chunk = decoder.decode(value)
          const lines = chunk.split('\n')

          for (const line of lines) {
            if (line.startsWith('data: ')) {
              try {
                const data = JSON.parse(line.slice(6))
                
                if (data.type === 'planning') {
                  setMessages(prev => [...prev, {
                    role: 'system',
                    content: data.reasoning,
                    type: 'planning'
                  }])
                } else if (data.type === 'tool_call') {
                  currentTool = data.tool;
                  currentCallId = typeof data.call_id === 'number' ? data.call_id : null;
                  if (data.viz) setViz({ ...data.viz, callId: currentCallId ?? undefined })
                  setMessages(prev => [...prev, {
                    role: 'system',
                    content: `Executing ${data.tool}...`,
                    type: 'tool'
                  }])
                } else if (data.type === 'tool_output') {
                  if (data.viz) setViz({ ...data.viz, callId: currentCallId ?? undefined })
                  // Push to Evidence Store
                  addEvidence({
                    type: currentTool || 'general',
                    status: data.content.toLowerCase().includes('error') ? 'error' : 'success',
                    title: currentTool ? `Verification: ${currentTool}` : 'System Check',
                    summary: typeof data.content === 'string' ? data.content.substring(0, 100) + '...' : 'Result received',
                    details: data.content
                  })
                } else if (data.type === 'answer') {
                  if (data.viz) setViz({ ...data.viz, callId: currentCallId ?? undefined })
                  setMessages(prev => [...prev, {
                    role: 'assistant',
                    content: data.content
                  }])
                }
              } catch { }
            }
          }
        }
      }
    } catch (err) {
      setMessages(prev => [...prev, { role: 'system', content: `Error: ${err}`, type: 'error' }])
    } finally {
      setIsStreaming(false)
    }
  }

  return (
    <div className="flex-1 flex flex-col min-h-0 bg-card">
      {/* Messages Area */}
      <div className="flex-1 overflow-y-auto pt-6 px-6 space-y-8 scroll-smooth">
        {messages.length === 0 && (
          <div className="h-full flex flex-col items-center justify-center text-center space-y-4 opacity-40">
            <div className="w-12 h-12 bg-muted rounded-2xl flex items-center justify-center grayscale">
              <span className="text-2xl">⚡</span>
            </div>
            <div className="space-y-1">
              <p className="text-sm font-medium text-foreground">What verification do you need?</p>
              <p className="text-xs text-muted-foreground">Ask about reachability, health, or configurations.</p>
            </div>
          </div>
        )}
        
        {messages.map((msg, i) => (
          <div key={i} className={`flex gap-4 ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
            <div className={`
              group relative flex flex-col space-y-1.5 
              ${msg.role === 'user' ? 'items-end max-w-[85%]' : 'items-start max-w-[90%]'}
            `}>
              {msg.role === 'system' ? (
                <div className="flex items-center gap-3 px-3 py-1.5 rounded-full bg-muted/40 border border-border/50">
                   <span className="text-[10px] grayscale opacity-50">
                    {msg.type === 'planning' ? '🧠' : '🔧'}
                   </span>
                   <span className="text-[11px] font-mono text-muted-foreground leading-none lowercase tracking-tight">
                    {msg.content}
                   </span>
                </div>
              ) : (
                <>
                  <div className={`
                    px-4 py-2.5 rounded-2xl text-[13.5px] leading-relaxed
                    ${msg.role === 'user' 
                      ? 'bg-primary text-primary-foreground font-medium shadow-sm' 
                      : 'bg-muted/30 text-foreground border border-border/50'}
                  `}>
                    {msg.content}
                  </div>
                  <span className="text-[10px] text-muted-foreground/40 font-medium uppercase tracking-widest px-1">
                    {msg.role}
                  </span>
                </>
              )}
            </div>
          </div>
        ))}
        {isStreaming && (
          <div className="flex items-center gap-2 px-1">
            <div className="w-1.5 h-1.5 bg-primary rounded-full animate-bounce [animation-delay:-0.3s]" />
            <div className="w-1.5 h-1.5 bg-primary rounded-full animate-bounce [animation-delay:-0.15s]" />
            <div className="w-1.5 h-1.5 bg-primary rounded-full animate-bounce" />
          </div>
        )}
        <div ref={messagesEndRef} className="h-4" />
      </div>

      {/* Input Area */}
      <div className="p-6 border-t border-border bg-card/50 backdrop-blur-sm">
        <form onSubmit={handleSubmit} className="relative group">
          <textarea
            rows={1}
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={e => {
              if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault()
                handleSubmit(e)
              }
            }}
            placeholder={selectedNode ? `Query ${selectedNode}...` : "Send a message..."}
            className="
              w-full pl-4 pr-12 py-3 rounded-xl
              bg-muted/50 border border-border
              text-[14px] text-foreground placeholder-muted-foreground/60
              focus:outline-none focus:ring-1 focus:ring-primary/40 focus:border-primary/40
              resize-none transition-all
            "
          />
          <button
            type="submit"
            disabled={isStreaming || !input.trim()}
            className="
              absolute right-2.5 top-2.5 h-8 w-8
              bg-primary text-primary-foreground rounded-lg
              flex items-center justify-center
              disabled:opacity-20 disabled:grayscale transition-all
              hover:shadow-lg hover:shadow-primary/20
            "
          >
            <span className="text-sm font-bold">↑</span>
          </button>
        </form>
        <p className="mt-3 text-[10px] text-center text-muted-foreground/50 uppercase font-bold tracking-tighter">
          Powered by NetAlly Agent Framework v0.1
        </p>
      </div>
    </div>
  )
}
