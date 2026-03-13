'use client'

import React from 'react'
import { X, Shield, Search, Database, Briefcase, Activity } from 'lucide-react'

interface AgentMessage {
    agent: 'analyst' | 'intel' | 'forensics' | 'business' | 'response'
    message: string
    timestamp: string
}

interface AgentDiscussionModalProps {
    isOpen: boolean
    onClose: () => void
    riskName: string
    messages: AgentMessage[]
    isLoading: boolean
}

export default function AgentDiscussionModal({
    isOpen,
    onClose,
    riskName,
    messages,
    isLoading
}: AgentDiscussionModalProps) {
    const [displayedMessages, setDisplayedMessages] = React.useState<AgentMessage[]>([])
    const [typingAgent, setTypingAgent] = React.useState<string | null>(null)
    const messagesEndRef = React.useRef<HTMLDivElement>(null)

    // Reset conversation when modal opens or messages change
    React.useEffect(() => {
        if (isOpen && messages.length > 0) {
            setDisplayedMessages([])
            processMessages(messages)
        }
    }, [isOpen, messages])

    // Auto-scroll to bottom
    React.useEffect(() => {
        messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
    }, [displayedMessages, typingAgent])

    const processMessages = async (allMessages: AgentMessage[]) => {
        for (let i = 0; i < allMessages.length; i++) {
            // Set typing indicator for the next agent
            setTypingAgent(allMessages[i].agent)

            // Wait for a simulated typing duration (e.g. 1.5s to 3s)
            await new Promise(resolve => setTimeout(resolve, 2000))

            // Add message
            setDisplayedMessages(prev => [...prev, allMessages[i]])
            setTypingAgent(null) // Stop typing briefly

            // Small pause before next typing starts (unless it's the last one)
            if (i < allMessages.length - 1) {
                await new Promise(resolve => setTimeout(resolve, 500))
            }
        }
    }

    if (!isOpen) return null

    const getAgentColor = (agent: string) => {
        switch (agent) {
            case 'analyst': return 'bg-blue-100 text-blue-800 border-blue-200'
            case 'intel': return 'bg-purple-100 text-purple-800 border-purple-200'
            case 'forensics': return 'bg-orange-100 text-orange-800 border-orange-200'
            case 'business': return 'bg-green-100 text-green-800 border-green-200'
            case 'response': return 'bg-red-100 text-red-800 border-red-200'
            default: return 'bg-gray-100 text-gray-800 border-gray-200'
        }
    }

    const getAgentIcon = (agent: string) => {
        switch (agent) {
            case 'analyst': return <Shield className="w-4 h-4" />
            case 'intel': return <Search className="w-4 h-4" />
            case 'forensics': return <Database className="w-4 h-4" />
            case 'business': return <Briefcase className="w-4 h-4" />
            case 'response': return <Activity className="w-4 h-4" />
            default: return <Shield className="w-4 h-4" />
        }
    }

    const getAgentName = (agent: string) => {
        return agent.charAt(0).toUpperCase() + agent.slice(1)
    }

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 backdrop-blur-sm">
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl w-full max-w-3xl max-h-[80vh] flex flex-col m-4 border border-gray-200 dark:border-gray-700">
                {/* Header */}
                <div className="flex items-center justify-between p-4 border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-900 rounded-t-lg">
                    <div>
                        <h2 className="text-xl font-bold text-gray-900 dark:text-white flex items-center gap-2">
                            <Shield className="w-5 h-5 text-primary" />
                            Agent Discussion
                        </h2>
                        <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                            Analyzing: <span className="font-medium text-gray-900 dark:text-white">{riskName}</span>
                        </p>
                    </div>
                    <button
                        onClick={onClose}
                        className="text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200 transition-colors"
                    >
                        <X className="w-6 h-6" />
                    </button>
                </div>

                {/* Content */}
                <div className="flex-1 overflow-y-auto p-6 space-y-6 bg-gray-50/50 dark:bg-gray-900/50">
                    {isLoading ? (
                        <div className="flex flex-col items-center justify-center py-12 space-y-4">
                            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
                            <p className="text-gray-500 dark:text-gray-400 animate-pulse">Initializing Multi-Agent Swarm...</p>
                            <div className="flex space-x-2">
                                <span className="w-3 h-3 bg-blue-400 rounded-full animate-bounce" style={{ animationDelay: '0ms' }}></span>
                                <span className="w-3 h-3 bg-purple-400 rounded-full animate-bounce" style={{ animationDelay: '150ms' }}></span>
                                <span className="w-3 h-3 bg-orange-400 rounded-full animate-bounce" style={{ animationDelay: '300ms' }}></span>
                                <span className="w-3 h-3 bg-green-400 rounded-full animate-bounce" style={{ animationDelay: '450ms' }}></span>
                            </div>
                        </div>
                    ) : (
                        <div className="space-y-4">
                            {displayedMessages.map((msg, index) => (
                                <div key={index} className="flex gap-4 animate-slideUp fade-in">
                                    <div className={`flex items-center justify-center w-8 h-8 rounded-full shrink-0 ${msg.agent === 'analyst' ? 'bg-blue-100 text-blue-600' :
                                        msg.agent === 'intel' ? 'bg-purple-100 text-purple-600' :
                                            msg.agent === 'forensics' ? 'bg-orange-100 text-orange-600' :
                                                msg.agent === 'business' ? 'bg-green-100 text-green-600' :
                                                    'bg-red-100 text-red-600'
                                        }`}>
                                        {getAgentIcon(msg.agent)}
                                    </div>
                                    <div className={`flex-1 rounded-lg p-4 border ${getAgentColor(msg.agent)}`}>
                                        <div className="flex items-center justify-between mb-2">
                                            <span className="font-bold text-sm uppercase tracking-wider">{getAgentName(msg.agent)} Agent</span>
                                            <div className="flex items-center gap-2">
                                                <span className="text-xs opacity-75">{msg.timestamp}</span>
                                            </div>
                                        </div>
                                        <p className="text-sm leading-relaxed whitespace-pre-wrap">{msg.message}</p>
                                    </div>
                                </div>
                            ))}

                            {typingAgent && (
                                <div className="flex gap-4 animate-pulse">
                                    <div className={`flex items-center justify-center w-8 h-8 rounded-full shrink-0 bg-gray-200 text-gray-500`}>
                                        {getAgentIcon(typingAgent)}
                                    </div>
                                    <div className="flex items-center p-3 rounded-lg border border-gray-200 bg-white dark:bg-gray-800">
                                        <span className="text-xs text-gray-500 mr-2">{getAgentName(typingAgent)} is typing</span>
                                        <div className="flex space-x-1">
                                            <div className="w-1.5 h-1.5 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '0ms' }} />
                                            <div className="w-1.5 h-1.5 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '150ms' }} />
                                            <div className="w-1.5 h-1.5 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '300ms' }} />
                                        </div>
                                    </div>
                                </div>
                            )}
                            <div ref={messagesEndRef} />
                        </div>
                    )}
                </div>

                {/* Footer */}
                <div className="p-4 border-t border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 rounded-b-lg flex justify-between items-center bg-opacity-50">
                    <div className="flex space-x-4 text-xs text-gray-500">
                        <div className="flex items-center"><span className="w-2 h-2 bg-blue-500 rounded-full mr-1"></span>Analyst</div>
                        <div className="flex items-center"><span className="w-2 h-2 bg-purple-500 rounded-full mr-1"></span>Intel</div>
                        <div className="flex items-center"><span className="w-2 h-2 bg-orange-500 rounded-full mr-1"></span>Forensics</div>
                        <div className="flex items-center"><span className="w-2 h-2 bg-green-500 rounded-full mr-1"></span>Business</div>
                    </div>
                </div>
            </div>
        </div>
    )
}
