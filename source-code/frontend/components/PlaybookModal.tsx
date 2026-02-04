import { useState, useEffect } from 'react'
import { X, Play, Clock } from 'lucide-react'
import { Playbook } from '../utils/playbooks'

interface PlaybookModalProps {
    isOpen: boolean
    onClose: () => void
    playbook: Playbook | null
    onMitigate: () => void
}

export default function PlaybookModal({ isOpen, onClose, playbook, onMitigate }: PlaybookModalProps) {
    const [completedSteps, setCompletedSteps] = useState<number[]>([])

    // Reset state when playbook changes or modal opens
    useEffect(() => {
        if (isOpen) {
            setCompletedSteps([])
        }
    }, [isOpen, playbook])

    const toggleStep = (order: number) => {
        setCompletedSteps(prev =>
            prev.includes(order)
                ? prev.filter(o => o !== order)
                : [...prev, order]
        )
    }

    if (!isOpen || !playbook) return null

    const manualSteps = playbook ? playbook.steps.filter(s => s.action_type === 'manual') : [];
    const allManualStepsCompleted = manualSteps.every(s => completedSteps.includes(s.order));

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 backdrop-blur-sm p-4">
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl w-full max-w-4xl max-h-[90vh] flex flex-col border border-gray-200 dark:border-gray-700">
                {/* Header */}
                <div className="flex items-center justify-between p-6 border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-900 rounded-t-lg shrink-0">
                    <div className="flex items-center gap-4">
                        <div className="flex h-12 w-12 flex-shrink-0 items-center justify-center rounded-full bg-blue-100 dark:bg-blue-900">
                            <Play className="h-6 w-6 text-blue-600 dark:text-blue-200" />
                        </div>
                        <div>
                            <h2 className="text-xl font-bold text-gray-900 dark:text-white flex items-center gap-2">
                                {playbook.name}
                                <span className="inline-flex items-center rounded-md bg-blue-50 dark:bg-blue-900 px-2 py-1 text-xs font-medium text-blue-700 dark:text-blue-100 ring-1 ring-inset ring-blue-700/10 dark:ring-blue-100/10">
                                    v{playbook.version}
                                </span>
                            </h2>
                            <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                                {playbook.description}
                            </p>
                        </div>
                    </div>
                    <button
                        onClick={onClose}
                        className="text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200 transition-colors"
                    >
                        <X className="w-6 h-6" />
                    </button>
                </div>

                {/* Content */}
                <div className="overflow-y-auto p-6">
                    <div className="flow-root">
                        <ul role="list" className="-mb-8">
                            {playbook.steps.map((step, stepIdx) => {
                                const isCompleted = completedSteps.includes(step.order);
                                return (
                                    <li key={step.order}>
                                        <div className="relative pb-8">
                                            {stepIdx !== playbook.steps.length - 1 ? (
                                                <span className="absolute left-4 top-4 -ml-px h-full w-0.5 bg-gray-200 dark:bg-gray-700" aria-hidden="true" />
                                            ) : null}
                                            <div className={`relative flex space-x-3 rounded-lg p-2 transition-colors ${isCompleted ? 'bg-gray-100 dark:bg-gray-700/50' : ''}`}>
                                                <div className="flex h-8 w-8 items-center justify-center rounded-full bg-white dark:bg-gray-800 ring-4 ring-white dark:ring-gray-800 shrink-0">
                                                    <span className={`flex h-8 w-8 items-center justify-center rounded-full text-sm font-medium ${isCompleted ? 'bg-green-100 dark:bg-green-900 text-green-600 dark:text-green-300' : 'bg-gray-100 dark:bg-gray-700 text-gray-500 dark:text-gray-300'}`}>
                                                        {step.order}
                                                    </span>
                                                </div>
                                                <div className="flex min-w-0 flex-1 justify-between space-x-4 pt-1.5">
                                                    <div>
                                                        <p className={`text-sm font-semibold ${isCompleted ? 'text-gray-500 dark:text-gray-400 line-through' : 'text-gray-900 dark:text-white'}`}>
                                                            {step.name}
                                                            {step.required && <span className="ml-2 text-red-500 text-xs no-underline decoration-0">*Required</span>}
                                                        </p>
                                                        <p className="text-sm text-gray-500 dark:text-gray-400">{step.description}</p>
                                                        {step.automation_script && (
                                                            <p className="mt-1 text-xs text-indigo-600 dark:text-indigo-400 font-mono bg-indigo-50 dark:bg-indigo-900/30 px-2 py-1 rounded inline-block">
                                                                Script: {step.automation_script}
                                                            </p>
                                                        )}
                                                    </div>
                                                    <div className="whitespace-nowrap text-right text-sm text-gray-500 dark:text-gray-400 flex flex-col items-end gap-2">
                                                        <div className="flex items-center gap-1 justify-end">
                                                            <Clock className="h-4 w-4" />
                                                            <span>{step.timeout_minutes}m</span>
                                                        </div>
                                                        <div className="mt-1 flex items-center gap-2">
                                                            <span className={`inline-flex items-center rounded-md px-1.5 py-0.5 text-xs font-medium ring-1 ring-inset ${step.action_type === 'automated'
                                                                ? 'bg-green-50 text-green-700 ring-green-600/20 dark:bg-green-900/30 dark:text-green-400 dark:ring-green-500/20'
                                                                : 'bg-yellow-50 text-yellow-700 ring-yellow-600/20 dark:bg-yellow-900/30 dark:text-yellow-400 dark:ring-yellow-500/20'
                                                                }`}>
                                                                {step.action_type}
                                                            </span>
                                                            {step.action_type === 'manual' && (
                                                                <input
                                                                    type="checkbox"
                                                                    checked={isCompleted}
                                                                    onChange={(e) => {
                                                                        e.stopPropagation();
                                                                        toggleStep(step.order);
                                                                    }}
                                                                    className="h-4 w-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-600 cursor-pointer"
                                                                />
                                                            )}
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    </li>
                                );
                            })}
                        </ul>
                    </div>
                </div>

                <div className="bg-gray-50 dark:bg-gray-700/50 px-6 py-4 rounded-b-lg flex justify-end gap-3 shrink-0">
                    <button
                        type="button"
                        className="inline-flex w-full justify-center rounded-md bg-white dark:bg-gray-800 px-3 py-2 text-sm font-semibold text-gray-900 dark:text-white shadow-sm ring-1 ring-inset ring-gray-300 dark:ring-gray-600 hover:bg-gray-50 dark:hover:bg-gray-700 sm:mt-0 sm:w-auto"
                        onClick={onClose}
                    >
                        Close
                    </button>
                    <button
                        type="button"
                        disabled={!allManualStepsCompleted}
                        className={`inline-flex w-full justify-center rounded-md px-3 py-2 text-sm font-semibold text-white shadow-sm sm:w-auto ${allManualStepsCompleted
                            ? 'bg-green-600 hover:bg-green-500'
                            : 'bg-gray-400 cursor-not-allowed opacity-50'
                            }`}
                        onClick={onMitigate}
                    >
                        Mitigate Risk
                    </button>
                </div>
            </div>
        </div>
    )
}
