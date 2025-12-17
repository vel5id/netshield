import { useEffect, useRef } from 'react';
import { translations, Language } from '../translations';

interface LogEntry {
    timestamp: string;
    ip: string;
    country: string;
    asn: string;
    speed: string;
    throttled: boolean;
    threat_score: number;
    signature: string;
}

interface HistoryModalProps {
    isOpen: boolean;
    onClose: () => void;
    logs: LogEntry[];
    theme: 'cyber' | 'forest';
    lang: Language;
}

export function HistoryModal({ isOpen, onClose, logs, theme, lang }: HistoryModalProps) {
    const modalRef = useRef<HTMLDivElement>(null);
    const t = translations[lang];

    // Close on Escape
    useEffect(() => {
        const handleEsc = (e: KeyboardEvent) => {
            if (e.key === 'Escape') onClose();
        };
        if (isOpen) window.addEventListener('keydown', handleEsc);
        return () => window.removeEventListener('keydown', handleEsc);
    }, [isOpen, onClose]);

    // Close on outside click
    const handleBackdrop = (e: React.MouseEvent) => {
        if (e.target === modalRef.current) onClose();
    };

    if (!isOpen) return null;

    return (
        <div
            ref={modalRef}
            onClick={handleBackdrop}
            className="fixed inset-0 z-[1000] flex items-center justify-center bg-black/70 backdrop-blur-sm transition-opacity duration-300"
        >
            <div className="bg-[var(--bg-primary)] border border-[var(--border-primary)] rounded-xl shadow-2xl w-[90vw] max-w-4xl max-h-[80vh] flex flex-col overflow-hidden backdrop-blur-md">
                {/* Header */}
                <div className="flex justify-between items-center p-4 border-b border-[var(--border-primary)] bg-[var(--bg-secondary)]">
                    <h2 className="text-lg font-bold text-[var(--accent-primary)] flex items-center gap-2">
                        <span>📜</span> {t.history.modalTitle}
                    </h2>
                    <button
                        onClick={onClose}
                        className="text-[var(--text-dim)] hover:text-[var(--text-base)] transition-colors text-xl leading-none"
                    >
                        ✕
                    </button>
                </div>

                {/* Table */}
                <div className="flex-1 overflow-auto p-2 bg-[var(--bg-secondary)]/50">
                    <table className="w-full text-xs font-mono">
                        <thead className="sticky top-0 bg-[var(--bg-secondary)] text-[var(--text-dim)] shadow-sm">
                            <tr>
                                <th className="text-left p-2">{t.history.columns.time}</th>
                                <th className="text-left p-2">{t.history.columns.ip}</th>
                                <th className="text-left p-2">{t.history.columns.country}</th>
                                <th className="text-left p-2">{t.history.columns.action}</th>
                                <th className="text-left p-2">{t.history.columns.score}</th>
                                <th className="text-left p-2">{t.history.columns.signature}</th>
                            </tr>
                        </thead>
                        <tbody>
                            {logs.length === 0 ? (
                                <tr>
                                    <td colSpan={6} className="text-center text-[var(--text-dim)] p-8">
                                        {t.history.empty}
                                    </td>
                                </tr>
                            ) : (
                                logs.map((entry, i) => (
                                    <tr
                                        key={`${entry.timestamp}-${i}`}
                                        className="border-b border-[var(--border-primary)] hover:bg-[var(--accent-glow)] transition-colors"
                                    >
                                        <td className="p-2 text-[var(--text-dim)]">{entry.timestamp || '-'}</td>
                                        <td className="p-2 text-[var(--text-base)] font-bold">{entry.ip}</td>
                                        <td className="p-2 text-[var(--text-dim)]">{entry.country || '-'}</td>
                                        <td className="p-2">
                                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${entry.throttled
                                                ? 'bg-red-900/50 text-red-400'
                                                : 'bg-green-900/50 text-green-400'
                                                }`}>
                                                {entry.throttled ? 'THROTTLE' : 'ALLOW'}
                                            </span>
                                        </td>
                                        <td className={`p-2 font-bold ${entry.threat_score > 75 ? 'text-red-500' :
                                            entry.threat_score > 50 ? 'text-yellow-500' : 'text-green-500'
                                            }`}>
                                            {entry.threat_score}
                                        </td>
                                        <td className="p-2 text-[var(--text-dim)] truncate max-w-[150px]" title={entry.signature}>
                                            {entry.signature || '-'}
                                        </td>
                                    </tr>
                                ))
                            )}
                        </tbody>
                    </table>
                </div>

                {/* Footer */}
                <div className="p-3 border-t border-[var(--border-primary)] bg-[var(--bg-secondary)] text-[10px] text-[var(--text-dim)] flex justify-between">
                    <span>{t.history.showingLast} {logs.length} {t.history.entries}</span>
                    <span>{t.history.source}: traffic.csv</span>
                </div>
            </div>
        </div>
    );
}
