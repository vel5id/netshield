import { useState, useEffect, useRef } from 'react'
import { TrafficChart } from './components/TrafficChart'
import { ThreatMap } from './components/ThreatMap'
import { HistoryModal } from './components/HistoryModal'
import { translations, Language } from './translations'

interface TrafficStats {
    udp_packets: number
    tcp_packets: number
    udp_dropped: number
    tcp_dropped: number
    speed_mbps: number
    max_bandwidth_mbps: number
    flood_mode: boolean
}

interface LogEntry {
    timestamp: string
    ip: string
    country: string
    asn: string
    speed: string
    throttled: boolean
    threat_score: number
    signature: string
}

// Temporary mock threats until backend sends real geo data
const MOCK_THREATS = [
    { ip: "45.155.205.101", lat: 52.52, lng: 13.40, country: "DE", score: 90 },
    { ip: "185.220.101.5", lat: 59.93, lng: 30.33, country: "RU", score: 45 },
    { ip: "5.188.62.40", lat: 37.77, lng: -122.41, country: "US", score: 60 },
    { ip: "220.181.38.148", lat: 39.90, lng: 116.40, country: "CN", score: 85 },
    { ip: "89.248.165.1", lat: 51.50, lng: -0.12, country: "UK", score: 70 },
]

function App() {
    const [stats, setStats] = useState<TrafficStats | null>(null)
    const [history, setHistory] = useState<{ time: string, speed: number, udp: number, tcp: number }[]>([])
    const [connected, setConnected] = useState(false)
    const [logs, setLogs] = useState<LogEntry[]>([])
    const [showHistory, setShowHistory] = useState(false)
    const [theme, setTheme] = useState<'cyber' | 'forest'>('cyber')
    const [lang, setLang] = useState<Language>('en')
    const ws = useRef<WebSocket | null>(null)
    const t = translations[lang]

    const toggleTheme = () => {
        setTheme(prev => prev === 'cyber' ? 'forest' : 'cyber')
    }

    const toggleLang = () => {
        setLang(prev => {
            if (prev === 'en') return 'ru'
            if (prev === 'ru') return 'kk'
            return 'en'
        })
    }

    useEffect(() => {
        connect()
        return () => ws.current?.close()
    }, [])

    const connect = () => {
        const socket = new WebSocket('ws://127.0.0.1:8765')

        socket.onopen = () => {
            console.log('Connected to NetShield Engine')
            setConnected(true)
        }

        socket.onclose = () => {
            console.log('Disconnected')
            setConnected(false)
            setTimeout(connect, 2000)
        }

        socket.onmessage = (event) => {
            try {
                const msg = JSON.parse(event.data)
                if (msg.type === 'stats') {
                    const newStats = msg.data as TrafficStats
                    setStats(newStats)

                    // Update History for Graph
                    setHistory(prev => {
                        const now = new Date()
                        const timeStr = `${now.getHours()}:${now.getMinutes()}:${now.getSeconds()}`
                        const point = {
                            time: timeStr,
                            speed: parseFloat(newStats.speed_mbps.toFixed(2)),
                            udp: newStats.udp_packets,
                            tcp: newStats.tcp_packets
                        }
                        const newHistory = [...prev, point]
                        if (newHistory.length > 60) newHistory.shift()
                        return newHistory
                    })
                } else if (msg.type === 'logs') {
                    const entries = msg.data as LogEntry[]
                    if (msg.is_initial) {
                        setLogs(entries)
                    } else {
                        // Merge new entries (dedup by timestamp+ip)
                        setLogs(prev => {
                            const existing = new Set(prev.map(e => `${e.timestamp}-${e.ip}`))
                            const newEntries = entries.filter(e => !existing.has(`${e.timestamp}-${e.ip}`))
                            return [...prev, ...newEntries].slice(-100) // Keep last 100
                        })
                    }
                }
            } catch (e) {
                console.error('Failed to parse WS message', e)
            }
        }

        ws.current = socket
    }

    return (
        <div
            data-theme={theme}
            className="h-screen max-h-screen font-mono border-t-4 flex flex-col overflow-hidden bg-[var(--bg-primary)] border-[var(--border-accent)] text-[var(--text-base)] transition-colors duration-300"
        >
            {/* Title Bar (Fixed Height) */}
            <div className="titlebar-drag h-12 flex-none flex justify-between items-center px-4 bg-[var(--bg-secondary)] border-b border-[var(--border-primary)] select-none z-50 backdrop-blur-md transition-colors duration-300">
                <div className="flex items-center gap-3">
                    <h1 className="text-xl font-bold tracking-wider text-[var(--accent-primary)] flex items-baseline gap-2">
                        {t.appTitle}
                        <span className="text-xs text-[var(--text-dim)] font-normal font-sans tracking-normal opacity-70">by h621</span>
                    </h1>
                    <span className="px-1.5 py-0.5 rounded-md bg-[var(--bg-primary)] border border-[var(--border-primary)] text-[10px] font-bold text-[var(--text-dim)] shadow-sm">v3.0</span>
                </div>
                <div className="flex items-center titlebar-no-drag">
                    <div className={`flex items-center gap-2 px-3 py-1 rounded-full text-[10px] font-bold mr-4 ${connected ? 'bg-green-900/30 text-green-400' : 'bg-red-900/30 text-red-400'}`}>
                        <span className={`w-1.5 h-1.5 rounded-full ${connected ? 'bg-green-500 animate-pulse' : 'bg-red-500'}`}></span>
                        {connected ? t.status.connected : t.status.offline}
                    </div>

                    {/* Lang Toggle */}
                    <button
                        onClick={toggleLang}
                        className="h-8 px-3 mr-2 rounded-lg text-[10px] font-bold uppercase tracking-wider transition-colors bg-[var(--bg-primary)] border border-[var(--border-primary)] text-[var(--text-base)] hover:bg-[var(--accent-glow)]"
                    >
                        {lang === 'en' ? '🇺🇸 EN' : lang === 'ru' ? '🇷🇺 RU' : '🇰🇿 KK'}
                    </button>

                    {/* Theme Toggle */}
                    <button
                        onClick={toggleTheme}
                        className="h-8 px-3 mr-2 rounded-lg text-[10px] font-bold uppercase tracking-wider transition-colors bg-[var(--accent-glow)] text-[var(--accent-primary)] hover:bg-[var(--accent-primary)] hover:text-white"
                    >
                        {theme === 'forest' ? `🌲 ${t.theme.forest}` : `💠 ${t.theme.cyber}`}
                    </button>

                    <div className="flex items-center h-12 border-l border-gray-800">
                        <button
                            onClick={() => window.electron.window.minimize()}
                            className="h-12 w-12 flex items-center justify-center hover:bg-gray-800 text-gray-400 hover:text-white transition-colors"
                        >
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="5" y1="12" x2="19" y2="12"></line></svg>
                        </button>
                        <button
                            onClick={() => window.electron.window.close()}
                            className="h-12 w-12 flex items-center justify-center hover:bg-red-600 text-gray-400 hover:text-white transition-colors"
                        >
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
                        </button>
                    </div>
                </div>
            </div>

            {/* Main Content Area - Vertical Split with 20px GAP/PADDING */}
            <div className="flex-1 flex flex-col min-h-0 overflow-hidden p-[20px] gap-[20px]">

                {/* TOP HEADER: Map (55% Height) - Enclosed in a styled Box */}
                <div className="flex-[55] min-h-0 relative border border-[var(--border-primary)] rounded-xl overflow-hidden bg-[var(--bg-secondary)] shadow-xl flex flex-col backdrop-blur-sm">
                    <div className="absolute top-3 left-4 z-[400] bg-[var(--bg-secondary)] px-3 py-1.5 rounded border border-[var(--border-primary)] backdrop-blur shadow-lg">
                        <h3 className="text-[11px] font-bold uppercase tracking-widest flex items-center gap-2 text-[var(--text-base)]">
                            <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse"></span>
                            {t.map.title}
                        </h3>
                    </div>
                    {/* Map Container - Strictly follows parent size */}
                    <div className="flex-1 w-full relative">
                        <ThreatMap threats={MOCK_THREATS} theme={theme} lang={lang} />
                    </div>
                </div>

                {/* BOTTOM SECTION: Data Split (45% Height) */}
                <div className="flex-[45] min-h-0 flex flex-row gap-[20px]">

                    {/* LEFT: Traffic Chart (70% Width) */}
                    <div className="flex-[7] border border-[var(--border-primary)] bg-[var(--bg-secondary)] rounded-xl p-0.5 flex flex-col shadow-lg overflow-hidden backdrop-blur-sm">
                        <div className="px-4 py-2 border-b border-[var(--border-primary)] bg-[var(--bg-secondary)]">
                            <h3 className="text-[var(--text-dim)] text-[10px] font-bold uppercase tracking-wider">{t.chart.title}</h3>
                        </div>
                        <div className="flex-1 min-h-0 relative">
                            <TrafficChart data={history} theme={theme} lang={lang} />
                        </div>
                    </div>

                    {/* RIGHT: Stats Cards (30% Width) */}
                    <div className="flex-[3] flex flex-col gap-[10px] overflow-y-auto">

                        {/* Speed */}
                        <div className="bg-[var(--bg-secondary)] p-3 rounded-lg border border-[var(--border-primary)] flex flex-col justify-center flex-1 min-h-[70px] backdrop-blur-sm">
                            <h3 className="text-[var(--text-dim)] text-[10px] font-bold uppercase tracking-wider mb-1">{t.chart.bandwidth}</h3>
                            <div className="flex items-end gap-1">
                                <span className="text-xl font-bold text-[var(--accent-primary)] leading-none">{stats ? stats.speed_mbps.toFixed(2) : '0.00'}</span>
                                <span className="text-[10px] text-[var(--text-dim)] mb-0.5">MB/s</span>
                            </div>
                            <div className="w-full bg-gray-700/30 h-1 rounded-full overflow-hidden mt-2">
                                <div
                                    className={`h-full transition-all duration-300 ${stats?.flood_mode ? 'bg-red-500' : 'bg-[var(--accent-primary)]'}`}
                                    style={{ width: `${Math.min(100, ((stats?.speed_mbps || 0) / (stats?.max_bandwidth_mbps || 100)) * 100)}%` }}
                                ></div>
                            </div>
                        </div>

                        {/* Packets */}
                        <div className="bg-[var(--bg-secondary)] p-3 rounded-lg border border-[var(--border-primary)] flex-1 min-h-[70px] flex flex-col justify-center backdrop-blur-sm">
                            <h3 className="text-[var(--text-dim)] text-[10px] font-bold uppercase tracking-wider mb-1">{t.stats.totalPackets}</h3>
                            <div className="text-lg font-bold text-blue-400 leading-none mb-1">
                                {stats ? (stats.udp_packets + stats.tcp_packets).toLocaleString() : '0'}
                            </div>
                            <div className="flex gap-3 text-[10px] text-[var(--text-dim)]">
                                <span>UDP: {stats?.udp_packets}</span>
                                <span>TCP: {stats?.tcp_packets}</span>
                            </div>
                        </div>

                        {/* Blocked */}
                        <div className="bg-[var(--bg-secondary)] p-3 rounded-lg border border-[var(--border-primary)] flex-1 min-h-[70px] flex flex-col justify-center backdrop-blur-sm">
                            <h3 className="text-[var(--text-dim)] text-[10px] font-bold uppercase tracking-wider mb-1">{t.stats.blockedPackets}</h3>
                            <div className="text-lg font-bold text-red-500 leading-none mb-1">
                                {stats ? (stats.udp_dropped + stats.tcp_dropped).toLocaleString() : '0'}
                            </div>
                        </div>

                        {/* History Widget */}
                        <div
                            className="bg-[var(--bg-secondary)] p-3 rounded-lg border border-[var(--border-primary)] flex-1 min-h-[70px] flex flex-col justify-center cursor-pointer hover:bg-[var(--accent-glow)] transition-colors group relative overflow-hidden backdrop-blur-sm"
                            onClick={() => setShowHistory(true)}
                        >
                            <div className="absolute top-0 right-0 p-2 opacity-50 text-[50px] leading-3 text-[var(--text-dim)] group-hover:text-[var(--accent-primary)] pointer-events-none select-none">
                                📜
                            </div>
                            <div className="flex justify-between items-center mb-1 relative z-10">
                                <h3 className="text-[var(--text-dim)] text-[10px] font-bold uppercase tracking-wider">{t.history.title}</h3>
                                <span className="text-[9px] text-[var(--accent-primary)] opacity-0 group-hover:opacity-100 transition-opacity">{t.history.viewAll}</span>
                            </div>
                            <div className="relative z-10">
                                <div className={`text-[11px] font-mono text-[var(--text-base)] truncate border-l-2 pl-2 mb-1 ${logs.length > 0 && logs[logs.length - 1].throttled ? 'border-red-500' : 'border-green-500'}`}>
                                    {logs.length > 0 ? (
                                        <>{logs[logs.length - 1].throttled ? 'THROTTLE' : 'ALLOW'} <span className="text-[var(--text-dim)]">{logs[logs.length - 1].ip}</span></>
                                    ) : (
                                        <>{t.widget.noData} <span className="text-[var(--text-dim)]">—</span></>
                                    )}
                                </div>
                                <div className="text-[9px] text-[var(--text-dim)] pl-2">
                                    {logs.length > 0 ? `Last: ${logs[logs.length - 1].timestamp}` : t.widget.waiting}
                                </div>
                            </div>
                        </div>

                    </div>
                </div>
            </div>
            {/* History Modal */}
            <HistoryModal
                isOpen={showHistory}
                onClose={() => setShowHistory(false)}
                logs={logs}
                theme={theme}
                lang={lang}
            />
        </div>
    )
}

export default App
