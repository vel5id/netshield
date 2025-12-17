import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { translations, Language } from '../translations';

interface TrafficData {
    time: string;
    speed: number;
    udp: number;
    tcp: number;
}

interface TrafficChartProps {
    data: TrafficData[];
    theme: 'cyber' | 'forest';
    lang: Language;
}

export function TrafficChart({ data, theme, lang }: TrafficChartProps) {
    const t = translations[lang];

    // Colors based on theme
    const gridColor = theme === 'forest' ? '#d1fae5' : '#374151'; // emerald-100 vs gray-700
    const textColor = theme === 'forest' ? '#065f46' : '#9ca3af'; // emerald-800 vs gray-400
    const tooltipBg = theme === 'forest' ? 'rgba(255, 255, 255, 0.95)' : 'rgba(17, 24, 39, 0.9)';
    const tooltipBorder = theme === 'forest' ? '#10b981' : '#0891b2'; // emerald-500 vs cyan-600
    const tooltipText = theme === 'forest' ? '#064e3b' : '#fff';
    const strokeColor = theme === 'forest' ? '#059669' : '#06b6d4';
    const gradientTop = theme === 'forest' ? '#10b981' : '#06b6d4';

    return (
        <div className="h-full w-full">
            <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={data}>
                    <defs>
                        <linearGradient id="colorSpeed" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor={gradientTop} stopOpacity={0.8} />
                            <stop offset="95%" stopColor={gradientTop} stopOpacity={0} />
                        </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke={gridColor} vertical={false} />
                    <XAxis
                        dataKey="time"
                        stroke={textColor}
                        fontSize={10}
                        tickLine={false}
                        axisLine={false}
                    />
                    <YAxis
                        stroke={textColor}
                        fontSize={10}
                        tickLine={false}
                        axisLine={false}
                        tickFormatter={(value) => `${value}M`}
                    />
                    <Tooltip
                        contentStyle={{
                            backgroundColor: tooltipBg,
                            borderColor: tooltipBorder,
                            color: tooltipText,
                            fontSize: '12px'
                        }}
                        itemStyle={{ color: tooltipText }}
                        labelStyle={{ color: tooltipText, marginBottom: '4px' }}
                    />
                    <Area
                        type="monotone"
                        dataKey="speed"
                        name={t.chart.bandwidth}
                        stroke={strokeColor}
                        fillOpacity={1}
                        fill="url(#colorSpeed)"
                        isAnimationActive={false}
                    />
                </AreaChart>
            </ResponsiveContainer>
        </div>
    );
}
