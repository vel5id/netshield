import { MapContainer, TileLayer, CircleMarker, Popup } from 'react-leaflet';
import 'leaflet/dist/leaflet.css';

interface ThreatLocation {
    ip: string;
    lat: number;
    lng: number;
    country: string;
    score: number;
}

interface ThreatMapProps {
    threats: ThreatLocation[];
    theme: 'cyber' | 'forest';
}

export function ThreatMap({ threats, theme }: ThreatMapProps) {
    return (
        <div className="h-full w-full bg-[var(--bg-secondary)] rounded-lg overflow-hidden relative z-0">
            <MapContainer
                center={[20, 0]}
                zoom={2}
                style={{ height: '100%', width: '100%' }}
                scrollWheelZoom={true}
                zoomControl={false}
                className="z-0"
            >
                {/* Switch Tiles based on Theme */}
                <TileLayer
                    attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>'
                    url={theme === 'forest'
                        ? "https://{s}.basemaps.cartocdn.com/rastertiles/voyager/{z}/{x}/{y}{r}.png" // Light colorful map
                        : "https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png" // Dark matter
                    }
                />

                {threats.map((t) => (
                    <CircleMarker
                        key={t.ip}
                        center={[t.lat, t.lng]}
                        radius={8}
                        pathOptions={{
                            color: t.score > 75 ? '#ef4444' : '#eab308',
                            fillColor: t.score > 75 ? '#ef4444' : '#eab308',
                            fillOpacity: 0.8,
                            weight: 2,
                            className: t.score > 75 ? 'threat-pulse-red' : 'threat-pulse-yellow'
                        }}
                    >
                        <Popup>
                            <div className="font-mono text-sm">
                                <div className="font-bold text-gray-900">{t.ip}</div>
                                <div className="text-xs text-gray-600">{t.country}</div>
                                <div className={`text-xs font-bold mt-1 ${t.score > 80 ? 'text-red-600' : 'text-yellow-600'}`}>
                                    Threat Score: {t.score}
                                </div>
                            </div>
                        </Popup>
                    </CircleMarker>
                ))}
            </MapContainer>
        </div>
    );
}
