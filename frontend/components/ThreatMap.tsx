"use client";

import React, { useEffect, useState } from "react";
import { ComposableMap, Geographies, Geography, Marker } from "react-simple-maps";

interface GeoIP {
  query: string;
  status: string;
  country: string;
  countryCode: string;
  regionName: string;
  city: string;
  lat: number;
  lon: number;
}

export default function ThreatMap({ ips }: { ips: string[] }) {
  const [locations, setLocations] = useState<GeoIP[]>([]);
  const [loading, setLoading] = useState(false);
  const geoUrl = "/india-states.json";

  useEffect(() => {
    if (!ips || ips.length === 0) {
      setLocations([]);
      return;
    }

    const fetchLocations = async () => {
      setLoading(true);
      try {
        const res = await fetch("/api/geoip", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ ips })
        });
        const data = await res.json();
        // Filter out IPs that failed or have no coordinates
        setLocations(data.filter((d: GeoIP) => d.status === "success" && d.lat && d.lon));
      } catch (err) {
        console.error("Failed to fetch geo IP", err);
      } finally {
        setLoading(false);
      }
    };

    fetchLocations();
  }, [ips]);

  // Handle case where we might not have IPs yet
  if (!ips || ips.length === 0) {
    return null; // Do not render the map if no dangerous IPs are found
  }

  return (
    <div className="card-surface p-6 rounded-2xl space-y-4 relative overflow-hidden" style={{ minHeight: "450px" }}>
      <div className="flex items-center justify-between z-10 relative">
        <h2 className="font-semibold text-slate-200 text-sm">Dynamic C2 Infrastructure Map</h2>
        <span className="text-[10px] text-rose-400 bg-rose-500/10 px-2 py-1 rounded border border-rose-500/20 font-bold">
          {ips.length} Dangerous IPs Detected
        </span>
      </div>

      {loading && (
        <div className="absolute inset-0 flex items-center justify-center bg-slate-900/50 z-20 backdrop-blur-sm">
          <div className="animate-spin w-6 h-6 border-2 border-rose-500 border-t-transparent rounded-full" />
        </div>
      )}

      <div className="w-full h-full relative flex items-center justify-center" style={{ height: "400px" }}>
        <ComposableMap
          projection="geoMercator"
          projectionConfig={{
            scale: 1000,
            center: [82, 22] // Centered on India
          }}
          style={{ width: "100%", height: "100%" }}
        >
          <Geographies geography={geoUrl}>
            {({ geographies }) =>
              geographies.map((geo) => (
                <Geography
                  key={geo.rsmKey}
                  geography={geo}
                  fill="#1e293b" // slate-800
                  stroke="#334155" // slate-700
                  strokeWidth={0.5}
                  style={{
                    default: { outline: "none" },
                    hover: { fill: "#334155", outline: "none" },
                    pressed: { outline: "none" },
                  }}
                />
              ))
            }
          </Geographies>

          {locations.map((loc, idx) => (
            <Marker key={`${loc.query}-${idx}`} coordinates={[loc.lon, loc.lat]}>
              <g
                fill="none"
                stroke="#f43f5e" // rose-500
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
                transform="translate(-12, -24)"
                className="group cursor-pointer"
              >
                <circle cx="12" cy="10" r="3" fill="#f43f5e" />
                <path d="M12 21.7C17.3 17 20 13 20 10a8 8 0 1 0-16 0c0 3 2.7 6.9 8 11.7z" />
                
                {/* Tooltip on hover */}
                <foreignObject x="-60" y="-45" width="150" height="40" className="opacity-0 group-hover:opacity-100 transition-opacity">
                  <div className="bg-slate-900 border border-rose-500/30 text-[10px] p-1.5 rounded text-slate-200 shadow-xl whitespace-nowrap text-center">
                    <p className="font-mono text-rose-400 font-bold">{loc.query}</p>
                    <p>{loc.city}, {loc.countryCode === 'IN' ? loc.regionName : loc.country}</p>
                  </div>
                </foreignObject>
              </g>
              
              {/* Radar pulse effect */}
              <circle r="8" fill="#f43f5e" className="animate-ping opacity-75" />
            </Marker>
          ))}
        </ComposableMap>
      </div>
    </div>
  );
}
