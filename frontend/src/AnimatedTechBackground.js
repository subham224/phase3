// frontend/src/AnimatedPacketFlow.js
import React, { useMemo } from 'react';
import { motion } from 'framer-motion';
import './AnimatedTechBackground.css';

// --- Configuration ---
const NUM_LANES = 25; // Number of horizontal traffic lanes
const PACKETS_PER_LANE = 3; // Max concurrent packets per lane

export default function AnimatedTechBackground() {
    return (
        <div className="packet-flow-container">
            {/* Layer 0: Film grain / Noise texture for a tactile screen feel */}
            <div className="noise-overlay" />
            
            {/* Layer 1: Ambient deep glow (very subtle) */}
            <div className="ambient-teal-glow" />

            {/* Layer 2: Traffic Lanes */}
            <div className="lanes-container">
                {Array.from({ length: NUM_LANES }).map((_, i) => (
                    <TrafficLane key={`lane-${i}`} laneIndex={i} />
                ))}
            </div>
        </div>
    );
}

// --- Sub-Components ---

function TrafficLane({ laneIndex }) {
    // Distribute lanes evenly across the vertical space
    const topPosition = `${(laneIndex / NUM_LANES) * 100}%`;
    const laneOpacity = useMemo(() => Math.random() * 0.05 + 0.02, []); // Barely visible tracks

    return (
        <div className="traffic-lane" style={{ top: topPosition }}>
            <div className="lane-track" style={{ opacity: laneOpacity }} />
            
            {Array.from({ length: PACKETS_PER_LANE }).map((_, i) => (
                <Packet key={`packet-${laneIndex}-${i}`} />
            ))}
        </div>
    );
}

function Packet() {
    // Generate static random properties so they don't shift on re-renders
    const duration = useMemo(() => Math.random() * 15 + 10, []); // 10s to 25s (Slow, analytical speed)
    const delay = useMemo(() => Math.random() * 20, []); // Random start time stagger
    const width = useMemo(() => Math.random() * 40 + 5, []); // 5px to 45px long
    const isAnomaly = useMemo(() => Math.random() > 0.92, []); // 8% chance to be an anomaly (Amber)
    const direction = useMemo(() => Math.random() > 0.5 ? 1 : -1, []); // Left-to-right or Right-to-left

    // Jitter effect for anomalies
    const jitterY = isAnomaly ? [0, -1, 1, -0.5, 0.5, 0] : [0, 0];
    const jitterOpacity = isAnomaly ? [0.8, 0.4, 1, 0.6, 0.9] : [0.3, 0.6, 0.3];

    return (
        <motion.div
            className={`packet ${isAnomaly ? 'packet-anomaly' : 'packet-standard'}`}
            style={{ 
                width: `${width}px`,
                // Start completely off-screen
                left: direction === 1 ? '-5%' : '105%' 
            }}
            animate={{
                left: direction === 1 ? '105%' : '-5%',
                y: jitterY,
                opacity: jitterOpacity,
            }}
            transition={{
                left: {
                    duration: duration,
                    repeat: Infinity,
                    ease: "linear",
                    delay: delay,
                },
                y: {
                    duration: 0.2,
                    repeat: Infinity,
                    repeatType: "mirror",
                    ease: "linear"
                },
                opacity: {
                    duration: duration / 3, // Pulse opacity slowly as it moves
                    repeat: Infinity,
                    ease: "easeInOut"
                }
            }}
        />
    );
}