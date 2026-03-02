// frontend/src/AnimatedTechBackground.js
import React, { useMemo, useRef, useEffect } from 'react';
import { motion, useScroll, useTransform, useSpring, useMotionValue, useMotionTemplate } from 'framer-motion';
import './AnimatedTechBackground.css';

// --- Configuration ---
const ASSETS_BASE_URL = 'https://raw.githubusercontent.com/sayed-imran/portfolio/main/public/logos';

const LOGO_DATA = [
    // Center / Hero Logos (High Clarity)
    { src: `${ASSETS_BASE_URL}/google-cloud-icon-2048x1646-7admxejz.png`, alt: 'GCP', scale: 180, x: -15, y: -10, z: 10, rotate: 0 },
    { src: `${ASSETS_BASE_URL}/Kubernetes_logo_without_workmark.svg.png`, alt: 'K8s', scale: 160, x: 15, y: -10, z: 10, rotate: 0 },
    { src: `${ASSETS_BASE_URL}/Amazon_Web_Services_Logo.svg.png`, alt: 'AWS', scale: 160, x: 0, y: 15, z: 10, rotate: 0 },
    
    // Mid-Layer Logos
    { src: `${ASSETS_BASE_URL}/docker-mark-blue.png`, alt: 'Docker', scale: 140, x: 35, y: -35, z: 5, rotate: 15 },
    { src: `${ASSETS_BASE_URL}/azure.png`, alt: 'Azure', scale: 130, x: -35, y: -30, z: 5, rotate: -15 },
    { src: `${ASSETS_BASE_URL}/github-logo.png`, alt: 'GitHub', scale: 120, x: 25, y: 35, z: 5, rotate: 10 },
    
    // Background Logos
    { src: `${ASSETS_BASE_URL}/Linux.png`, alt: 'Linux', scale: 100, x: -45, y: 40, z: 1, rotate: -10 },
    { src: `${ASSETS_BASE_URL}/Jenkins_logo.svg.png`, alt: 'Jenkins', scale: 90, x: 45, y: 10, z: 1, rotate: 20 },
    { src: `${ASSETS_BASE_URL}/istio-logo-icon-342x512-gh5boo0w.png`, alt: 'Istio', scale: 80, x: -50, y: -10, z: 1, rotate: -25 },
];

export default function AnimatedTechBackground() {
    const containerRef = useRef(null);
    
    // 1. Scroll Motion Hooks
    const { scrollY } = useScroll();
    const smoothScrollY = useSpring(scrollY, { stiffness: 60, damping: 20, restDelta: 0.001 });

    // 2. Mouse Motion Hooks (For 3D Parallax)
    const mouseX = useMotionValue(0);
    const mouseY = useMotionValue(0);
    const smoothMouseX = useSpring(mouseX, { stiffness: 50, damping: 20 });
    const smoothMouseY = useSpring(mouseY, { stiffness: 50, damping: 20 });

    useEffect(() => {
        const handleMouseMove = (e) => {
            const { innerWidth, innerHeight } = window;
            const x = (e.clientX / innerWidth) * 2 - 1;
            const y = (e.clientY / innerHeight) * 2 - 1;
            mouseX.set(x);
            mouseY.set(y);
        };
        
        window.addEventListener('mousemove', handleMouseMove);
        return () => window.removeEventListener('mousemove', handleMouseMove);
    }, [mouseX, mouseY]);

    return (
        <div ref={containerRef} className="tech-bg-container">
            {/* Layer 0: Background Gradient Mesh */}
            <div className="tech-bg-gradient-purple" />
            <div className="tech-bg-gradient-cyan" />
            <div className="tech-bg-grid" />

            {/* Layer 1: Particles */}
            {Array.from({ length: 20 }).map((_, i) => (
                <Particle 
                    key={`particle-${i}`} 
                    scrollY={smoothScrollY} 
                    mouseX={smoothMouseX}
                    mouseY={smoothMouseY}
                />
            ))}

            {/* Layer 2: Logos */}
            {LOGO_DATA.map((logo, index) => (
                <FloatingLogo 
                    key={logo.alt} 
                    data={logo} 
                    index={index} 
                    scrollY={smoothScrollY}
                    mouseX={smoothMouseX}
                    mouseY={smoothMouseY}
                />
            ))}
        </div>
    );
}

// --- Sub-Components ---

function FloatingLogo({ data, index, scrollY, mouseX, mouseY }) {
    const yTransform = useTransform(scrollY, [0, 2000], [0, -300 * (1 + data.z * 0.1)]);
    const rotateTransform = useTransform(scrollY, [0, 2000], [data.rotate, data.rotate + 45]);
    
    const xParallax = useTransform(mouseX, [-1, 1], [-30 * data.z * 0.2, 30 * data.z * 0.2]);
    const yParallax = useTransform(mouseY, [-1, 1], [-30 * data.z * 0.2, 30 * data.z * 0.2]);

    const blurValue = data.z < 10 ? 'blur(1px)' : 'blur(0px)';
    const opacityValue = data.z < 10 ? 0.6 : 1;

    return (
        <motion.div
            className="tech-logo-container"
            style={{
                left: `${50 + data.x}%`,
                top: `${50 + data.y}%`,
                x: xParallax,
                y: useMotionTemplate`calc(${yTransform}px + ${yParallax}px)`,
                rotate: rotateTransform,
                zIndex: Math.floor(data.z),
                filter: blurValue,
                opacity: opacityValue,
            }}
            initial={{ opacity: 0, scale: 0 }}
            animate={{ 
                opacity: opacityValue, 
                scale: 1,
                y: [0, -15, 0],
            }}
            transition={{
                opacity: { duration: 1.5, delay: index * 0.1 },
                scale: { duration: 1.5, type: 'spring', delay: index * 0.1 },
                y: { duration: 4 + Math.random() * 2, repeat: Infinity, ease: "easeInOut", delay: Math.random() * 2 }
            }}
        >
            <img
                src={data.src}
                alt={data.alt}
                width={data.scale}
                height={data.scale}
                className="tech-logo-image"
            />
        </motion.div>
    );
}

function Particle({ scrollY, mouseX, mouseY }) {
    const xPos = useMemo(() => Math.random() * 100, []);
    const yPos = useMemo(() => Math.random() * 100, []);
    const size = useMemo(() => Math.random() * 4 + 2, []);
    const depth = useMemo(() => Math.random() * 2 + 0.5, []);

    const yTransform = useTransform(scrollY, [0, 1000], [0, -100 * depth]);
    const xParallax = useTransform(mouseX, [-1, 1], [-20 * depth, 20 * depth]);
    const yParallax = useTransform(mouseY, [-1, 1], [-20 * depth, 20 * depth]);

    return (
        <motion.div
            className="tech-particle"
            style={{
                left: `${xPos}%`,
                top: `${yPos}%`,
                width: size,
                height: size,
                opacity: 0.1 * depth,
                x: xParallax,
                y: useMotionTemplate`calc(${yTransform}px + ${yParallax}px)`,
            }}
            animate={{
                opacity: [0.1 * depth, 0.4 * depth, 0.1 * depth],
                scale: [1, 1.5, 1],
            }}
            transition={{
                duration: Math.random() * 3 + 2,
                repeat: Infinity,
                delay: Math.random() * 2,
            }}
        />
    );
}