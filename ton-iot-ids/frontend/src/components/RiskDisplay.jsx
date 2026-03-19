import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';

// Colour map for each threat type
const THREAT_COLORS = {
    normal: { border: 'border-green-500', bg: 'from-green-900/20 to-green-950/10', text: 'text-green-400', bar: 'bg-green-500' },
    backdoor: { border: 'border-red-600', bg: 'from-red-900/30 to-red-950/10', text: 'text-red-400', bar: 'bg-red-600' },
    ddos: { border: 'border-orange-500', bg: 'from-orange-900/20 to-orange-950/10', text: 'text-orange-400', bar: 'bg-orange-500' },
    dos: { border: 'border-orange-500', bg: 'from-orange-900/20 to-orange-950/10', text: 'text-orange-400', bar: 'bg-orange-500' },
    injection: { border: 'border-red-500', bg: 'from-red-900/25 to-red-950/10', text: 'text-red-400', bar: 'bg-red-500' },
    mitm: { border: 'border-purple-500', bg: 'from-purple-900/20 to-purple-950/10', text: 'text-purple-400', bar: 'bg-purple-500' },
    password: { border: 'border-yellow-500', bg: 'from-yellow-900/20 to-yellow-950/10', text: 'text-yellow-400', bar: 'bg-yellow-500' },
    ransomware: { border: 'border-red-600', bg: 'from-red-900/30 to-red-950/10', text: 'text-red-400', bar: 'bg-red-600' },
    scanning: { border: 'border-blue-500', bg: 'from-blue-900/20 to-blue-950/10', text: 'text-blue-400', bar: 'bg-blue-500' },
    xss: { border: 'border-pink-500', bg: 'from-pink-900/20 to-pink-950/10', text: 'text-pink-400', bar: 'bg-pink-500' },
};

const SEVERITY_BADGE = {
    None: 'bg-green-700 text-green-100',
    Low: 'bg-blue-700 text-blue-100',
    Medium: 'bg-yellow-600 text-yellow-100',
    High: 'bg-orange-600 text-orange-100',
    Critical: 'bg-red-700 text-red-100',
    Unknown: 'bg-gray-700 text-gray-100',
};

const RiskDisplay = ({ result }) => {
    const [showAllProbs, setShowAllProbs] = useState(false);
    const [precautions, setPrecautions] = useState('');
    const [loadingPrecautions, setLoadingPrecautions] = useState(false);

    React.useEffect(() => {
        setPrecautions('');
    }, [result]);

    const fetchPrecautions = async (threatType) => {
        setLoadingPrecautions(true);
        try {
            const res = await fetch('http://localhost:8000/precautions', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ threat_type: threatType })
            });
            const data = await res.json();
            setPrecautions(data.precautions);
        } catch (e) {
            setPrecautions('Failed to load precautions.');
        } finally {
            setLoadingPrecautions(false);
        }
    };

    if (!result) {
        return (
            <div className="h-full flex flex-col items-center justify-center text-gray-500 border-2 border-dashed border-gray-800 rounded-2xl p-10 bg-gray-900/30">
                <div className="text-6xl mb-4 opacity-50">🛡️</div>
                <p className="text-lg">Awaiting prediction...</p>
                <p className="text-sm text-gray-600 mt-2">Enter feature values and click Predict</p>
            </div>
        );
    }

    const {
        prediction,
        threat_type = 'unknown',
        threat_icon = '⚠️',
        threat_description = '',
        severity = 'Unknown',
        probability,
        risk_level,
        class_probabilities = {},
    } = result;

    const isAttack = prediction === 'Attack';
    const typeKey = (threat_type || 'normal').toLowerCase();
    const colors = THREAT_COLORS[typeKey] || THREAT_COLORS['normal'];

    // Sort class probabilities for display
    const sortedProbs = Object.entries(class_probabilities)
        .sort(([, a], [, b]) => b - a);

    const topProbs = sortedProbs.slice(0, 3);
    const extraProbs = sortedProbs.slice(3);

    return (
        <motion.div
            initial={{ scale: 0.95, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            className={`h-full flex flex-col p-6 rounded-2xl border-2 ${colors.border} bg-gradient-to-br ${colors.bg} relative overflow-hidden shadow-2xl`}
        >
            {/* Pulsing background glow */}
            <div className={`absolute inset-0 opacity-5 ${isAttack ? 'bg-red-600' : 'bg-green-600'} animate-pulse`}></div>

            <div className="relative z-10 space-y-5">

                {/* ── Header ── */}
                <div className="text-center space-y-1">
                    <div className={`inline-flex items-center justify-center w-20 h-20 rounded-full ${isAttack ? 'bg-red-500/20' : 'bg-green-500/20'} mb-2`}>
                        <span className="text-4xl">{threat_icon}</span>
                    </div>

                    <p className="text-gray-400 uppercase tracking-widest text-xs font-semibold">Prediction</p>

                    <h1 className={`text-4xl font-black ${colors.text} tracking-tight`}>
                        {prediction.toUpperCase()}
                    </h1>

                    {/* Threat type badge */}
                    <div className="flex items-center justify-center gap-2 mt-1">
                        <span className={`px-3 py-1 rounded-full text-sm font-bold uppercase tracking-wide ${isAttack ? 'bg-red-600/30 text-red-300 border border-red-500/40' : 'bg-green-600/30 text-green-300 border border-green-500/40'}`}>
                            {threat_type}
                        </span>
                        <span className={`px-2 py-1 rounded text-xs font-bold ${SEVERITY_BADGE[severity] || SEVERITY_BADGE['Unknown']}`}>
                            {severity}
                        </span>
                    </div>

                    {threat_description && (
                        <p className="text-gray-400 text-xs mt-2 max-w-xs mx-auto">{threat_description}</p>
                    )}
                </div>

                {/* ── Metrics row ── */}
                <div className="grid grid-cols-2 gap-4 pt-4 border-t border-gray-700/60">
                    {/* Confidence */}
                    <div className="text-center space-y-1">
                        <p className="text-gray-500 text-xs uppercase font-semibold">Confidence</p>
                        <div className="overflow-hidden h-2 rounded bg-gray-700 mt-1">
                            <motion.div
                                initial={{ width: 0 }}
                                animate={{ width: `${probability * 100}%` }}
                                transition={{ duration: 0.6, ease: 'easeOut' }}
                                className={`h-full ${colors.bar}`}
                            />
                        </div>
                        <p className="text-2xl font-bold text-white">{(probability * 100).toFixed(1)}%</p>
                    </div>

                    {/* Risk level */}
                    <div className="text-center space-y-1">
                        <p className="text-gray-500 text-xs uppercase font-semibold">Risk Level</p>
                        <span className={`inline-block px-4 py-2 rounded-lg text-sm font-bold mt-2
                            ${risk_level === 'Critical' ? 'bg-red-700 text-white' :
                                risk_level === 'High' ? 'bg-orange-600 text-white' :
                                    risk_level === 'Medium' ? 'bg-yellow-600 text-white' :
                                        risk_level === 'Low' ? 'bg-blue-600 text-white' :
                                            'bg-green-700 text-white'}`}>
                            {risk_level}
                        </span>
                    </div>
                </div>

                {/* ── Top 3 class probabilities ── */}
                {sortedProbs.length > 0 && (
                    <div className="pt-4 border-t border-gray-700/60 space-y-2">
                        <p className="text-gray-500 text-xs uppercase font-semibold">Top Threat Probabilities</p>
                        {topProbs.map(([cls, prob]) => {
                            const clsColors = THREAT_COLORS[cls] || THREAT_COLORS['normal'];
                            return (
                                <div key={cls} className="flex items-center gap-2">
                                    <span className={`text-xs font-semibold w-20 text-right capitalize ${clsColors.text}`}>{cls}</span>
                                    <div className="flex-1 h-2 bg-gray-800 rounded overflow-hidden">
                                        <motion.div
                                            initial={{ width: 0 }}
                                            animate={{ width: `${prob * 100}%` }}
                                            transition={{ duration: 0.5, delay: 0.1 }}
                                            className={`h-full ${clsColors.bar}`}
                                        />
                                    </div>
                                    <span className="text-xs text-gray-400 w-10 text-right">{(prob * 100).toFixed(1)}%</span>
                                </div>
                            );
                        })}

                        {/* Toggle extra probabilities */}
                        {extraProbs.length > 0 && (
                            <button
                                onClick={() => setShowAllProbs(v => !v)}
                                className="text-xs text-gray-500 hover:text-gray-300 transition-colors mt-1 underline"
                            >
                                {showAllProbs ? 'Show less ▲' : `Show all ${sortedProbs.length} classes ▼`}
                            </button>
                        )}

                        <AnimatePresence>
                            {showAllProbs && extraProbs.map(([cls, prob]) => {
                                const clsColors = THREAT_COLORS[cls] || THREAT_COLORS['normal'];
                                return (
                                    <motion.div
                                        key={cls}
                                        initial={{ opacity: 0, height: 0 }}
                                        animate={{ opacity: 1, height: 'auto' }}
                                        exit={{ opacity: 0, height: 0 }}
                                        className="flex items-center gap-2"
                                    >
                                        <span className={`text-xs font-semibold w-20 text-right capitalize ${clsColors.text}`}>{cls}</span>
                                        <div className="flex-1 h-2 bg-gray-800 rounded overflow-hidden">
                                            <div style={{ width: `${prob * 100}%` }} className={`h-full ${clsColors.bar}`} />
                                        </div>
                                        <span className="text-xs text-gray-400 w-10 text-right">{(prob * 100).toFixed(1)}%</span>
                                    </motion.div>
                                );
                            })}
                        </AnimatePresence>
                    </div>
                )}

                {/* ── Attack warning banner ── */}
                {isAttack && (
                    <div className="p-3 bg-red-950/50 border border-red-800 rounded-lg">
                        <div className="flex items-start gap-3">
                            <span className="text-xl">🚨</span>
                            <div>
                                <p className="text-red-300 font-semibold text-sm">Threat Detected: {threat_type.toUpperCase()}</p>
                                <p className="text-red-400 text-xs mt-0.5">Immediate investigation recommended</p>
                            </div>
                        </div>

                        <div className="mt-4 border-t border-red-800/50 pt-3">
                            {!precautions ? (
                                <button
                                    onClick={() => fetchPrecautions(threat_type)}
                                    disabled={loadingPrecautions}
                                    className="px-4 py-2 bg-gradient-to-r from-red-800 to-red-600 hover:from-red-700 hover:to-red-500 text-white rounded-lg text-xs font-bold transition-all shadow-md flex items-center justify-center gap-2 w-full disabled:opacity-50"
                                >
                                    {loadingPrecautions ? (
                                        <span className="animate-pulse">🤖 Consulting AI...</span>
                                    ) : (
                                        <span>⚡ Get AI Precautions via Gemini</span>
                                    )}
                                </button>
                            ) : (
                                <div className="bg-black/40 p-3 rounded-lg text-sm text-red-200 mt-2">
                                    <p className="font-bold text-red-400 mb-2 flex items-center gap-2">
                                        <span className="text-lg">🤖</span> Mitigations
                                    </p>
                                    <div className="whitespace-pre-wrap leading-relaxed space-y-2">
                                        {precautions}
                                    </div>
                                </div>
                            )}
                        </div>
                    </div>
                )}
            </div>
        </motion.div>
    );
};

export default RiskDisplay;
