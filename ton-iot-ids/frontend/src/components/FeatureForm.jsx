import React, { useState } from 'react';
import axios from 'axios';
import { motion } from 'framer-motion';

const FeatureForm = ({ setRefreshedResult }) => {
    // 36 True Features from ton-iot.csv model
    const [formData, setFormData] = useState({
        src_port: 0, dst_port: 0, proto: 'tcp', service: '-', duration: 0,
        src_bytes: 0, dst_bytes: 0, missed_bytes: 0, src_pkts: 0, src_ip_bytes: 0,
        dst_pkts: 0, dst_ip_bytes: 0, dns_query: '-', dns_qclass: 0, dns_qtype: 0,
        dns_rcode: 0, dns_AA: '-', dns_RD: '-', dns_RA: '-', dns_rejected: '-',
        ssl_version: '-', ssl_cipher: '-', ssl_resumed: '-', ssl_established: '-',
        ssl_subject: '-', ssl_issuer: '-', http_trans_depth: '-', http_method: '-',
        http_uri: '-', http_version: '-', http_request_body_len: 0,
        http_response_body_len: 0, http_user_agent: '-', http_orig_mime_types: '-',
        http_resp_mime_types: '-', weird_addl: '-'
    });

    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);

    const handleChange = (key, value) => {
        // Only parse as float if it's a number, otherwise keep as string (for categoricals)
        const isNumeric = !isNaN(value) && value.toString().trim() !== '';
        setFormData(prev => ({
            ...prev,
            [key]: isNumeric ? parseFloat(value) : value
        }));
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        setError(null);

        try {
            console.log('📤 Sending to backend:', formData);
            const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';
            const response = await axios.post(`${API_URL}/predict`, {
                features: formData
            });
            console.log('📥 Received from backend:', response.data);
            setRefreshedResult(response.data);
        } catch (err) {
            console.error('❌ Error:', err);
            setError(err.response?.data?.detail || err.message || "Failed to predict");
        } finally {
            setLoading(false);
        }
    };

    const featureGroups = {
        "Network": ["src_port", "dst_port", "proto", "service", "duration"],
        "Bytes/Packets": ["src_bytes", "dst_bytes", "missed_bytes", "src_pkts", "src_ip_bytes", "dst_pkts", "dst_ip_bytes"],
        "DNS": ["dns_query", "dns_qclass", "dns_qtype", "dns_rcode", "dns_AA", "dns_RD", "dns_RA", "dns_rejected"],
        "SSL": ["ssl_version", "ssl_cipher", "ssl_resumed", "ssl_established", "ssl_subject", "ssl_issuer"],
        "HTTP/Other": ["http_trans_depth", "http_method", "http_uri", "http_version", "http_request_body_len", "http_response_body_len", "http_user_agent", "http_orig_mime_types", "http_resp_mime_types", "weird_addl"]
    };

    return (
        <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="bg-gradient-to-br from-gray-900 to-gray-800 p-8 rounded-2xl shadow-2xl border border-gray-700 max-h-[85vh] overflow-y-auto custom-scrollbar"
        >
            <h2 className="text-2xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-500 mb-6">
                Network Flow Features
            </h2>
            <p className="text-gray-400 text-xs mb-6 -mt-4">Supply all 36 valid features to match the prediction model exactly.</p>

            <form onSubmit={handleSubmit} className="space-y-6">
                {Object.entries(featureGroups).map(([groupName, features]) => (
                    <div key={groupName} className="space-y-3">
                        <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider border-b border-gray-700 pb-2">
                            {groupName}
                        </h3>
                        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                            {features.map((key) => (
                                <div key={key} className="space-y-1">
                                    <label className="block text-[11px] text-gray-400 truncate" title={key}>{key}</label>
                                    <input
                                        type="text"
                                        value={formData[key]}
                                        onChange={(e) => handleChange(key, e.target.value)}
                                        className="w-full bg-gray-800 border border-gray-600 rounded-lg p-2 text-white text-sm 
                                                 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 outline-none transition-all"
                                    />
                                </div>
                            ))}
                        </div>
                    </div>
                ))}

                {error && (
                    <div className="p-4 bg-red-900/50 border border-red-500 text-red-200 text-sm rounded-lg shadow-inner">
                        <span className="font-bold">Error:</span> {error}
                    </div>
                )}

                <button
                    type="submit"
                    disabled={loading}
                    className="w-full bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 
                             text-white font-bold py-4 px-6 rounded-xl transition-all transform hover:scale-[1.01] 
                             disabled:opacity-50 disabled:cursor-not-allowed shadow-lg"
                >
                    {loading ? (
                        <span className="flex items-center justify-center gap-2">
                            <svg className="animate-spin h-5 w-5" viewBox="0 0 24 24">
                                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none"></circle>
                                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                            </svg>
                            Analyzing Flow...
                        </span>
                    ) : 'PREDICT NETWORK THREAT'}
                </button>
                
                {/* Prefill helper buttons for testing */}
                <div className="flex gap-2 justify-center mt-4">
                    <button type="button" onClick={() => setFormData(p => ({...p, src_port: 80, dst_port: 443, proto: 'tcp', src_bytes: 400, dst_bytes: 5000}))} className="text-xs text-gray-500 hover:text-cyan-400">Normal Sample</button>
                    <button type="button" onClick={() => setFormData(p => ({...p, src_port: 0, dst_port: 0, proto: 'icmp', src_bytes: 99999, dst_bytes: 0}))} className="text-xs text-gray-500 hover:text-red-400">Attack Sample</button>
                </div>
            </form>
        </motion.div>
    );
};

export default FeatureForm;

