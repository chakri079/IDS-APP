
import { useState } from 'react'
import './App.css'
import FeatureForm from './components/FeatureForm';
import RiskDisplay from './components/RiskDisplay';

function App() {
  const [result, setResult] = useState(null);

  return (
    <div className="min-h-screen bg-gray-950 text-white p-4 md:p-10 font-sans">
      <header className="mb-10 flex items-center justify-between border-b border-gray-800 pb-4">
        <div>
          <h1 className="text-3xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-cyan-400 to-blue-600">
            TON-IoT
          </h1>
          <p className="text-gray-500 text-sm">Intrusion Detection System</p>
        </div>
        <div className="flex items-center space-x-2">
          <div className="h-2 w-2 rounded-full bg-green-500 animate-pulse"></div>
          <span className="text-xs text-green-500 font-mono">SYSTEM ACTIVE</span>
        </div>
      </header>

      <main className="max-w-6xl mx-auto grid grid-cols-1 lg:grid-cols-2 gap-8">
        <div className="w-full">
          <FeatureForm setRefreshedResult={setResult} />
        </div>

        <div className="w-full">
          {result && <RiskDisplay result={result} />}
          {!result && (
            <div className="h-full flex flex-col items-center justify-center text-gray-500 border border-gray-800 rounded-lg p-10 bg-gray-900/30">
              <div className="text-4xl mb-4 grayscale opacity-50">🛡️</div>
              <p>Waiting for analysis...</p>
            </div>
          )}
        </div>
      </main>

      <footer className="mt-20 text-center text-gray-600 text-xs border-t border-gray-900 pt-6">
        <p>TON-IoT IDS Demo | CNN-BiLSTM Model | Leakage-Free Inference</p>
      </footer>
    </div>
  )
}

export default App
