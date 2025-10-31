
"use client";

import { useState } from 'react';
import VulnerabilityCard from './VulnerabilityCard';

interface Finding {
  id: string;
  title: string;
  severity: 'High' | 'Medium' | 'Low';
  description: string;
  details: string;
  recommendation: string;
}

export default function Home() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [error, setError] = useState<string | null>(null);

  const handleScan = async () => {
    setLoading(true);
    setFindings([]);
    setError(null);

    try {
      const response = await fetch('/api/passive-scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Something went wrong');
      }

      const data = await response.json();
      setFindings(data);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="bg-gray-900 text-white min-h-screen p-8">
      <header className="text-center mb-12">
        <h1 className="text-5xl font-bold mb-2">Vulnerability Scanner</h1>
        <p className="text-gray-400">Your advanced security analysis tool</p>
      </header>

      <main className="max-w-4xl mx-auto">
        <div className="bg-gray-800 p-6 rounded-lg shadow-lg mb-8">
          <div className="flex space-x-4">
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="Enter URL to scan..."
              className="flex-grow bg-gray-700 text-white rounded-md p-3 focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
            <button
              onClick={handleScan}
              disabled={loading}
              className="bg-blue-600 hover:bg-blue-700 text-white font-bold py-3 px-6 rounded-md transition-colors disabled:bg-gray-500"
            >
              {loading ? 'Scanning...' : 'Scan'}
            </button>
          </div>
        </div>

        {loading && (
          <div className="text-center">
            <p className="text-lg">Scanning in progress...</p>
            {/* You could add a spinner here */}
          </div>
        )}

        {error && (
          <div className="bg-red-800 border border-red-500 text-white p-4 rounded-md text-center">
            <p><strong>Error:</strong> {error}</p>
          </div>
        )}

        <div className="space-y-6">
          {findings.length > 0 && (
            <div className="bg-gray-800 p-6 rounded-lg shadow-lg">
              <h2 className="text-2xl font-bold mb-4">Passive Scan Results</h2>
              {findings.map((finding) => (
                <VulnerabilityCard key={finding.id} {...finding} />
              ))}
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
