import React, { useState } from 'react';
import './App.css';

function App() {
  const [url, setUrl] = useState('');
  const [scanResults, setScanResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleScan = async () => {
    // Reset states before starting a new scan
    setLoading(true);
    setError(null);
    setScanResults(null);
    
    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url }),
      });

      // Check if response is OK before attempting to parse JSON
      if (!response.ok) {
        // Try to parse error as JSON, but handle cases where it might not be JSON
        let errorMessage = `HTTP error! status: ${response.status}`;
        try {
          const errorData = await response.json();
          if (errorData.detail) {
            errorMessage += `, details: ${errorData.detail}`;
          }
        } catch (jsonError) {
          // If error response isn't valid JSON, use status text
          errorMessage += `, message: ${response.statusText}`;
        }
        throw new Error(errorMessage);
      }

      const data = await response.json();
      setScanResults(data);
    } catch (e) {
      setError(e.message);
      console.error("Scan error:", e);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="App">
      <h1>Project Nightingale - Vulnerability Scanner</h1>
      <div className="input-area">
        <input
          type="text"
          placeholder="Enter URL to scan"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
        />
        <button onClick={handleScan} disabled={loading || !url.trim()}>
          {loading ? 'Scanning...' : 'Scan URL'}
        </button>
      </div>

      {error && <div className="error">Error: {error}</div>}

      {loading && <div className="loading">Scanning in progress, please wait...</div>}

      {scanResults && (
        <div className="results">
          <h2>Scan Results for: {scanResults.url}</h2>
          {scanResults.results && scanResults.results.length === 0 ? (
            <div className="no-vulnerabilities">No vulnerabilities found.</div>
          ) : scanResults.results && scanResults.results.length > 0 ? (
            <ul className="results-list">
              {scanResults.results.map((result, index) => (
                <li key={index} className={`result-item severity-${result.severity}`}>
                  <h3>{result.test_name}</h3>
                  <p><strong>Severity:</strong> {result.severity}</p>
                  <p><strong>Description:</strong> {result.description}</p>
                  <p><strong>Recommendation:</strong> {result.recommendation}</p>
                  {result.details && Object.keys(result.details).length > 0 && (
                    <details>
                      <summary>Technical Details</summary>
                      <pre>{JSON.stringify(result.details, null, 2)}</pre>
                    </details>
                  )}
                </li>
              ))}
            </ul>
          ) : (
            <div className="error">Invalid results format received from server.</div>
          )}
        </div>
      )}
    </div>
  );
}

export default App;