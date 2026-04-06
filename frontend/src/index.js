import React from 'react';
import ReactDOM from 'react-dom/client'; // Using createRoot for React 18+
import App from './App'; // Import your consolidated App.js

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);