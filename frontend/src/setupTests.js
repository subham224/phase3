// src/setupTests.js
// jest-dom adds custom jest matchers for asserting on DOM nodes.
import '@testing-library/jest-dom';

// Polyfill for jsPDF / TextEncoder issue in Jest
import { TextEncoder, TextDecoder } from 'util';

Object.assign(global, { TextDecoder, TextEncoder });

// Ignore jsPDF console warnings during tests (optional, keeps terminal clean)
window.URL.createObjectURL = function() {};