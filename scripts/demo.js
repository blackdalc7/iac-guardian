#!/usr/bin/env node
'use strict';

// Starts the agent in demo mode without needing a shell that understands
// inline environment variables (works the same on Windows, macOS and Linux).
process.env.GUARDIAN_DEMO = '1';
require('../src/server.js');
