#!/usr/bin/env node
// Simple test client to trigger login flow

const net = require('net');

const client = new net.Socket();

client.connect(8080, 'localhost', () => {
    console.log('[TEST] Connected to C++ server');
    
    // Wait a bit then send choice (1 = Login)
    setTimeout(() => {
        console.log('[TEST] Sending choice: 1 (Login)');
        client.write('1\n');
    }, 100);
    
    // Send username
    setTimeout(() => {
        console.log('[TEST] Sending username: alice');
        client.write('alice\n');
    }, 200);
    
    // Send password
    setTimeout(() => {
        console.log('[TEST] Sending password: alice123');
        client.write('alice123\n');
    }, 300);
    
    // Wait for response then close
    setTimeout(() => {
        console.log('[TEST] Closing connection');
        client.end();
    }, 1000);
});

client.on('data', (data) => {
    console.log('[TEST] Received from server:\n', data.toString());
});

client.on('end', () => {
    console.log('[TEST] Connection ended');
    process.exit(0);
});

client.on('error', (err) => {
    console.error('[TEST] Error:', err.message);
    process.exit(1);
});
