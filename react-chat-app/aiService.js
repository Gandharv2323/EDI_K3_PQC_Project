import 'dotenv/config';
import https from 'https';

/**
 * AI Chatbot Service
 * Supports Google Gemini and OpenRouter APIs
 */

const AI_PROVIDER = process.env.AI_PROVIDER || 'gemini';
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const GEMINI_MODEL = process.env.GEMINI_MODEL || 'gemini-1.5-flash';
const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY;
const OPENROUTER_MODEL = process.env.OPENROUTER_MODEL || 'meta-llama/llama-3.2-3b-instruct:free';

/**
 * Check if AI is enabled
 * @returns {boolean}
 */
export function isAIEnabled() {
    if (AI_PROVIDER === 'gemini') {
        return GEMINI_API_KEY && GEMINI_API_KEY !== 'your-gemini-api-key-here';
    } else if (AI_PROVIDER === 'openrouter') {
        return OPENROUTER_API_KEY && OPENROUTER_API_KEY !== 'your-openrouter-api-key-here';
    }
    return false;
}

/**
 * Make HTTPS request
 */
function makeHttpsRequest(options, postData) {
    return new Promise((resolve, reject) => {
        const req = https.request(options, (res) => {
            let data = '';
            
            res.on('data', (chunk) => {
                data += chunk;
            });
            
            res.on('end', () => {
                if (res.statusCode >= 200 && res.statusCode < 300) {
                    try {
                        resolve(JSON.parse(data));
                    } catch (error) {
                        reject(new Error('Failed to parse response: ' + data));
                    }
                } else {
                    reject(new Error(`HTTP ${res.statusCode}: ${data}`));
                }
            });
        });
        
        req.on('error', (error) => {
            reject(error);
        });
        
        if (postData) {
            req.write(postData);
        }
        
        req.end();
    });
}

/**
 * Call Google Gemini API
 */
async function callGeminiAPI(message, conversationHistory = []) {
    if (!GEMINI_API_KEY || GEMINI_API_KEY === 'your-gemini-api-key-here') {
        throw new Error('Gemini API key not configured. Please set GEMINI_API_KEY in .env file');
    }

    // Use the configured Gemini model
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent?key=${GEMINI_API_KEY}`;
    const urlObj = new URL(url);

    console.log(`[AI] Using Gemini model: ${GEMINI_MODEL}`);

    // Build conversation context
    let fullPrompt = '';
    if (conversationHistory.length > 0) {
        fullPrompt = conversationHistory.map(msg => 
            `${msg.role === 'user' ? 'User' : 'Assistant'}: ${msg.content}`
        ).join('\n') + '\n';
    }
    fullPrompt += `User: ${message}`;

    const postData = JSON.stringify({
        contents: [{
            parts: [{
                text: fullPrompt
            }]
        }],
        generationConfig: {
            temperature: 0.7,
            topK: 40,
            topP: 0.95,
            maxOutputTokens: 8192,
        }
    });

    const options = {
        hostname: urlObj.hostname,
        path: urlObj.pathname + urlObj.search,
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(postData)
        }
    };

    try {
        const response = await makeHttpsRequest(options, postData);
        
        if (response.candidates && response.candidates.length > 0) {
            const content = response.candidates[0].content;
            if (content && content.parts && content.parts.length > 0) {
                return content.parts[0].text;
            }
        }
        
        throw new Error('No valid response from Gemini');
    } catch (error) {
        console.error('[AI] Gemini API error:', error);
        throw error;
    }
}

/**
 * Call OpenRouter API
 */
async function callOpenRouterAPI(message, conversationHistory = []) {
    if (!OPENROUTER_API_KEY || OPENROUTER_API_KEY === 'your-openrouter-api-key-here') {
        throw new Error('OpenRouter API key not configured. Please set OPENROUTER_API_KEY in .env file');
    }

    console.log(`[AI] Using OpenRouter model: ${OPENROUTER_MODEL}`);

    // Build messages array
    const messages = [
        {
            role: 'system',
            content: 'You are a helpful AI assistant in a chat application. Be concise and friendly.'
        },
        ...conversationHistory,
        {
            role: 'user',
            content: message
        }
    ];

    const postData = JSON.stringify({
        model: OPENROUTER_MODEL,
        messages: messages,
        temperature: 0.7,
        max_tokens: 1000
    });

    const options = {
        hostname: 'openrouter.ai',
        path: '/api/v1/chat/completions',
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${OPENROUTER_API_KEY}`,
            'HTTP-Referer': 'http://localhost:5000',
            'X-Title': 'SecureChatServer',
            'Content-Length': Buffer.byteLength(postData)
        }
    };

    try {
        const response = await makeHttpsRequest(options, postData);
        
        if (response.choices && response.choices.length > 0) {
            return response.choices[0].message.content;
        }
        
        throw new Error('No valid response from OpenRouter');
    } catch (error) {
        console.error('[AI] OpenRouter API error:', error);
        throw error;
    }
}

/**
 * Get AI response
 * @param {string} message - User message
 * @param {Array} conversationHistory - Previous conversation messages
 * @returns {Promise<string>} - AI response
 */
export async function getAIResponse(message, conversationHistory = []) {
    if (!isAIEnabled()) {
        throw new Error('AI service is not configured');
    }

    try {
        console.log(`[AI] Getting response from ${AI_PROVIDER} for: ${message.substring(0, 50)}...`);
        
        if (AI_PROVIDER === 'gemini') {
            return await callGeminiAPI(message, conversationHistory);
        } else if (AI_PROVIDER === 'openrouter') {
            return await callOpenRouterAPI(message, conversationHistory);
        }
        
        throw new Error(`Unsupported AI provider: ${AI_PROVIDER}`);
    } catch (error) {
        console.error('[AI] Error getting response:', error);
        throw error;
    }
}

export { AI_PROVIDER, GEMINI_MODEL, OPENROUTER_MODEL };
