import { createClient } from '@supabase/supabase-js';

// Supabase configuration
// Replace these with your actual Supabase project credentials
const SUPABASE_URL = process.env.SUPABASE_URL || 'https://pxtaieunnwfnrbfcdvjl.supabase.co';
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InB4dGFpZXVubndmbnJiZmNkdmpsIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjE5Mjg0NDcsImV4cCI6MjA3NzUwNDQ0N30.QHFUXu_wIE7YflyhnwRufVwMpuTabbcT0WlDM11ousk';

// Create Supabase client
const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

/**
 * Save a message to Supabase
 * @param {Object} messageData - Message data to save
 * @returns {Promise<Object>} - Saved message data
 */
export async function saveMessage(messageData) {
    try {
        const { data, error } = await supabase
            .from('chat_history')
            .insert([
                {
                    sender: messageData.sender,
                    recipient: messageData.recipient,
                    message: messageData.message,
                    message_type: messageData.messageType, // 'private' or 'broadcast'
                    timestamp: new Date().toISOString(),
                    is_read: false
                }
            ])
            .select();

        if (error) {
            console.error('[SUPABASE] Error saving message:', error);
            throw error;
        }

        console.log('[SUPABASE] Message saved:', data[0].id);
        return data[0];
    } catch (error) {
        console.error('[SUPABASE] Failed to save message:', error);
        throw error;
    }
}

/**
 * Get chat history between two users
 * @param {string} user1 - First user
 * @param {string} user2 - Second user
 * @param {number} limit - Maximum number of messages to retrieve
 * @returns {Promise<Array>} - Array of messages
 */
export async function getChatHistory(user1, user2, limit = 100) {
    try {
        const { data, error } = await supabase
            .from('chat_history')
            .select('*')
            .eq('message_type', 'private')
            .or(`and(sender.eq.${user1},recipient.eq.${user2}),and(sender.eq.${user2},recipient.eq.${user1})`)
            .order('timestamp', { ascending: true })
            .limit(limit);

        if (error) {
            console.error('[SUPABASE] Error fetching chat history:', error);
            throw error;
        }

        console.log(`[SUPABASE] Fetched ${data.length} messages between ${user1} and ${user2}`);
        return data;
    } catch (error) {
        console.error('[SUPABASE] Failed to fetch chat history:', error);
        throw error;
    }
}

/**
 * Get broadcast message history
 * @param {number} limit - Maximum number of messages to retrieve
 * @returns {Promise<Array>} - Array of broadcast messages
 */
export async function getBroadcastHistory(limit = 100) {
    try {
        const { data, error } = await supabase
            .from('chat_history')
            .select('*')
            .eq('message_type', 'broadcast')
            .order('timestamp', { ascending: true })
            .limit(limit);

        if (error) {
            console.error('[SUPABASE] Error fetching broadcast history:', error);
            throw error;
        }

        console.log(`[SUPABASE] Fetched ${data.length} broadcast messages`);
        return data;
    } catch (error) {
        console.error('[SUPABASE] Failed to fetch broadcast history:', error);
        throw error;
    }
}

/**
 * Mark messages as read
 * @param {string} sender - Sender username
 * @param {string} recipient - Recipient username
 * @returns {Promise<void>}
 */
export async function markMessagesAsRead(sender, recipient) {
    try {
        const { error } = await supabase
            .from('chat_history')
            .update({ is_read: true })
            .eq('sender', sender)
            .eq('recipient', recipient)
            .eq('is_read', false);

        if (error) {
            console.error('[SUPABASE] Error marking messages as read:', error);
            throw error;
        }

        console.log(`[SUPABASE] Marked messages from ${sender} to ${recipient} as read`);
    } catch (error) {
        console.error('[SUPABASE] Failed to mark messages as read:', error);
        throw error;
    }
}

/**
 * Get unread message count for a user
 * @param {string} recipient - Recipient username
 * @returns {Promise<number>} - Count of unread messages
 */
export async function getUnreadCount(recipient) {
    try {
        const { count, error } = await supabase
            .from('chat_history')
            .select('*', { count: 'exact', head: true })
            .eq('recipient', recipient)
            .eq('is_read', false);

        if (error) {
            console.error('[SUPABASE] Error getting unread count:', error);
            throw error;
        }

        return count || 0;
    } catch (error) {
        console.error('[SUPABASE] Failed to get unread count:', error);
        return 0;
    }
}

/**
 * Get unread message count by sender
 * @param {string} recipient - Recipient username
 * @returns {Promise<Object>} - Object with sender usernames as keys and counts as values
 */
export async function getUnreadCountBySender(recipient) {
    try {
        const { data, error } = await supabase
            .from('chat_history')
            .select('sender')
            .eq('recipient', recipient)
            .eq('is_read', false)
            .eq('message_type', 'private');

        if (error) {
            console.error('[SUPABASE] Error getting unread count by sender:', error);
            throw error;
        }

        // Count messages by sender
        const counts = {};
        data.forEach(msg => {
            counts[msg.sender] = (counts[msg.sender] || 0) + 1;
        });

        return counts;
    } catch (error) {
        console.error('[SUPABASE] Failed to get unread count by sender:', error);
        return {};
    }
}

/**
 * Delete a message
 * @param {number} messageId - Message ID to delete
 * @returns {Promise<void>}
 */
export async function deleteMessage(messageId) {
    try {
        const { error } = await supabase
            .from('chat_history')
            .delete()
            .eq('id', messageId);

        if (error) {
            console.error('[SUPABASE] Error deleting message:', error);
            throw error;
        }

        console.log(`[SUPABASE] Deleted message ${messageId}`);
    } catch (error) {
        console.error('[SUPABASE] Failed to delete message:', error);
        throw error;
    }
}

export default supabase;
