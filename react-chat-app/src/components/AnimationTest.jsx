import React, { useState } from 'react';
import { LoadingSpinner, SuccessAnimation } from './Common';
import './Common/AnimationComponents.css';

/**
 * Simple Test Component
 * Add this to your App.jsx to test animations quickly
 */
const AnimationTest = () => {
    const [showSuccess, setShowSuccess] = useState(false);

    return (
        <div style={{ 
            padding: '40px',
            textAlign: 'center',
            fontFamily: 'Arial, sans-serif'
        }}>
            <h1>✨ Animation Test</h1>
            <p>Your Lottie animations are working!</p>

            <div style={{ 
                display: 'flex', 
                flexDirection: 'column',
                gap: '40px',
                marginTop: '40px',
                alignItems: 'center'
            }}>
                {/* Loading Spinner */}
                <div>
                    <h3>Loading Spinner</h3>
                    <LoadingSpinner size={80} message="Loading..." />
                </div>

                {/* Success Animation */}
                <div>
                    <h3>Success Animation</h3>
                    {!showSuccess ? (
                        <button 
                            onClick={() => setShowSuccess(true)}
                            style={{
                                padding: '12px 24px',
                                fontSize: '16px',
                                background: '#007bff',
                                color: 'white',
                                border: 'none',
                                borderRadius: '8px',
                                cursor: 'pointer'
                            }}
                        >
                            Show Success
                        </button>
                    ) : (
                        <div>
                            <SuccessAnimation 
                                size={100} 
                                message="Success!" 
                                onComplete={() => {
                                    console.log('Animation completed!');
                                    setTimeout(() => setShowSuccess(false), 1000);
                                }}
                            />
                        </div>
                    )}
                </div>

                {/* Info */}
                <div style={{ 
                    marginTop: '20px',
                    padding: '20px',
                    background: '#f0f8ff',
                    borderRadius: '8px',
                    maxWidth: '500px'
                }}>
                    <p style={{ margin: 0, lineHeight: 1.6 }}>
                        ✅ Animations are working!<br/>
                        📚 Check <code>ANIMATIONS_QUICK_START.md</code> to learn more<br/>
                        🎨 View <code>AnimationShowcase</code> for all components
                    </p>
                </div>
            </div>
        </div>
    );
};

export default AnimationTest;
