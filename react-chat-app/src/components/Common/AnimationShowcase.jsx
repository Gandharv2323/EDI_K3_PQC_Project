import React, { useState } from 'react';
import {
    LoadingSpinner,
    SuccessAnimation,
    TypingAnimation,
    ControllableAnimation,
    HoverAnimation,
    ScrollAnimation,
    ClickAnimation,
    ProgressAnimation,
    SegmentedAnimation,
    BackgroundAnimation
} from './AnimationComponents';
import './AnimationComponents.css';
import loadingAnimation from '../../animations/loading.json';
import successAnimation from '../../animations/success.json';
import typingAnimation from '../../animations/typing.json';

/**
 * Animation Showcase Component
 * Demonstrates all available animation components
 */
const AnimationShowcase = () => {
    const [progress, setProgress] = useState(0);
    const [currentSegment, setCurrentSegment] = useState(0);

    // Simulate progress
    const simulateProgress = () => {
        setProgress(0);
        const interval = setInterval(() => {
            setProgress(prev => {
                if (prev >= 100) {
                    clearInterval(interval);
                    return 100;
                }
                return prev + 5;
            });
        }, 200);
    };

    const segments = [
        [0, 30],
        [31, 60],
        [61, 90]
    ];

    return (
        <div style={{ padding: '40px', maxWidth: '1200px', margin: '0 auto' }}>
            <h1 style={{ textAlign: 'center', marginBottom: '40px' }}>
                Lottie Animation Components Showcase
            </h1>

            {/* Loading Spinner */}
            <section style={{ marginBottom: '60px' }}>
                <h2>1. Loading Spinner</h2>
                <p>Perfect for loading states, data fetching, page transitions</p>
                <div style={{ display: 'flex', gap: '40px', flexWrap: 'wrap', marginTop: '20px' }}>
                    <LoadingSpinner size={80} message="Loading..." />
                    <LoadingSpinner size={60} message="Please wait..." />
                    <LoadingSpinner size={100} showMessage={false} />
                </div>
            </section>

            {/* Success Animation */}
            <section style={{ marginBottom: '60px' }}>
                <h2>2. Success Animation</h2>
                <p>Use for successful operations, confirmations</p>
                <div style={{ display: 'flex', gap: '40px', flexWrap: 'wrap', marginTop: '20px' }}>
                    <SuccessAnimation size={100} message="Success!" />
                    <SuccessAnimation 
                        size={80} 
                        message="Message Sent!" 
                        onComplete={() => console.log('Animation completed!')}
                    />
                </div>
            </section>

            {/* Typing Indicator */}
            <section style={{ marginBottom: '60px' }}>
                <h2>3. Typing Indicator</h2>
                <p>Shows when someone is typing in chat</p>
                <div style={{ marginTop: '20px' }}>
                    <TypingAnimation userName="John" size={50} />
                    <div style={{ marginTop: '10px' }}>
                        <TypingAnimation userName="Sarah" size={60} />
                    </div>
                </div>
            </section>

            {/* Controllable Animation */}
            <section style={{ marginBottom: '60px' }}>
                <h2>4. Controllable Animation</h2>
                <p>Full control with play, pause, stop, and restart</p>
                <div style={{ marginTop: '20px' }}>
                    <ControllableAnimation 
                        animationData={loadingAnimation}
                        size={150}
                        speed={1}
                    />
                </div>
            </section>

            {/* Hover Animation */}
            <section style={{ marginBottom: '60px' }}>
                <h2>5. Hover Animation</h2>
                <p>Animation plays on mouse hover</p>
                <div style={{ display: 'flex', gap: '20px', marginTop: '20px' }}>
                    <div style={{ textAlign: 'center' }}>
                        <p>Hover me!</p>
                        <HoverAnimation 
                            animationData={successAnimation}
                            size={100}
                            direction={1}
                        />
                    </div>
                </div>
            </section>

            {/* Click Animation */}
            <section style={{ marginBottom: '60px' }}>
                <h2>6. Click Animation</h2>
                <p>Animation plays on click</p>
                <div style={{ marginTop: '20px', textAlign: 'center' }}>
                    <p>Click the animation!</p>
                    <ClickAnimation 
                        animationData={successAnimation}
                        size={120}
                        onClick={() => alert('Animation clicked!')}
                    />
                </div>
            </section>

            {/* Progress Animation */}
            <section style={{ marginBottom: '60px' }}>
                <h2>7. Progress Animation</h2>
                <p>Shows progress from 0-100%</p>
                <div style={{ marginTop: '20px', textAlign: 'center' }}>
                    <ProgressAnimation 
                        animationData={loadingAnimation}
                        progress={progress}
                        size={120}
                    />
                    <div style={{ marginTop: '20px' }}>
                        <input 
                            type="range" 
                            min="0" 
                            max="100" 
                            value={progress}
                            onChange={(e) => setProgress(Number(e.target.value))}
                            style={{ width: '300px' }}
                        />
                        <button 
                            onClick={simulateProgress}
                            style={{ 
                                marginLeft: '20px', 
                                padding: '8px 16px',
                                cursor: 'pointer'
                            }}
                        >
                            Simulate Progress
                        </button>
                    </div>
                </div>
            </section>

            {/* Segmented Animation */}
            <section style={{ marginBottom: '60px' }}>
                <h2>8. Segmented Animation</h2>
                <p>Play specific segments of animation</p>
                <div style={{ marginTop: '20px', textAlign: 'center' }}>
                    <SegmentedAnimation 
                        animationData={loadingAnimation}
                        segments={segments}
                        currentSegment={currentSegment}
                        size={150}
                    />
                    <div className="segment-control" style={{ marginTop: '20px' }}>
                        {segments.map((_, index) => (
                            <button
                                key={index}
                                className={`segment-btn ${currentSegment === index ? 'active' : ''}`}
                                onClick={() => setCurrentSegment(index)}
                            >
                                Segment {index + 1}
                            </button>
                        ))}
                    </div>
                </div>
            </section>

            {/* Scroll Animation */}
            <section style={{ marginBottom: '60px' }}>
                <h2>9. Scroll Animation</h2>
                <p>Animation plays when scrolled into view</p>
                <div style={{ height: '300px', marginTop: '20px' }}>
                    <p>Scroll down to see the animation...</p>
                </div>
                <div style={{ textAlign: 'center' }}>
                    <ScrollAnimation 
                        animationData={successAnimation}
                        size={150}
                        threshold={0.5}
                    />
                </div>
            </section>

            {/* Background Animation */}
            <section style={{ marginBottom: '60px' }}>
                <h2>10. Background Animation</h2>
                <p>Animated background with content overlay</p>
                <div style={{ 
                    height: '300px', 
                    marginTop: '20px',
                    border: '2px solid #ddd',
                    borderRadius: '12px',
                    overflow: 'hidden'
                }}>
                    <BackgroundAnimation 
                        animationData={loadingAnimation}
                        opacity={0.2}
                    >
                        <div style={{ 
                            padding: '60px', 
                            textAlign: 'center',
                            color: '#333'
                        }}>
                            <h3>Content Over Animation</h3>
                            <p>This content appears over the animated background</p>
                            <button style={{ 
                                padding: '10px 20px',
                                marginTop: '20px',
                                cursor: 'pointer'
                            }}>
                                Action Button
                            </button>
                        </div>
                    </BackgroundAnimation>
                </div>
            </section>
        </div>
    );
};

export default AnimationShowcase;
