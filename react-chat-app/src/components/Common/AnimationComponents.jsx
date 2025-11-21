import React, { useRef, useEffect, useState } from 'react';
import Lottie from 'lottie-react';
import loadingAnimation from '../../animations/loading.json';
import successAnimation from '../../animations/success.json';
import typingAnimation from '../../animations/typing.json';

/**
 * Loading Spinner Component
 * Use for loading states, data fetching, etc.
 */
export const LoadingSpinner = ({ 
    size = 100, 
    message = "Loading...",
    showMessage = true 
}) => {
    return (
        <div className="animation-container" style={{ 
            display: 'flex', 
            flexDirection: 'column', 
            alignItems: 'center',
            justifyContent: 'center',
            gap: '10px'
        }}>
            <Lottie
                animationData={loadingAnimation}
                loop={true}
                autoplay={true}
                style={{ width: size, height: size }}
            />
            {showMessage && <p className="animation-message">{message}</p>}
        </div>
    );
};

/**
 * Success Animation Component
 * Use for successful operations, confirmations, etc.
 */
export const SuccessAnimation = ({ 
    size = 100, 
    message = "Success!",
    showMessage = true,
    onComplete,
    loop = false
}) => {
    const lottieRef = useRef();

    useEffect(() => {
        if (lottieRef.current && onComplete) {
            lottieRef.current.addEventListener('complete', onComplete);
            return () => {
                lottieRef.current?.removeEventListener('complete', onComplete);
            };
        }
    }, [onComplete]);

    return (
        <div className="animation-container" style={{ 
            display: 'flex', 
            flexDirection: 'column', 
            alignItems: 'center',
            justifyContent: 'center',
            gap: '10px'
        }}>
            <Lottie
                lottieRef={lottieRef}
                animationData={successAnimation}
                loop={loop}
                autoplay={true}
                style={{ width: size, height: size }}
            />
            {showMessage && <p className="animation-message">{message}</p>}
        </div>
    );
};

/**
 * Typing Indicator Animation
 * Use for showing typing status in chats
 */
export const TypingAnimation = ({ 
    size = 60,
    userName = "Someone"
}) => {
    return (
        <div className="typing-animation-container" style={{ 
            display: 'flex', 
            alignItems: 'center',
            gap: '8px',
            padding: '5px'
        }}>
            <Lottie
                animationData={typingAnimation}
                loop={true}
                autoplay={true}
                style={{ width: size, height: size }}
            />
            <span className="typing-text" style={{ fontSize: '14px', color: '#666' }}>
                {userName} is typing...
            </span>
        </div>
    );
};

/**
 * Controllable Animation Component
 * Advanced component with play/pause/stop controls
 */
export const ControllableAnimation = ({ 
    animationData,
    size = 150,
    showControls = true,
    loop = true,
    speed = 1
}) => {
    const lottieRef = useRef();
    const [isPaused, setIsPaused] = useState(false);

    useEffect(() => {
        if (lottieRef.current) {
            lottieRef.current.setSpeed(speed);
        }
    }, [speed]);

    const handlePlayPause = () => {
        if (lottieRef.current) {
            if (isPaused) {
                lottieRef.current.play();
            } else {
                lottieRef.current.pause();
            }
            setIsPaused(!isPaused);
        }
    };

    const handleStop = () => {
        if (lottieRef.current) {
            lottieRef.current.stop();
            setIsPaused(true);
        }
    };

    const handleRestart = () => {
        if (lottieRef.current) {
            lottieRef.current.goToAndPlay(0);
            setIsPaused(false);
        }
    };

    return (
        <div className="controllable-animation" style={{ 
            display: 'flex', 
            flexDirection: 'column', 
            alignItems: 'center',
            gap: '15px'
        }}>
            <Lottie
                lottieRef={lottieRef}
                animationData={animationData}
                loop={loop}
                autoplay={true}
                style={{ width: size, height: size }}
            />
            {showControls && (
                <div className="animation-controls" style={{ 
                    display: 'flex', 
                    gap: '10px' 
                }}>
                    <button onClick={handlePlayPause} className="control-btn">
                        {isPaused ? '▶️ Play' : '⏸️ Pause'}
                    </button>
                    <button onClick={handleStop} className="control-btn">
                        ⏹️ Stop
                    </button>
                    <button onClick={handleRestart} className="control-btn">
                        🔄 Restart
                    </button>
                </div>
            )}
        </div>
    );
};

/**
 * Hover Animation Component
 * Animation that plays on hover
 */
export const HoverAnimation = ({ 
    animationData,
    size = 100,
    direction = 1 // 1 = forward, -1 = reverse
}) => {
    const lottieRef = useRef();
    const [isHovered, setIsHovered] = useState(false);

    const handleMouseEnter = () => {
        setIsHovered(true);
        if (lottieRef.current) {
            lottieRef.current.setDirection(direction);
            lottieRef.current.play();
        }
    };

    const handleMouseLeave = () => {
        setIsHovered(false);
        if (lottieRef.current) {
            lottieRef.current.setDirection(-direction);
            lottieRef.current.play();
        }
    };

    return (
        <div 
            onMouseEnter={handleMouseEnter}
            onMouseLeave={handleMouseLeave}
            style={{ 
                cursor: 'pointer',
                transition: 'transform 0.3s ease'
            }}
        >
            <Lottie
                lottieRef={lottieRef}
                animationData={animationData}
                loop={false}
                autoplay={false}
                style={{ width: size, height: size }}
            />
        </div>
    );
};

/**
 * Scroll-Triggered Animation Component
 * Animation that plays when scrolled into view
 */
export const ScrollAnimation = ({ 
    animationData,
    size = 150,
    threshold = 0.5
}) => {
    const lottieRef = useRef();
    const containerRef = useRef();
    const [hasPlayed, setHasPlayed] = useState(false);

    useEffect(() => {
        const observer = new IntersectionObserver(
            (entries) => {
                entries.forEach((entry) => {
                    if (entry.isIntersecting && !hasPlayed) {
                        if (lottieRef.current) {
                            lottieRef.current.play();
                            setHasPlayed(true);
                        }
                    }
                });
            },
            { threshold }
        );

        if (containerRef.current) {
            observer.observe(containerRef.current);
        }

        return () => {
            if (containerRef.current) {
                observer.unobserve(containerRef.current);
            }
        };
    }, [hasPlayed, threshold]);

    return (
        <div ref={containerRef}>
            <Lottie
                lottieRef={lottieRef}
                animationData={animationData}
                loop={false}
                autoplay={false}
                style={{ width: size, height: size }}
            />
        </div>
    );
};

/**
 * Click-Triggered Animation Component
 * Animation that plays on click
 */
export const ClickAnimation = ({ 
    animationData,
    size = 100,
    onClick,
    loop = false
}) => {
    const lottieRef = useRef();

    const handleClick = () => {
        if (lottieRef.current) {
            lottieRef.current.goToAndPlay(0);
        }
        if (onClick) {
            onClick();
        }
    };

    return (
        <div 
            onClick={handleClick}
            style={{ cursor: 'pointer' }}
        >
            <Lottie
                lottieRef={lottieRef}
                animationData={animationData}
                loop={loop}
                autoplay={false}
                style={{ width: size, height: size }}
            />
        </div>
    );
};

/**
 * Progress Animation Component
 * Animation that shows progress (0-100%)
 */
export const ProgressAnimation = ({ 
    animationData,
    progress = 0, // 0-100
    size = 120
}) => {
    const lottieRef = useRef();

    useEffect(() => {
        if (lottieRef.current) {
            const totalFrames = lottieRef.current.getDuration(true);
            const frame = (progress / 100) * totalFrames;
            lottieRef.current.goToAndStop(frame, true);
        }
    }, [progress]);

    return (
        <div style={{ 
            display: 'flex', 
            flexDirection: 'column', 
            alignItems: 'center',
            gap: '10px'
        }}>
            <Lottie
                lottieRef={lottieRef}
                animationData={animationData}
                loop={false}
                autoplay={false}
                style={{ width: size, height: size }}
            />
            <div style={{ fontSize: '14px', fontWeight: 'bold' }}>
                {Math.round(progress)}%
            </div>
        </div>
    );
};

/**
 * Segmented Animation Component
 * Play specific segments of an animation
 */
export const SegmentedAnimation = ({ 
    animationData,
    segments = [[0, 60]], // Array of [start, end] frame pairs
    size = 150,
    currentSegment = 0
}) => {
    const lottieRef = useRef();

    useEffect(() => {
        if (lottieRef.current && segments[currentSegment]) {
            lottieRef.current.playSegments(segments[currentSegment], true);
        }
    }, [currentSegment, segments]);

    return (
        <Lottie
            lottieRef={lottieRef}
            animationData={animationData}
            loop={false}
            autoplay={false}
            style={{ width: size, height: size }}
        />
    );
};

/**
 * Background Animation Component
 * Full-screen or container background animation
 */
export const BackgroundAnimation = ({ 
    animationData,
    opacity = 0.3,
    children
}) => {
    return (
        <div style={{ position: 'relative', width: '100%', height: '100%' }}>
            <div style={{ 
                position: 'absolute', 
                top: 0, 
                left: 0, 
                width: '100%', 
                height: '100%',
                opacity: opacity,
                zIndex: 0
            }}>
                <Lottie
                    animationData={animationData}
                    loop={true}
                    autoplay={true}
                    style={{ width: '100%', height: '100%' }}
                />
            </div>
            <div style={{ position: 'relative', zIndex: 1 }}>
                {children}
            </div>
        </div>
    );
};

// Export all components
export default {
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
};
