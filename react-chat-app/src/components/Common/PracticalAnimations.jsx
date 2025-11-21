import React, { useState, useEffect } from 'react';
import {
    LoadingSpinner,
    SuccessAnimation,
    TypingAnimation,
    ClickAnimation,
    ProgressAnimation,
    HoverAnimation,
    BackgroundAnimation
} from './AnimationComponents';
import './AnimationComponents.css';
import successAnimation from '../../animations/success.json';
import loadingAnimation from '../../animations/loading.json';

/**
 * Loading Overlay - Full screen loading indicator
 */
export const LoadingOverlay = ({ message = "Loading...", dark = false }) => {
    return (
        <div className={`loading-overlay ${dark ? 'dark' : ''}`}>
            <LoadingSpinner size={100} message={message} />
        </div>
    );
};

/**
 * Success Modal - Modal with success animation
 */
export const SuccessModal = ({ 
    message = "Success!", 
    isOpen, 
    onClose,
    autoClose = true,
    autoCloseDelay = 3000
}) => {
    useEffect(() => {
        if (isOpen && autoClose) {
            const timer = setTimeout(() => {
                onClose();
            }, autoCloseDelay);
            return () => clearTimeout(timer);
        }
    }, [isOpen, autoClose, autoCloseDelay, onClose]);

    if (!isOpen) return null;

    return (
        <>
            <div className="success-modal-overlay" onClick={onClose} />
            <div className="success-modal animation-scale-in">
                <SuccessAnimation 
                    message={message}
                    size={120}
                    onComplete={autoClose ? onClose : undefined}
                />
                {!autoClose && (
                    <button 
                        onClick={onClose}
                        style={{ 
                            marginTop: '20px',
                            padding: '8px 24px',
                            cursor: 'pointer'
                        }}
                    >
                        Close
                    </button>
                )}
            </div>
        </>
    );
};

/**
 * Animated Button - Button with loading and success states
 */
export const AnimatedButton = ({ 
    children,
    onClick,
    isLoading = false,
    showSuccess = false,
    disabled = false,
    className = ""
}) => {
    return (
        <button 
            className={`animated-button ${className}`}
            onClick={onClick}
            disabled={disabled || isLoading}
        >
            {isLoading ? (
                <>
                    <div className="button-animation">
                        <LoadingSpinner size={24} showMessage={false} />
                    </div>
                    <span>Processing...</span>
                </>
            ) : showSuccess ? (
                <>
                    <div className="button-animation">
                        <SuccessAnimation size={24} showMessage={false} />
                    </div>
                    <span>Success!</span>
                </>
            ) : (
                children
            )}
        </button>
    );
};

/**
 * File Upload Progress - Upload with progress animation
 */
export const FileUploadProgress = ({ 
    fileName,
    progress,
    isComplete = false
}) => {
    return (
        <div style={{ 
            padding: '20px',
            background: '#f8f9fa',
            borderRadius: '12px',
            maxWidth: '400px'
        }}>
            <div style={{ marginBottom: '15px' }}>
                <strong>Uploading: {fileName}</strong>
            </div>
            
            <ProgressAnimation 
                animationData={loadingAnimation}
                progress={progress}
                size={100}
            />

            {isComplete && (
                <div style={{ marginTop: '15px', textAlign: 'center' }}>
                    <SuccessAnimation 
                        size={60}
                        message="Upload Complete!"
                    />
                </div>
            )}
        </div>
    );
};

/**
 * Chat Typing Indicator - Enhanced typing indicator
 */
export const ChatTypingIndicator = ({ 
    users = [],
    position = 'left'
}) => {
    if (users.length === 0) return null;

    const userName = users.length === 1 
        ? users[0]
        : users.length === 2
        ? `${users[0]} and ${users[1]}`
        : `${users[0]} and ${users.length - 1} others`;

    return (
        <div className="animation-fade-in" style={{ 
            display: 'flex',
            justifyContent: position === 'left' ? 'flex-start' : 'flex-end',
            padding: '10px'
        }}>
            <TypingAnimation userName={userName} size={50} />
        </div>
    );
};

/**
 * Interactive Like Button
 */
export const LikeButton = ({ 
    isLiked,
    onLike,
    count = 0
}) => {
    const [showAnimation, setShowAnimation] = useState(false);

    const handleClick = () => {
        setShowAnimation(true);
        onLike(!isLiked);
        setTimeout(() => setShowAnimation(false), 1000);
    };

    return (
        <div style={{ 
            display: 'flex',
            alignItems: 'center',
            gap: '8px'
        }}>
            <ClickAnimation 
                animationData={successAnimation}
                size={40}
                onClick={handleClick}
            />
            <span style={{ fontSize: '16px', fontWeight: 'bold' }}>
                {count}
            </span>
        </div>
    );
};

/**
 * Message Sent Confirmation
 */
export const MessageSentConfirmation = ({ onComplete }) => {
    return (
        <div style={{ 
            position: 'fixed',
            top: '20px',
            right: '20px',
            zIndex: 9999,
            background: 'white',
            padding: '15px',
            borderRadius: '12px',
            boxShadow: '0 4px 12px rgba(0,0,0,0.15)',
            animation: 'slideUp 0.3s ease-out'
        }}>
            <SuccessAnimation 
                size={60}
                message="Message Sent!"
                onComplete={onComplete}
            />
        </div>
    );
};

/**
 * Hero Section with Background Animation
 */
export const AnimatedHeroSection = ({ 
    title,
    subtitle,
    children,
    animationData
}) => {
    return (
        <div style={{ minHeight: '500px', borderRadius: '16px', overflow: 'hidden' }}>
            <BackgroundAnimation 
                animationData={animationData || loadingAnimation}
                opacity={0.15}
            >
                <div style={{ 
                    padding: '80px 40px',
                    textAlign: 'center'
                }}>
                    <h1 style={{ fontSize: '48px', marginBottom: '20px' }}>
                        {title}
                    </h1>
                    <p style={{ fontSize: '20px', color: '#666', marginBottom: '40px' }}>
                        {subtitle}
                    </p>
                    {children}
                </div>
            </BackgroundAnimation>
        </div>
    );
};

/**
 * Hover Card with Animation
 */
export const HoverCard = ({ 
    title,
    description,
    animationData,
    onClick
}) => {
    return (
        <div 
            onClick={onClick}
            style={{ 
                padding: '30px',
                background: 'white',
                borderRadius: '16px',
                boxShadow: '0 2px 8px rgba(0,0,0,0.1)',
                cursor: 'pointer',
                transition: 'all 0.3s ease',
                textAlign: 'center'
            }}
            onMouseEnter={(e) => {
                e.currentTarget.style.boxShadow = '0 8px 24px rgba(0,0,0,0.15)';
                e.currentTarget.style.transform = 'translateY(-5px)';
            }}
            onMouseLeave={(e) => {
                e.currentTarget.style.boxShadow = '0 2px 8px rgba(0,0,0,0.1)';
                e.currentTarget.style.transform = 'translateY(0)';
            }}
        >
            <HoverAnimation 
                animationData={animationData || successAnimation}
                size={100}
            />
            <h3 style={{ margin: '15px 0 10px' }}>{title}</h3>
            <p style={{ color: '#666', margin: 0 }}>{description}</p>
        </div>
    );
};

/**
 * Multi-Step Form Progress
 */
export const MultiStepProgress = ({ 
    currentStep,
    totalSteps,
    stepTitles = []
}) => {
    const progress = ((currentStep - 1) / (totalSteps - 1)) * 100;

    return (
        <div style={{ padding: '30px', maxWidth: '600px', margin: '0 auto' }}>
            <div style={{ 
                display: 'flex',
                justifyContent: 'space-between',
                marginBottom: '20px'
            }}>
                {stepTitles.map((title, index) => (
                    <div 
                        key={index}
                        style={{ 
                            flex: 1,
                            textAlign: 'center',
                            color: index < currentStep ? '#007bff' : '#999',
                            fontWeight: index < currentStep ? 'bold' : 'normal'
                        }}
                    >
                        <div style={{ 
                            width: '30px',
                            height: '30px',
                            borderRadius: '50%',
                            background: index < currentStep ? '#007bff' : '#e0e0e0',
                            color: 'white',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            margin: '0 auto 8px'
                        }}>
                            {index + 1}
                        </div>
                        <small>{title}</small>
                    </div>
                ))}
            </div>

            <ProgressAnimation 
                animationData={loadingAnimation}
                progress={progress}
                size={80}
            />
        </div>
    );
};

/**
 * Empty State with Animation
 */
export const EmptyState = ({ 
    title = "No data available",
    description = "Get started by adding some content",
    animationData,
    actionButton
}) => {
    return (
        <div style={{ 
            textAlign: 'center',
            padding: '60px 20px'
        }}>
            <div style={{ marginBottom: '20px' }}>
                {animationData ? (
                    <HoverAnimation 
                        animationData={animationData}
                        size={150}
                    />
                ) : (
                    <LoadingSpinner size={120} showMessage={false} />
                )}
            </div>
            <h3 style={{ fontSize: '24px', marginBottom: '12px' }}>{title}</h3>
            <p style={{ color: '#666', marginBottom: '24px', maxWidth: '400px', margin: '0 auto 24px' }}>
                {description}
            </p>
            {actionButton}
        </div>
    );
};

// Export all practical components
export default {
    LoadingOverlay,
    SuccessModal,
    AnimatedButton,
    FileUploadProgress,
    ChatTypingIndicator,
    LikeButton,
    MessageSentConfirmation,
    AnimatedHeroSection,
    HoverCard,
    MultiStepProgress,
    EmptyState
};
