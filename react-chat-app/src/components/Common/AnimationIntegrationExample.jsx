import React, { useState } from 'react';
import {
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
} from './PracticalAnimations';
import './AnimationComponents.css';
import loadingAnimation from '../../animations/loading.json';
import successAnimation from '../../animations/success.json';

/**
 * Complete Integration Example
 * Shows how to use all animation components together
 */
const AnimationIntegrationExample = () => {
    // State management
    const [isLoading, setIsLoading] = useState(false);
    const [showSuccess, setShowSuccess] = useState(false);
    const [uploadProgress, setUploadProgress] = useState(0);
    const [isUploading, setIsUploading] = useState(false);
    const [typingUsers, setTypingUsers] = useState([]);
    const [likeCount, setLikeCount] = useState(42);
    const [isLiked, setIsLiked] = useState(false);
    const [showMessageSent, setShowMessageSent] = useState(false);
    const [currentStep, setCurrentStep] = useState(1);

    // Simulate loading
    const handleLoadData = () => {
        setIsLoading(true);
        setTimeout(() => {
            setIsLoading(false);
            setShowSuccess(true);
        }, 2000);
    };

    // Simulate file upload
    const handleFileUpload = () => {
        setIsUploading(true);
        setUploadProgress(0);

        const interval = setInterval(() => {
            setUploadProgress(prev => {
                if (prev >= 100) {
                    clearInterval(interval);
                    setTimeout(() => {
                        setIsUploading(false);
                        setShowSuccess(true);
                    }, 500);
                    return 100;
                }
                return prev + 10;
            });
        }, 300);
    };

    // Simulate typing
    const handleStartTyping = () => {
        setTypingUsers(['John', 'Sarah']);
        setTimeout(() => setTypingUsers([]), 3000);
    };

    // Handle like
    const handleLike = (liked) => {
        setIsLiked(liked);
        setLikeCount(prev => liked ? prev + 1 : prev - 1);
    };

    // Send message
    const handleSendMessage = () => {
        setShowMessageSent(true);
        setTimeout(() => setShowMessageSent(false), 2000);
    };

    return (
        <div style={{ padding: '20px', maxWidth: '1400px', margin: '0 auto' }}>
            {/* Loading Overlay Example */}
            {isLoading && (
                <LoadingOverlay message="Fetching data..." dark={false} />
            )}

            {/* Success Modal Example */}
            <SuccessModal 
                message="Operation Successful!"
                isOpen={showSuccess}
                onClose={() => setShowSuccess(false)}
                autoClose={true}
                autoCloseDelay={2500}
            />

            {/* Message Sent Confirmation */}
            {showMessageSent && (
                <MessageSentConfirmation 
                    onComplete={() => setShowMessageSent(false)}
                />
            )}

            {/* Hero Section */}
            <AnimatedHeroSection 
                title="Welcome to Animation Components"
                subtitle="Explore beautiful Lottie animations for your React app"
                animationData={loadingAnimation}
            >
                <AnimatedButton onClick={handleLoadData}>
                    Load Data with Animation
                </AnimatedButton>
            </AnimatedHeroSection>

            <div style={{ marginTop: '40px', display: 'grid', gap: '40px' }}>
                
                {/* Section 1: Button Examples */}
                <section>
                    <h2>Interactive Buttons</h2>
                    <div style={{ display: 'flex', gap: '20px', flexWrap: 'wrap', marginTop: '20px' }}>
                        <AnimatedButton 
                            onClick={handleLoadData}
                            isLoading={isLoading}
                        >
                            Click Me
                        </AnimatedButton>

                        <AnimatedButton 
                            onClick={handleSendMessage}
                            showSuccess={showMessageSent}
                        >
                            Send Message
                        </AnimatedButton>

                        <div>
                            <p style={{ marginBottom: '10px' }}>Like Button:</p>
                            <LikeButton 
                                isLiked={isLiked}
                                onLike={handleLike}
                                count={likeCount}
                            />
                        </div>
                    </div>
                </section>

                {/* Section 2: File Upload */}
                <section>
                    <h2>File Upload Progress</h2>
                    <div style={{ marginTop: '20px' }}>
                        {!isUploading ? (
                            <button 
                                onClick={handleFileUpload}
                                style={{ 
                                    padding: '12px 24px',
                                    cursor: 'pointer',
                                    fontSize: '16px'
                                }}
                            >
                                Start Upload Demo
                            </button>
                        ) : (
                            <FileUploadProgress 
                                fileName="example-file.pdf"
                                progress={uploadProgress}
                                isComplete={uploadProgress === 100}
                            />
                        )}
                    </div>
                </section>

                {/* Section 3: Chat Features */}
                <section>
                    <h2>Chat Features</h2>
                    <div style={{ marginTop: '20px' }}>
                        <button 
                            onClick={handleStartTyping}
                            style={{ 
                                padding: '10px 20px',
                                cursor: 'pointer',
                                marginBottom: '20px'
                            }}
                        >
                            Simulate Typing Indicator
                        </button>
                        
                        <div style={{ 
                            background: '#f8f9fa',
                            padding: '20px',
                            borderRadius: '12px',
                            minHeight: '100px'
                        }}>
                            <ChatTypingIndicator 
                                users={typingUsers}
                                position="left"
                            />
                        </div>
                    </div>
                </section>

                {/* Section 4: Multi-Step Progress */}
                <section>
                    <h2>Multi-Step Form</h2>
                    <div style={{ marginTop: '20px' }}>
                        <MultiStepProgress 
                            currentStep={currentStep}
                            totalSteps={4}
                            stepTitles={['Account', 'Profile', 'Preferences', 'Complete']}
                        />
                        <div style={{ 
                            display: 'flex', 
                            gap: '10px', 
                            justifyContent: 'center',
                            marginTop: '20px'
                        }}>
                            <button 
                                onClick={() => setCurrentStep(Math.max(1, currentStep - 1))}
                                disabled={currentStep === 1}
                                style={{ padding: '8px 16px', cursor: 'pointer' }}
                            >
                                Previous
                            </button>
                            <button 
                                onClick={() => setCurrentStep(Math.min(4, currentStep + 1))}
                                disabled={currentStep === 4}
                                style={{ padding: '8px 16px', cursor: 'pointer' }}
                            >
                                Next
                            </button>
                        </div>
                    </div>
                </section>

                {/* Section 5: Hover Cards */}
                <section>
                    <h2>Interactive Hover Cards</h2>
                    <div style={{ 
                        display: 'grid', 
                        gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))',
                        gap: '20px',
                        marginTop: '20px'
                    }}>
                        <HoverCard 
                            title="Feature One"
                            description="Hover to see animation"
                            animationData={successAnimation}
                            onClick={() => alert('Card 1 clicked!')}
                        />
                        <HoverCard 
                            title="Feature Two"
                            description="Interactive and smooth"
                            animationData={loadingAnimation}
                            onClick={() => alert('Card 2 clicked!')}
                        />
                        <HoverCard 
                            title="Feature Three"
                            description="Beautiful animations"
                            animationData={successAnimation}
                            onClick={() => alert('Card 3 clicked!')}
                        />
                    </div>
                </section>

                {/* Section 6: Empty State */}
                <section>
                    <h2>Empty State Example</h2>
                    <div style={{ 
                        background: '#f8f9fa',
                        borderRadius: '12px',
                        marginTop: '20px'
                    }}>
                        <EmptyState 
                            title="No messages yet"
                            description="Start a conversation by sending your first message"
                            animationData={loadingAnimation}
                            actionButton={
                                <button 
                                    onClick={() => alert('Create new message')}
                                    style={{ 
                                        padding: '12px 32px',
                                        background: '#007bff',
                                        color: 'white',
                                        border: 'none',
                                        borderRadius: '8px',
                                        cursor: 'pointer',
                                        fontSize: '16px'
                                    }}
                                >
                                    Send First Message
                                </button>
                            }
                        />
                    </div>
                </section>

            </div>

            {/* Integration Tips */}
            <section style={{ 
                marginTop: '60px',
                padding: '30px',
                background: '#f0f8ff',
                borderRadius: '12px',
                borderLeft: '4px solid #007bff'
            }}>
                <h2>Integration Tips</h2>
                <ul style={{ lineHeight: '2' }}>
                    <li><strong>LoadingOverlay:</strong> Use for full-page loading states</li>
                    <li><strong>SuccessModal:</strong> Perfect for form submissions and confirmations</li>
                    <li><strong>AnimatedButton:</strong> Provides feedback during async operations</li>
                    <li><strong>FileUploadProgress:</strong> Essential for file upload UX</li>
                    <li><strong>ChatTypingIndicator:</strong> Real-time chat experience</li>
                    <li><strong>MultiStepProgress:</strong> Great for wizards and onboarding</li>
                    <li><strong>HoverCard:</strong> Feature showcases and product galleries</li>
                    <li><strong>EmptyState:</strong> Improve UX when no data is available</li>
                </ul>
            </section>
        </div>
    );
};

export default AnimationIntegrationExample;
