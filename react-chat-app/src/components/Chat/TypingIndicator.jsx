import React from 'react';
import LottieAnimation from '../Common/LottieAnimation';
import typingAnimation from '../../animations/typing.json';
import './TypingIndicator.css';

const TypingIndicator = ({ username }) => {
    return (
        <div className="typing-indicator animate-fade-in">
            <div className="typing-indicator-content">
                <span className="typing-username">{username} is typing</span>
                <div className="typing-animation">
                    <LottieAnimation 
                        animationData={typingAnimation}
                        style={{ width: '50px', height: '20px' }}
                    />
                </div>
            </div>
        </div>
    );
};

export default TypingIndicator;
