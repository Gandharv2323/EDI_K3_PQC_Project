import React from 'react';
import Lottie from 'lottie-react';

const LottieAnimation = ({ animationData, loop = true, autoplay = true, style, className }) => {
    return (
        <Lottie
            animationData={animationData}
            loop={loop}
            autoplay={autoplay}
            style={style}
            className={className}
        />
    );
};

export default LottieAnimation;
