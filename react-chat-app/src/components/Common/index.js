/**
 * Animation Components - Main Export File
 * Import animations easily from a single location
 */

// Core Animation Components
export {
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

// Practical Animation Components
export {
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

// Showcase Components
export { default as AnimationShowcase } from './AnimationShowcase';
export { default as AnimationIntegrationExample } from './AnimationIntegrationExample';

// Base Component
export { default as LottieAnimation } from './LottieAnimation';

/**
 * Usage Examples:
 * 
 * // Import specific components
 * import { LoadingSpinner, SuccessAnimation } from './components/Common';
 * 
 * // Import all core components
 * import * as Animations from './components/Common';
 * 
 * // Use in your component
 * <Animations.LoadingSpinner size={100} message="Loading..." />
 * 
 * // Don't forget to import styles
 * import './components/Common/AnimationComponents.css';
 */
