/**
 * Quick Test File for AnimationIntegrationExample
 * 
 * To test this component:
 * 1. Import it in your App.jsx or create a test route
 * 2. Add this to your routes:
 *    <Route path="/test-animations" element={<AnimationIntegrationExample />} />
 * 3. Navigate to http://localhost:3000/test-animations
 */

import React from 'react';
import AnimationIntegrationExample from './src/components/Common/AnimationIntegrationExample';

function TestPage() {
  return (
    <div style={{ minHeight: '100vh', background: '#f5f5f5' }}>
      <AnimationIntegrationExample />
    </div>
  );
}

export default TestPage;
