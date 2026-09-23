import React from 'react';

// Landing pages are self-contained (skip link + nav + footer live in the page),
// so the layout is a plain near-black shell for any future landing sections.
export const LandingLayout: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <div className="min-h-dvh bg-bg text-text">
    {children}
  </div>
);

export default LandingLayout;
