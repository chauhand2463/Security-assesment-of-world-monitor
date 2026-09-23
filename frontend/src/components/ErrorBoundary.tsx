import React from 'react';

interface Props {
  children: React.ReactNode;
}

interface State {
  error: Error | null;
}

export class ErrorBoundary extends React.Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    console.error('[ErrorBoundary]', error, info.componentStack);
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div className="mx-auto max-w-md px-4 py-16 text-center">
        <p className="eyebrow mb-2">Render error</p>
        <h2 className="text-[15px] font-semibold text-text">This view could not be rendered.</h2>
        <p className="mt-2 font-mono text-[10.5px] leading-relaxed text-faint">{String(this.state.error.message || this.state.error)}</p>
        <button
          onClick={() => this.setState({ error: null })}
          className="mt-4 inline-flex cursor-pointer items-center gap-1.5 rounded-full border border-line px-3 py-1.5 text-[11.5px] text-muted transition-colors duration-500 ease-spring hover:bg-surface-2 hover:text-text"
        >
          Try again
        </button>
      </div>
    );
  }
}