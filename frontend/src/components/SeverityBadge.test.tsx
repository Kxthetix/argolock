import { describe, test, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import React from 'react';
import { SeverityBadge } from './SeverityBadge';

describe('SeverityBadge Component', () => {
  test('renders critical severity badge correctly', () => {
    const { container } = render(<SeverityBadge severity="critical" />);
    expect(screen.getByText('Critical')).toBeInTheDocument();
    expect(container.firstChild).toHaveClass('badge-critical');
  });

  test('renders high severity badge correctly', () => {
    const { container } = render(<SeverityBadge severity="high" />);
    expect(screen.getByText('High')).toBeInTheDocument();
    expect(container.firstChild).toHaveClass('badge-high');
  });

  test('defaults to info badge for unknown severity values', () => {
    const { container } = render(<SeverityBadge severity="unknown-value" />);
    expect(screen.getByText('Info')).toBeInTheDocument();
    expect(container.firstChild).toHaveClass('badge-info');
  });
});
