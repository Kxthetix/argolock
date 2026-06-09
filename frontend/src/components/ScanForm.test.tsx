import { vi, describe, test, expect, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import React from 'react';
import { ScanForm } from './ScanForm';
import { api } from '../lib/api';

vi.mock('../lib/api', () => ({
  api: {
    scans: {
      create: vi.fn(),
    },
  },
}));

describe('ScanForm Component', () => {
  const mockOnCreated = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
  });

  test('renders form inputs correctly', () => {
    render(<ScanForm onCreated={mockOnCreated} />);
    expect(screen.getByPlaceholderText(/example.com/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/I confirm I have authorization to scan this target/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Launch VAPT Scan/i })).toBeInTheDocument();
  });

  test('shows validation error if authorization checkbox is not checked', async () => {
    render(<ScanForm onCreated={mockOnCreated} />);
    const targetInput = screen.getByPlaceholderText(/example.com/i);
    fireEvent.change(targetInput, { target: { value: 'scanme.nmap.org' } });

    const submitBtn = screen.getByRole('button', { name: /Launch VAPT Scan/i });
    fireEvent.click(submitBtn);

    expect(await screen.findByText(/You must confirm authorization/i)).toBeInTheDocument();
    expect(api.scans.create).not.toHaveBeenCalled();
  });

  test('successfully submits scan details and triggers onCreated', async () => {
    vi.mocked(api.scans.create).mockResolvedValue({
      scan_id: 'test-scan-id-123',
      status: 'pending',
      message: 'queued',
    });

    render(<ScanForm onCreated={mockOnCreated} />);
    
    const targetInput = screen.getByPlaceholderText(/example.com/i);
    fireEvent.change(targetInput, { target: { value: 'scanme.nmap.org' } });

    const authCheckbox = screen.getByLabelText(/I confirm I have authorization to scan this target/i);
    fireEvent.click(authCheckbox);

    const submitBtn = screen.getByRole('button', { name: /Launch VAPT Scan/i });
    fireEvent.click(submitBtn);

    await waitFor(() => {
      expect(api.scans.create).toHaveBeenCalledWith({
        name: undefined,
        scope: {
          target: 'scanme.nmap.org',
          authorized: true,
          authorization_note: undefined,
        },
        config: {
          safe_mode: true,
          enable_exploitation: false,
          nuclei_severity: ['critical', 'high', 'medium'],
        },
      });
      expect(mockOnCreated).toHaveBeenCalledWith('test-scan-id-123');
    });
  });
});
