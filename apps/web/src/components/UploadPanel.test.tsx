import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { ApiError } from '../api/client';
import { MAX_UPLOAD_BYTES } from '../lib/upload';
import { UploadPanel } from './UploadPanel';

function setup(uploadPackage = vi.fn(() => Promise.resolve({ assessmentId: 'new-id' }))) {
  const onUploaded = vi.fn();
  const user = userEvent.setup({ applyAccept: false });
  render(<UploadPanel api={{ uploadPackage }} onUploaded={onUploaded} />);
  const input = screen.getByLabelText('Choose evidence package');
  return { user, input, uploadPackage, onUploaded };
}

describe('UploadPanel', () => {
  it('rejects a non-zip file without calling the API', async () => {
    const { user, input, uploadPackage } = setup();
    await user.upload(input, new File(['{}'], 'evidence.json', { type: 'application/json' }));
    expect(screen.getByRole('status').textContent).toContain('not a .zip file');
    expect(uploadPackage).not.toHaveBeenCalled();
  });

  it('rejects an oversized zip without calling the API', async () => {
    const { user, input, uploadPackage } = setup();
    const big = new File(['x'], 'big.zip', { type: 'application/zip' });
    Object.defineProperty(big, 'size', { value: MAX_UPLOAD_BYTES + 1 });
    await user.upload(input, big);
    expect(screen.getByRole('status').textContent).toContain('maximum package size');
    expect(uploadPackage).not.toHaveBeenCalled();
  });

  it('uploads a valid zip and reports success', async () => {
    const { user, input, uploadPackage, onUploaded } = setup();
    await user.upload(input, new File(['PK'], 'evidence.zip', { type: 'application/zip' }));
    await waitFor(() => expect(onUploaded).toHaveBeenCalledWith('new-id'));
    expect(uploadPackage).toHaveBeenCalledTimes(1);
    expect(screen.getByRole('status').textContent).toContain('evidence.zip was processed');
  });

  it('shows the API error message when processing fails', async () => {
    const failing = vi.fn(() => Promise.reject(new ApiError('integrity_failed', 'Manifest hash mismatch.', 422)));
    const { user, input, onUploaded } = setup(failing);
    await user.upload(input, new File(['PK'], 'evidence.zip', { type: 'application/zip' }));
    await waitFor(() => expect(screen.getByRole('status').textContent).toContain('Manifest hash mismatch.'));
    expect(onUploaded).not.toHaveBeenCalled();
  });
});
