import { createInterface } from 'node:readline/promises';

export type ApprovalOutcome = 'granted' | 'declined' | 'unavailable';

export type ApprovalRequest = Readonly<{
  actor: 'user' | 'agent';
  secret?: string;
  executable: string;
  argumentsPreview: readonly string[];
}>;

/**
 * Asks the operator to approve one sensitive operation on the controlling
 * terminal. Approval requires an interactive terminal; unattended contexts
 * fail closed with 'unavailable' and the caller must deny.
 */
export async function requestApproval(
  request: ApprovalRequest,
): Promise<ApprovalOutcome> {
  if (!process.stdin.isTTY || !process.stderr.isTTY) {
    return 'unavailable';
  }
  if (process.stdin.readableEnded) {
    // An input that has already closed can never answer; fail closed now
    // instead of waiting forever below.
    return 'declined';
  }
  const lines = [
    '',
    'Kavrix approval required:',
    `  Credential: ${request.secret ?? '(unspecified)'}`,
    `  Executable: ${request.executable}`,
    ...(request.argumentsPreview.length > 0
      ? [`  Arguments:  ${request.argumentsPreview.join(' ')}`]
      : []),
    ...['Allow once? [y/N]'],
  ];
  process.stderr.write(`${lines.join('\n')} `);
  // Keystrokes typed while the prompt rendered arrive before readline starts
  // listening (the stream may already be flowing). Capture them, start the
  // question, then replay so an early answer is never dropped.
  const earlyInput: string[] = [];
  const captureEarly = (chunk: Buffer | string): void => {
    earlyInput.push(typeof chunk === 'string' ? chunk : chunk.toString('utf8'));
  };
  process.stdin.on('data', captureEarly);
  const interfaceRef = createInterface({ input: process.stdin, output: undefined });
  // Readline re-emits input errors on the interface; without a listener the
  // synthetic event would escape as an uncaught exception.
  interfaceRef.on('error', () => undefined);
  let abortApproval: () => void = () => undefined;
  const ended = new Promise<never>((_, reject) => {
    abortApproval = (): void => {
      reject(new Error('approval stream ended'));
    };
  });
  try {
    // An input stream that ends before an answer arrives must fail closed
    // instead of waiting forever on an operator who is gone.
    process.stdin.on('end', abortApproval);
    process.stdin.on('close', abortApproval);
    process.stdin.on('error', abortApproval);

    const answerPromise = interfaceRef.question('');
    process.stdin.off('data', captureEarly);
    if (earlyInput.length > 0) {
      interfaceRef.write(earlyInput.join(''));
    }

    const answer = await Promise.race([answerPromise, ended]);
    const normalized = answer.trim().toLowerCase();
    return normalized === 'y' || normalized === 'yes' ? 'granted' : 'declined';
  } catch {
    return 'declined';
  } finally {
    process.stdin.off('end', abortApproval);
    process.stdin.off('close', abortApproval);
    process.stdin.off('error', abortApproval);
    interfaceRef.close();
    process.stdout.write('\n');
  }
}
