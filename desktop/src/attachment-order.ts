/**
 * Start an attachment whose first channel payload is its screen snapshot.
 *
 * Tauri's invoke reply and Channel delivery are independent async paths. The
 * caller must not treat the attachment as ready until both have completed,
 * otherwise it can render an empty terminal and merely cache the snapshot
 * when it arrives a moment later.
 */
export async function attachAfterFirstPayload<T>(
  start: (deliver: (payload: Uint8Array) => void) => Promise<T>,
  consume: (payload: Uint8Array) => void,
): Promise<T> {
  let firstDelivered = false;
  let resolveFirst!: () => void;
  const firstPayload = new Promise<void>((resolve) => {
    resolveFirst = resolve;
  });

  const reply = start((payload) => {
    consume(payload);
    if (!firstDelivered) {
      firstDelivered = true;
      resolveFirst();
    }
  });

  const [value] = await Promise.all([reply, firstPayload]);
  return value;
}
