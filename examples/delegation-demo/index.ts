import { attemptDelegation, startDelegator } from './delegator.js';
import { startProvider } from './provider.js';
import { ui } from './ui.js';

const STARTUP_DELAY_MS = 1_000;

async function main(): Promise<void> {
  let provider: Awaited<ReturnType<typeof startProvider>> | undefined;
  let delegator: Awaited<ReturnType<typeof startDelegator>> | undefined;

  try {
    printHeader();

    provider = await startProvider();
    console.log(ui.step(`[1/4] Agent A booted on ${provider.baseUrl}`));

    delegator = await startDelegator();
    console.log(`${ui.runnerTag} Agent B booted on ${ui.value(delegator.baseUrl)}`);

    // Delay keeps the demo output deterministic and easy to follow.
    console.log(
      `${ui.runnerTag} Waiting ${ui.value(String(STARTUP_DELAY_MS))}ms for clean startup...`,
    );
    await sleep(STARTUP_DELAY_MS);

    await attemptDelegation(provider.baseUrl);

    console.log('');
    console.log(
      `${ui.runnerTag} ${ui.success('Demo complete.')} Both agents communicated over HTTP with trust verification.`,
    );
  } finally {
    await Promise.allSettled([provider?.stop(), delegator?.stop()]);
    console.log(`${ui.runnerTag} ${ui.subheading('Shutdown complete.')}`);
  }
}

function printHeader(): void {
  const line = '='.repeat(62);
  console.log(ui.subheading(line));
  console.log(ui.heading('Logpose A2A Delegation Demo'));
  console.log(ui.subheading('Agent A = Provider (port 3001), Agent B = Delegator (port 3002)'));
  console.log(ui.subheading(line));
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

main().catch((error: unknown) => {
  console.error(`${ui.runnerTag} ${ui.error('Demo failed:')}`, error);
  process.exitCode = 1;
});
