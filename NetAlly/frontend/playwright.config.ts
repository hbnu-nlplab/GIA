import { defineConfig } from '@playwright/test'

const isCI = !!process.env.CI

export default defineConfig({
  testDir: './e2e',
  timeout: 90_000,
  expect: {
    timeout: 10_000,
  },
  fullyParallel: false,
  retries: isCI ? 1 : 0,
  workers: 1,
  reporter: isCI ? [['github'], ['html', { open: 'never' }]] : 'list',
  use: {
    baseURL: 'http://127.0.0.1:8111',
    viewport: { width: 1440, height: 2200 },
    headless: true,
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },
  webServer: [
    {
      command: 'uv run uvicorn main:app --host 127.0.0.1 --port 8111',
      cwd: '..',
      url: 'http://127.0.0.1:8111/api/health',
      reuseExistingServer: !isCI,
      timeout: 120_000,
      env: {
        ...process.env,
        LANGSMITH_TRACING: 'false',
        NETALLY_TOOL_BACKEND: 'mcp',
        NETALLY_MCP_ALLOW_MUTATIONS: 'false',
      },
    },
    {
      command: 'npm run dev -- --host 127.0.0.1 --port 3000',
      cwd: '.',
      url: 'http://127.0.0.1:3000',
      reuseExistingServer: !isCI,
      timeout: 120_000,
    },
  ],
})
