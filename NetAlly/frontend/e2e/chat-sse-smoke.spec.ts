import { expect, test } from '@playwright/test'

test('Chat SSE 스모크: planning/answer 렌더', async ({ page }) => {
  await page.route('**/api/dashboard/summary?**', async route => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        health_score: 90,
        mode: 'lab',
        protocols: {
          bgp: { total: 1, up: 1, down: 0, status: 'healthy' },
          ospf: { total: 1, up: 1, down: 0, status: 'healthy' },
        },
        issues: [],
        device_status: {},
        compliance: { routing: 100, security: 100 },
      }),
    })
  })

  await page.route('**/api/chat', async route => {
    const streamBody = [
      'data: {"type":"planning","reasoning":"smoke plan ready","skills":["core"],"tool_backend":"mcp"}',
      'data: {"type":"tool_call","tool":"nso_list_devices","input":{}}',
      'data: {"type":"tool_output","content":"{}"}',
      'data: {"type":"answer","content":"smoke answer complete"}',
      'data: {"type":"complete"}',
      '',
      '',
    ].join('\n')

    await route.fulfill({
      status: 200,
      headers: {
        'content-type': 'text/event-stream',
        'cache-control': 'no-cache',
      },
      body: streamBody,
    })
  })

  await page.goto('http://127.0.0.1:3000')

  const input = page.getByPlaceholder('Send a message...')
  await input.fill('smoke test')
  await input.press('Enter')

  await expect(page.getByText('smoke plan ready')).toBeVisible()
  await expect(page.getByText('smoke answer complete')).toBeVisible()
})
