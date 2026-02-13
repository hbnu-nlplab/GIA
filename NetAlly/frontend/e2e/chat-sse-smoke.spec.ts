import { expect, test } from '@playwright/test'

test('Chat SSE 스모크: planning/answer 렌더', async ({ page }) => {
  let chatRequestCount = 0
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

  await page.route(/\/api\/chat(?:\/)?(?:\?.*)?$/, async route => {
    chatRequestCount += 1
    const events = [
      { type: 'planning', reasoning: 'smoke plan ready', skills: ['core'], tool_backend: 'mcp' },
      { type: 'tool_call', tool: 'nso_list_devices', input: {} },
      { type: 'tool_output', content: '{}' },
      { type: 'answer', content: 'smoke answer complete' },
      { type: 'complete' },
    ]
    const streamBody = `${events.map((event) => `data: ${JSON.stringify(event)}`).join('\n\n')}\n\n`

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

  const input = page.getByLabel('Message input')
  await input.fill('smoke test')
  await input.press('Enter')

  await expect(page.getByText('smoke plan ready')).toBeVisible()
  await expect(page.getByText('smoke answer complete')).toBeVisible()
  expect(chatRequestCount).toBeGreaterThan(0)
})
