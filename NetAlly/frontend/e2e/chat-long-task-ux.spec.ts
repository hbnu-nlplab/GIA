import { expect, test } from '@playwright/test'

test('Chat long-task UX: failed request exposes retry and succeeds on retry', async ({ page }) => {
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

  await page.route('**/api/runtime/health', async route => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        status: 'ok',
        overall: 'healthy',
        recommendedMode: 'full',
        checkedAt: new Date().toISOString(),
        services: {
          batfish: { status: 'ready', severity: 'ok' },
          nso: { status: 'ok', severity: 'ok' },
          pnetlab: { status: 'ok', severity: 'ok' },
        },
        notes: [],
      }),
    })
  })

  let callCount = 0
  await page.route('**/api/chat', async route => {
    callCount += 1

    if (callCount <= 2) {
      await route.fulfill({
        status: 503,
        contentType: 'application/json',
        body: JSON.stringify({ detail: 'temporary upstream error' }),
      })
      return
    }

    const events = [
      '{"type":"planning","reasoning":"retry plan"}',
      '{"type":"answer","content":"retry succeeded"}',
      '{"type":"complete"}',
    ]
    const streamBody = events.map((evt) => `data: ${evt}\n\n`).join('')
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

  const input = page.locator('textarea[aria-label="Message input"]')
  await input.fill('long task retry')
  await input.press('Enter')

  await expect(page.getByText('Retry')).toBeVisible()
  await page.getByRole('button', { name: 'Retry' }).click()

  await expect(page.getByText('retry succeeded')).toBeVisible()
})
