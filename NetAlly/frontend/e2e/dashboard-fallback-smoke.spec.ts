import { expect, test } from '@playwright/test'

test('Dashboard fallback 응답(ospf 누락)에서도 앱이 크래시하지 않는다', async ({ page }) => {
  const pageErrors: string[] = []
  page.on('pageerror', error => {
    pageErrors.push(error.message)
  })

  await page.route('**/api/dashboard/summary?**', async route => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        health_score: 0,
        mode: 'lab',
        protocols: {
          bgp: { total: 0, up: 0, down: 0, status: 'unknown' },
        },
        issues: [],
        device_status: {},
        compliance: { routing: 0 },
      }),
    })
  })

  await page.goto('http://127.0.0.1:3000')
  await expect(page.getByText('Network Health')).toBeVisible()
  await expect(page.getByLabel('Message input')).toBeVisible()
  expect(pageErrors).toEqual([])
})
