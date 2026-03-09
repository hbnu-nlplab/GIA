import { expect, test } from '@playwright/test'

test('Settings에서 Light 모드 전환이 실제 html class에 반영된다', async ({ page }) => {
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

  await page.goto('http://127.0.0.1:3000')
  await page.getByTitle('System Settings').click()

  await page.getByTestId('settings-nav-appearance').click()

  await expect.poll(async () => page.evaluate(() => document.documentElement.classList.contains('dark'))).toBe(true)

  await page.getByRole('button', { name: 'Light' }).click()
  await expect.poll(async () => page.evaluate(() => document.documentElement.classList.contains('dark'))).toBe(false)

  await page.getByRole('button', { name: 'Dark' }).click()
  await expect.poll(async () => page.evaluate(() => document.documentElement.classList.contains('dark'))).toBe(true)
})
