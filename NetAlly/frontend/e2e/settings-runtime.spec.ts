import { expect, test } from '@playwright/test'

test('Settings에서 MCP 런타임 필드 로드/수정/저장', async ({ page, request }) => {
  await page.route('**/api/dashboard/summary?**', async route => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        health_score: 95,
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

  await expect(page.getByText('API Connections')).toBeVisible()
  const apiConnectionsSection = page.locator('section').filter({ hasText: 'API Connections' }).first()

  const settingsBefore = await request.get('http://127.0.0.1:8111/api/settings')
  expect(settingsBefore.ok()).toBeTruthy()
  const settingsBeforePayload = await settingsBefore.json()

  const mcpUrlInput = apiConnectionsSection.locator('label:has-text("MCP Server URL") + input')
  const existingMcpUrl = (await mcpUrlInput.inputValue()).trim()
  expect(existingMcpUrl).toBe(String(settingsBeforePayload.mcp_server_url || ''))

  const mutationsToggle = apiConnectionsSection
    .locator('div')
    .filter({ hasText: 'Allow MCP Mutations' })
    .locator('input[type="checkbox"]')
    .first()
  const initialMutationAllowed = await mutationsToggle.isChecked()
  if (initialMutationAllowed) {
    await mutationsToggle.uncheck({ force: true })
  } else {
    await mutationsToggle.check({ force: true })
  }

  const applyButton = page.getByRole('button', { name: 'Apply API Settings' })
  await applyButton.scrollIntoViewIfNeeded()
  await applyButton.click()
  await expect(page.getByText('✓ Saved')).toBeVisible()

  const settingsResponse = await request.get('http://127.0.0.1:8111/api/settings')
  expect(settingsResponse.ok()).toBeTruthy()

  const payload = await settingsResponse.json()
  expect(['mcp', 'legacy']).toContain(payload.tool_backend)
  expect(payload.mcp_server_url).toBe(existingMcpUrl)
  expect(payload.mcp_allow_mutations).toBe(!initialMutationAllowed)
})
