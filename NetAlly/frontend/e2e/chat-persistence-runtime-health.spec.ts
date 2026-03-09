import { expect, test } from '@playwright/test'

test('Chat session persists across reload and runtime degraded banner is visible', async ({ page }) => {
  await page.route('**/api/dashboard/summary?**', async route => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        health_score: 88,
        mode: 'lab',
        protocols: {
          bgp: { total: 2, up: 1, down: 1, status: 'warning' },
          ospf: { total: 1, up: 1, down: 0, status: 'healthy' },
        },
        issues: [],
        device_status: {},
        compliance: { routing: 90, security: 94 },
      }),
    })
  })

  await page.route('**/api/runtime/health', async route => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        status: 'ok',
        overall: 'degraded',
        recommendedMode: 'limited',
        checkedAt: new Date().toISOString(),
        services: {
          batfish: { status: 'not_ready', severity: 'warning', detail: 'Run Prepare' },
          nso: { status: 'ok', severity: 'ok', detail: '2 devices reachable' },
          pnetlab: { status: 'ok', severity: 'ok', detail: 'Lab reachable' },
        },
        notes: ['Run Prepare to load Batfish snapshot for full path verification.'],
      }),
    })
  })

  await page.route('**/api/chat', async route => {
    const events = [
      '{"type":"planning","reasoning":"plan ready"}',
      '{"type":"tool_call","tool":"batfish_path_check","call_id":1,"input":{"src":"R1","dst":"R2","test_type":"traceroute"}}',
      '{"type":"tool_output","tool":"batfish_path_check","call_id":1,"content":"{\\"status\\":\\"success\\"}","citation":{"id":"tool-call-1","type":"tool_output","tool":"batfish_path_check","status":"success","summary":"Traceroute path found","call_id":1}}',
      '{"type":"answer","content":"R1 can reach R2 via R3.","citations":[{"id":"tool-call-1","type":"tool_output","tool":"batfish_path_check","status":"success","summary":"Traceroute path found","call_id":1}],"grounding":{"supported_by_tools":true,"citation_count":1,"coverage":"tool_trace"}}',
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

  await expect(page.getByText('Degraded mode:')).toBeVisible()

  const input = page.locator('textarea[aria-label="Message input"]')
  await input.fill('check persistence')
  await input.press('Enter')

  await expect(page.getByText('R1 can reach R2 via R3.')).toBeVisible()
  await expect(page.getByText('Grounded by 1 tool evidence item(s)')).toBeVisible()

  await page.reload()

  await expect(page.getByText('check persistence')).toBeVisible()
  await expect(page.getByText('R1 can reach R2 via R3.')).toBeVisible()
  await expect(page.getByText('Grounded by 1 tool evidence item(s)')).toBeVisible()
})
