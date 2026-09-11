import { createRequire } from 'node:module';
import assert from 'node:assert/strict';
const require = createRequire(`${process.env.LINKED_MANAGER_DIR}/frontend/package.json`);
const { chromium } = require('@playwright/test');
const browser = await chromium.launch({headless:true});
try {
 const page = await browser.newPage({viewport:{width:1440,height:1000}});
 const errors=[];
 page.on('pageerror', error => errors.push(error.message));
 await page.goto(process.env.LINKED_MANAGER_URL);
 await page.locator('input[type=password]').fill(process.env.LINKED_PASSWORD);
 await page.locator('button[type=submit]').click();
 await page.locator('aside').waitFor();
 await page.evaluate(id=>localStorage.setItem('spm_selected_host_id',id),process.env.LINKED_HOST_ID);
 await page.reload();
 for (const label of ['Dashboard','Hosts Fleet','Nodes','Slots Manager','Policy Routing','Prom Metrics','Events & Logs','Share Links','Subscriptions','Settings','Audit Log']) {
  await page.locator('aside button').filter({hasText:label}).click();
  await page.waitForTimeout(500);
  assert.equal(await page.locator('aside').count(),1,`page disappeared: ${label}`);
  if (label === 'Share Links') {
   await page.getByText('Clash Meta',{exact:true}).waitFor();
   await page.locator('button').filter({hasText:'QR'}).first().click();
   await page.locator('canvas').waitFor();
   await page.locator('div.fixed.inset-0 button').first().click();
  }
 }
 assert.deepEqual(errors,[],'browser runtime errors');
 console.log('PASS: real Chromium login, eleven pages with empty VPN pool, canonical profile display and QR');
} finally { await browser.close(); }
