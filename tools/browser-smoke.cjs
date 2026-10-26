// Optional browser verification against the loopback integration fixture.
// Requires Playwright + Chromium; no website or external service is contacted.
const {chromium} = require('playwright');
const fs = require('node:fs');
const assert = require('node:assert/strict');
const c = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
(async () => {
 const browser = await chromium.launch({headless:true,executablePath:process.env.WORKGLEN_CHROMIUM,args:['--no-sandbox',...(process.env.WORKGLEN_BROWSER_SINGLE_PROCESS ? ['--single-process','--no-zygote'] : [])]});
 const context = await browser.newContext({ignoreHTTPSErrors:true,viewport:{width:1440,height:1050}});
 const page = await context.newPage();
 const errors = []; page.on('pageerror',e=>errors.push(e.message)); page.on('console',m=>{ if(m.type()==='error' && /content.security|refused to/i.test(m.text())) errors.push(m.text()); });
 try {
  await page.goto(c.primary);await page.locator('#login-form').waitFor();
  await page.screenshot({path:c.work+'/web-login.png',fullPage:true,animations:'disabled'});
  await page.locator('#username').fill('admin');await page.locator('#password').fill(c.password);await page.getByRole('button',{name:'Sign in',exact:false}).click();
  await page.locator('#service-headline').filter({hasText:'Ready to serve'}).waitFor();
  await page.screenshot({path:c.work+'/web-overview.png',fullPage:true,animations:'disabled'});
  assert.match(await page.title(),/Workglen/);
  await page.getByRole('button',{name:'Capacity',exact:true}).click();await page.locator('#capacity-connections').filter({hasText:'16'}).waitFor();
  await page.screenshot({path:c.work+'/workglen-capacity.png',fullPage:true,animations:'disabled'});

  await page.getByRole('button',{name:'Modules',exact:true}).click();await page.locator('#toggle-mail').waitFor();
  assert.equal(await page.locator('#planned-modules .module-card').count(),10);
  assert.equal(await page.locator('#planned-modules button').count(),0);
  await page.screenshot({path:c.work+'/workglen-modules.png',fullPage:true,animations:'disabled'});
  await page.locator('#toggle-mail').click();await page.locator('#cancel-module').click();
  assert.equal(await page.locator('#module-dialog').isVisible(),false);
  await page.locator('#toggle-mail').click();await page.locator('#confirm-module').click();
  await page.locator('#toggle-mail').filter({hasText:'Enable Mail'}).waitFor();
  assert.equal(await page.getByRole('button',{name:'Mailboxes',exact:true}).count(),0);
  await page.getByRole('button',{name:'Core services',exact:true}).click();await page.locator('#foundation').waitFor();
  await page.screenshot({path:c.work+'/workglen-foundation.png',fullPage:true,animations:'disabled'});
  await page.getByRole('button',{name:'Modules',exact:true}).click();
  await page.locator('#toggle-mail').click();await page.locator('#toggle-mail').filter({hasText:'Disable Mail'}).waitFor();
  await page.getByRole('button',{name:'Mailboxes',exact:true}).click();
  await page.locator('#accounts-body tr').first().waitFor();await page.locator('#add-account').click();
  await page.locator('#account-email').fill('browser@example.test');await page.locator('#account-password').fill('browser-password-long');await page.locator('#account-confirm').fill('browser-password-long');await page.locator('#save-account').click();
  await page.locator('#account-dialog').waitFor({state:'hidden'});await page.locator('#account-search').fill('browser@');
  await page.getByText('browser@example.test',{exact:true}).waitFor();
  await page.locator('[data-reset="browser@example.test"]').click();await page.locator('#account-password').fill('changed-browser-password');await page.locator('#account-confirm').fill('different-password');await page.locator('#save-account').click();
  assert.match(await page.locator('#account-error').textContent(),/do not match/);
  await page.locator('#account-confirm').fill('changed-browser-password');await page.locator('#save-account').click();await page.locator('#account-dialog').waitFor({state:'hidden'});
  await page.locator('#account-search').fill('');await page.screenshot({path:c.work+'/web-accounts.png',fullPage:true,animations:'disabled'});
  await page.getByRole('button',{name:'Mail protection',exact:true}).click();await page.getByText('Always evaluated',{exact:true}).waitFor();
  await page.getByRole('button',{name:'Delivery queue',exact:true}).click();await page.locator('#queue-empty').waitFor();assert.match(await page.locator('#queue-routing').textContent(),/relay/i);
  await page.getByRole('button',{name:'Backups',exact:true}).click();await page.locator('#create-backup').click();await page.locator('#backup-result').filter({hasText:'Completed backup'}).waitFor();
  await page.getByRole('button',{name:'Overview',exact:true}).click();await page.locator('#service-headline').waitFor();
  await page.locator('.deployment-guide summary').click();await page.getByText('Two nodes → single node',{exact:true}).waitFor();await page.locator('.deployment-guide summary').click();
  await page.getByRole('button',{name:'Modules',exact:true}).click();await page.locator('#toggle-mail').waitFor();
  await page.setViewportSize({width:390,height:844});await page.screenshot({path:c.work+'/web-mobile.png',fullPage:true,animations:'disabled'});
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>window.innerWidth),false,'no mobile page overflow');
  await page.locator('#logout').click();await page.locator('#login-view').waitFor();
  const standby = await context.newPage();await standby.goto(c.standby);await standby.locator('#username').fill('admin');await standby.locator('#password').fill(c.password);await standby.locator('#login-form button').click();await standby.locator('#standby-notice').waitFor();
  await standby.getByRole('button',{name:'Mailboxes',exact:true}).click();assert.equal(await standby.locator('#add-account').isDisabled(),true);
  await standby.getByRole('button',{name:'Modules',exact:true}).click();await standby.locator('#toggle-mail').waitFor();assert.equal(await standby.locator('#toggle-mail').isDisabled(),true);
  await standby.locator('#logout').click();
  assert.deepEqual(errors,[],'no browser script or CSP errors');
  fs.writeFileSync(c.work+'/browser-results.json',JSON.stringify({passed:true,checks:['capacity and configured limits','Workglen branding','module roadmap','cancel disable','disable and re-enable Mail','navigation follows module state','Core with Mail disabled','standby module read-only','HTTPS login','account creation','password confirmation and reset','security rules','queue empty state','backup creation','deployment guide','mobile without overflow','logout','standby read-only'],errors},null,2));
  console.log('Browser smoke checks passed');
 } finally { await browser.close(); }
})().catch(e=>{console.error(e);process.exit(1)});
