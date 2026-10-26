const {chromium}=require('playwright'),fs=require('node:fs'),assert=require('node:assert/strict');
const c=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));
(async()=>{const b=await chromium.launch({headless:true,executablePath:process.env.WORKGLEN_CHROMIUM,args:['--no-sandbox','--single-process','--no-zygote']});try{
const page=await b.newPage({ignoreHTTPSErrors:true}),errors=[];page.on('pageerror',e=>errors.push(e.message));
await page.goto(c.url);await page.locator('[name=username]').fill('admin');await page.locator('[name=password]').fill(c.password);await page.locator('#login-form button').click();
await page.getByText('Your local Admin console is running.',{exact:true}).waitFor();
await page.locator('button[data-page=modules]').click();await page.getByText('Not run by the local Admin profile',{exact:true}).first().waitFor();
assert.equal(await page.locator('#toggle-mail').count(),0);assert.equal(await page.locator('#toggle-webmail').count(),0);
await page.goto(c.url+'/mail-security');await page.getByRole('heading',{name:'Protection at a glance'}).waitFor();
await page.getByText('Setup mode:',{exact:false}).waitFor();await page.screenshot({path:c.work+'/local-admin-gateway.png',fullPage:true});assert.deepEqual(errors,[]);
}finally{await b.close();}})().catch(e=>{console.error(e);process.exitCode=1;});
