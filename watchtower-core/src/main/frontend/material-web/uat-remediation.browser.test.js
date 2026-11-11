/** Local real-Material browser contract. This is supplemental to the required deployed UAT. */
const {chromium} = require('@playwright/test');
const {readFileSync, existsSync} = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const assert = require('node:assert/strict');
const root = path.resolve(__dirname, '../../../../..');
const resources = path.join(root, 'watchtower-core/src/main/resources/static');
let submits = 0;
const script = name => `<script nonce="uat-local" src="/scripts/${name}"></script>`;
let html = readFileSync(path.join(root, 'watchtower-web/src/main/resources/templates/login.html'), 'utf8')
  .replace(/th:[\w-]+="[^"]*"/g, '')
  .replace(/<head\s*><\/head>/, `<head><meta name="viewport" content="width=device-width">${script('material-web-bundle.js')}<link rel="stylesheet" href="/styles/tokens.css"><link rel="stylesheet" href="/styles/md-theme.css"><link rel="stylesheet" href="/styles/base.css"><link rel="stylesheet" href="/styles/components.css"></head>`)
  .replace('src="/scripts/login.js"', 'nonce="uat-local" src="/scripts/login.js"');
const server = http.createServer((request, response) => {
  if (request.method === 'POST' && request.url === '/login') {
    submits++;request.resume();response.writeHead(303, {Location:'/login?error=invalid'});response.end();return;
  }
  response.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'nonce-uat-local' 'strict-dynamic'; style-src 'self' 'unsafe-inline'; font-src 'self'");
  if (request.url.startsWith('/login')) {response.setHeader('Content-Type','text/html');response.end(html);return;}
  const file = path.join(resources, request.url.split('?')[0]);
  if (!file.startsWith(resources + path.sep) || !existsSync(file)) {response.statusCode=404;response.end();return;}
  response.setHeader('Content-Type',file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':file.endsWith('.woff2')?'font/woff2':'application/octet-stream');
  response.end(readFileSync(file));
});
(async () => {
 await new Promise(resolve => server.listen(0,'127.0.0.1',resolve));
 let browser;
 try {
  const installed = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
  browser = await chromium.launch({headless:true,...(existsSync(chromium.executablePath())?{}:{executablePath:installed})});
  const page = await browser.newPage();
  const failures=[];page.on('pageerror',error=>failures.push(error.message));
  const base = `http://127.0.0.1:${server.address().port}`;
  await page.goto(base+'/login');
  await page.getByRole('textbox',{name:'Username',exact:true}).fill('fixture-user');
  await page.locator('#inputPassword4 input').fill('fixture-invalid-password');
  await Promise.all([page.waitForURL('**/login?error=invalid'),page.locator('#inputPassword4 input').press('Enter')]);
  assert.equal(submits,1,'Enter submits once');
  await page.getByRole('textbox',{name:'Username',exact:true}).fill('fixture-user');
  await page.locator('#inputPassword4 input').fill('fixture-invalid-password');
  await Promise.all([page.waitForResponse(r=>r.request().method()==='POST'),page.getByRole('button',{name:'Login',exact:true}).click()]);
  assert.equal(submits,2,'Click submits once');
  await page.waitForLoadState();
  await page.evaluate(() => { const form=document.getElementById('login_form');form.addEventListener('submit',e=>e.preventDefault());const field=document.getElementById('inputPassword4');field.dispatchEvent(new KeyboardEvent('keydown',{key:'Enter',bubbles:true,composed:true,isComposing:true})); });
  assert.equal(submits,2,'Composition does not submit');
  await page.setViewportSize({width:390,height:844});
  await page.screenshot({path:'/tmp/watchtower-uat-login-mobile.png',fullPage:true});
  assert.deepEqual(failures,[]);
  console.log('Real Chrome + Material + nonce CSP: Enter once, click once, composition guarded; mobile fixture rendered.');
 } finally {if(browser)await browser.close();await new Promise(resolve=>server.close(resolve));}
})().catch(error=>{console.error(error);process.exitCode=1;});
