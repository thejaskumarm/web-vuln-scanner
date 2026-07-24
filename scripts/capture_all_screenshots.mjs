import { createRequire } from 'module';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const require = createRequire(import.meta.url);
const puppeteer = require('/Users/bhuvangm/projects/soc analyst dashboard/node_modules/puppeteer-core');

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '..');
const imgDir = path.join(projectRoot, 'docs', 'screenshots');

if (!fs.existsSync(imgDir)) {
  fs.mkdirSync(imgDir, { recursive: true });
}

const CHROME_PATH = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';

async function run() {
  console.log('🚀 Starting Screenshot Capture for Both Projects...');

  const browser = await puppeteer.launch({
    executablePath: CHROME_PATH,
    headless: 'new',
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--window-size=1440,960']
  });

  const page = await browser.newPage();
  await page.setViewport({ width: 1440, height: 960, deviceScaleFactor: 2 });

  // ==========================================
  // PROJECT 1: Web Vulnerability Scanner
  // ==========================================
  console.log('\n--- PROJECT 1: Web Vulnerability Scanner ---');
  console.log('🌐 Navigating to http://localhost:8080 ...');
  await page.goto('http://localhost:8080/', { waitUntil: 'networkidle0' });
  await page.evaluate(() => new Promise(r => setTimeout(r, 1000)));

  // Screenshot 1: Landing Page
  console.log('📸 Capturing 01_vuln_scanner_landing.png ...');
  await page.screenshot({ path: path.join(imgDir, '01_vuln_scanner_landing.png') });

  // Type URL and start scan
  console.log('⚡ Entering target URL and starting scan...');
  await page.type('#url-input', 'https://example.com');
  await page.click('#scan-btn');

  // Screenshot 2: Scan in progress
  await page.evaluate(() => new Promise(r => setTimeout(r, 1500)));
  console.log('📸 Capturing 02_vuln_scanner_progress.png ...');
  await page.screenshot({ path: path.join(imgDir, '02_vuln_scanner_progress.png') });

  // Wait for scan complete
  console.log('⏳ Waiting for scan completion...');
  await page.evaluate(() => new Promise(r => setTimeout(r, 7000)));
  console.log('📸 Capturing 03_vuln_scanner_results.png ...');
  await page.screenshot({ path: path.join(imgDir, '03_vuln_scanner_results.png') });

  // Screenshot 4: Offline HTML Report view (if available)
  const reportPath = path.join(projectRoot, 'thejas_report.html');
  if (fs.existsSync(reportPath)) {
    console.log('📄 Rendering offline HTML report for screenshot 4...');
    await page.goto(`file://${reportPath}`, { waitUntil: 'networkidle0' });
    await page.evaluate(() => new Promise(r => setTimeout(r, 1000)));
    console.log('📸 Capturing 04_vuln_scanner_report.png ...');
    await page.screenshot({ path: path.join(imgDir, '04_vuln_scanner_report.png') });
  }

  // ==========================================
  // PROJECT 2: AEGIS SOC Analyst Dashboard
  // ==========================================
  console.log('\n--- PROJECT 2: AEGIS SOC Analyst Dashboard ---');
  console.log('🌐 Navigating to http://localhost:5173 ...');
  await page.goto('http://localhost:5173/', { waitUntil: 'networkidle0' });
  await page.evaluate(() => new Promise(r => setTimeout(r, 1000)));

  // Screenshot 5: Main Overview
  console.log('📸 Capturing 05_soc_overview.png ...');
  await page.screenshot({ path: path.join(imgDir, '05_soc_overview.png') });

  // Trigger DDoS Attack
  console.log('⚡ Triggering DDoS Attack Simulation...');
  const buttons = await page.$$('button');
  for (const btn of buttons) {
    const text = await page.evaluate(el => el.textContent, btn);
    if (text && text.includes('DDoS Flood')) {
      await btn.click();
      break;
    }
  }
  await page.evaluate(() => new Promise(r => setTimeout(r, 1500)));
  console.log('📸 Capturing 06_soc_attack_simulation.png ...');
  await page.screenshot({ path: path.join(imgDir, '06_soc_attack_simulation.png') });

  // Tab 2: Live Log Feed
  console.log('📜 Navigating to Live Log Feed tab...');
  const tabs = await page.$$('button');
  for (const tab of tabs) {
    const text = await page.evaluate(el => el.textContent, tab);
    if (text && text.includes('Live Log Feed')) {
      await tab.click();
      break;
    }
  }
  await page.evaluate(() => new Promise(r => setTimeout(r, 1000)));
  console.log('📸 Capturing 07_soc_log_table.png ...');
  await page.screenshot({ path: path.join(imgDir, '07_soc_log_table.png') });

  // Inspect Modal
  console.log('🔍 Inspecting first log row payload...');
  const inspectBtns = await page.$$('button');
  for (const btn of inspectBtns) {
    const text = await page.evaluate(el => el.textContent, btn);
    if (text && text.includes('Inspect')) {
      await btn.click();
      break;
    }
  }
  await page.evaluate(() => new Promise(r => setTimeout(r, 1000)));
  console.log('📸 Capturing 08_soc_payload_modal.png ...');
  await page.screenshot({ path: path.join(imgDir, '08_soc_payload_modal.png') });

  // Close modal by pressing Escape
  await page.keyboard.press('Escape');
  await page.evaluate(() => new Promise(r => setTimeout(r, 500)));

  // Tab 3: Threat Alerts
  console.log('🚨 Navigating to Threat Alerts tab...');
  const tabsAlerts = await page.$$('button');
  for (const tab of tabsAlerts) {
    const text = await page.evaluate(el => el.textContent, tab);
    if (text && text.includes('Threat Alerts')) {
      await tab.click();
      break;
    }
  }
  await page.evaluate(() => new Promise(r => setTimeout(r, 1000)));
  console.log('📸 Capturing 09_soc_alert_triage.png ...');
  await page.screenshot({ path: path.join(imgDir, '09_soc_alert_triage.png') });

  // Tab 4: Grafana Visualizer
  console.log('📊 Navigating to Grafana Visualizer tab...');
  const tabsGrafana = await page.$$('button');
  for (const tab of tabsGrafana) {
    const text = await page.evaluate(el => el.textContent, tab);
    if (text && text.includes('Grafana Visualizer')) {
      await tab.click();
      break;
    }
  }
  await page.evaluate(() => new Promise(r => setTimeout(r, 1000)));
  console.log('📸 Capturing 10_soc_grafana_visualizer.png ...');
  await page.screenshot({ path: path.join(imgDir, '10_soc_grafana_visualizer.png') });

  // Tab 5: Firewall & IP Bans
  console.log('🛡️ Navigating to Firewall & IP Bans tab...');
  const tabsFirewall = await page.$$('button');
  for (const tab of tabsFirewall) {
    const text = await page.evaluate(el => el.textContent, tab);
    if (text && text.includes('Firewall')) {
      await tab.click();
      break;
    }
  }
  await page.evaluate(() => new Promise(r => setTimeout(r, 1000)));
  console.log('📸 Capturing 11_soc_firewall_rules.png ...');
  await page.screenshot({ path: path.join(imgDir, '11_soc_firewall_rules.png') });

  await browser.close();
  console.log('✅ Screenshot capture completed successfully!');
}

run().catch(err => {
  console.error('❌ Error capturing screenshots:', err);
  process.exit(1);
});
