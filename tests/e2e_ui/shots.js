// Screenshot every console page (static, no SSE) for UI review: node shots.js <base url> <out dir>
const puppeteer = require("puppeteer-core");
(async () => {
  const [base, out] = [process.argv[2], process.argv[3]];
  const b = await puppeteer.launch({ executablePath: process.env.AICL_CHROME || "C:/Program Files/Google/Chrome/Application/chrome.exe", headless: "new" });
  const p = await b.newPage();
  await p.setViewport({ width: 1440, height: 900 });
  for (const pg of ["overview", "clients", "playground", "security", "network", "controls", "policy", "performance"]) {
    await p.goto("about:blank");
    await p.goto(base + "/console?nolive=1#" + pg, { waitUntil: "networkidle2" }).catch(() => {});
    await new Promise((r) => setTimeout(r, 1500));
    await p.screenshot({ path: `${out}/ui-${pg}.png`, fullPage: true });
  }
  await b.close();
})();
