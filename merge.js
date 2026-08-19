const fs = require('fs');
const yaml = require('yaml');

// ========== 配置区 ==========
const REGION_RULES = [
  { reg: /香港|HK|HKG|hk|🇭🇰/, flag: "🇭🇰", name: "香港" },
  { reg: /台湾|TW|tw|🇹🇼/, flag: "🇹🇼", name: "台湾" },
  { reg: /日本|JP|JPN|jp|🇯🇵/, flag: "🇯🇵", name: "日本" },
  { reg: /美国|US|USA|us|🇺🇸/, flag: "🇺🇸", name: "美国" },
  { reg: /新加坡|SG|SGP|sg|🇸🇬/, flag: "🇸🇬", name: "新加坡" },
  { reg: /韩国|KR|KOR|kr|🇰🇷/, flag: "🇰🇷", name: "韩国" },
];

const SKIP_TYPES = new Set(["http","socks5","ss","ssr","snell","vmess","trojan","hysteria","wireguard","tailscale","ssh","openvpn"]);

const SUBS = JSON.parse(fs.readFileSync("./subs.json", "utf8"));
const OUTPUT_FILE = "nodes.yaml";
const REQUEST_TIMEOUT = 15000;
// ========================================================

const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));

/**
 * 带超时请求
 */
async function fetchWithTimeout(url) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT);
  try {
    const res = await fetch(url, { signal: controller.signal });
    return res;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * 深度清洗对象（消除 yaml 内部标记）
 */
function cleanProxyObj(obj) {
  return JSON.parse(JSON.stringify(obj));
}

/**
 * 计算节点指纹（去重依据）
 */
function getFingerprint(p) {
  const type = p.type.toLowerCase();
  if (type === 'vless' && p['reality-opts']?.['public-key']) {
    return `${type}|${p.server}|${p.uuid}|${p['reality-opts']['public-key']}`;
  } else {
    return `${type}|${p.server}|${p.port}`;
  }
}

(async function main() {
  console.log(`===== 开始处理，共 ${SUBS.length} 个订阅 =====\n`);

  // 存放所有通过类型过滤 + 地区匹配的候选节点（未去重、未重命名）
  const allCandidates = [];

  for (let i = 0; i < SUBS.length; i++) {
    const subUrl = SUBS[i];
    console.log(`--- [${i + 1}/${SUBS.length}] ${subUrl}`);

    try {
      const res = await fetchWithTimeout(subUrl);
      if (!res.ok) {
        console.log(`  ❌ HTTP 失败，状态码：${res.status}`);
        continue;
      }

      const text = await res.text();
      const doc = yaml.parse(text);

      let rawProxies = [];
      if (Array.isArray(doc)) {
        rawProxies = doc;
      } else if (doc && Array.isArray(doc.proxies)) {
        rawProxies = doc.proxies;
      } else {
        console.log(`  ⚠️ 未找到 proxies 数组，跳过`);
        continue;
      }
      console.log(`  📥 原始节点数：${rawProxies.length}`);

      // 1. 类型过滤
      const typeFiltered = rawProxies.filter(p => {
        if (!p || !p.type) return false;
        return !SKIP_TYPES.has(p.type.toLowerCase());
      });
      console.log(`  🔍 类型过滤后：${typeFiltered.length}`);

      // 2. 地区匹配（仅筛选，不重命名）
      let matchedCount = 0;
      for (const rawP of typeFiltered) {
        const p = cleanProxyObj(rawP);
        if (!p.name || !p.server || !p.port) continue;

        const hit = REGION_RULES.find(r => r.reg.test(p.name));
        if (!hit) continue;

        // 暂存原始名称（保留给后续重命名用）
        allCandidates.push(p);
        matchedCount++;
      }
      console.log(`  ✅ 地区匹配候选节点数：${matchedCount}\n`);

    } catch (e) {
      console.log(`  ❌ 处理失败：${e.message}\n`);
    }
  }

  // ========== 全局去重 ==========
  const seen = new Set();
  const uniqueProxies = [];
  for (const p of allCandidates) {
    const fp = getFingerprint(p);
    if (seen.has(fp)) continue;
    seen.add(fp);
    uniqueProxies.push(p);
  }
  console.log(`\n全局候选节点总数：${allCandidates.length}`);
  console.log(`去重后节点数：${uniqueProxies.length}`);

  // ========== 统一重命名 ==========
  const regionCounter = {};
  for (const p of uniqueProxies) {
    const hit = REGION_RULES.find(r => r.reg.test(p.name));
    if (!hit) continue; // 理论上都有
    regionCounter[hit.name] = (regionCounter[hit.name] || 0) + 1;
    const seq = String(regionCounter[hit.name]).padStart(2, "0");
    p.name = `${hit.flag} ${hit.name} ${seq} | ${p.type}`;
  }

  // 输出统计
  console.log('\n===== 处理完成 =====');
  console.log(`总有效节点数（去重后）：${uniqueProxies.length}`);
  console.log('各地区数量：');
  for (const [name, count] of Object.entries(regionCounter)) {
    console.log(`  ${name}：${count}`);
  }

  // 生成 YAML
  const outputDoc = new yaml.Document();
  outputDoc.set("proxies", uniqueProxies);
  const outputYaml = outputDoc.toString({
    indent: 2,
    flow: false,
    singleQuote: false,
    doubleQuote: false,
    lineWidth: 0
  });

  fs.writeFileSync(OUTPUT_FILE, outputYaml);
  console.log(`\n✅ 已输出至 ${OUTPUT_FILE}`);
})();
