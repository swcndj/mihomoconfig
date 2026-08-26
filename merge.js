// -------------------------------------------------- 配置区 --------------------------------------------------
const fs = require('fs');
const yaml = require('yaml');
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));
const geoip = require('geoip-lite');

const SUBS = JSON.parse(fs.readFileSync("./subs.json", "utf8"));
const OUTPUT_FILE = "nodes.yaml";
const REQUEST_TIMEOUT = 15000;

const SKIP_TYPES = new Set(["http", "socks5", "ss", "ssr", "vmess", "trojan", "hysteria", "wireguard", "tailscale", "ssh", "openvpn"]);
const ALLOWED_REGIONS = ["HK", "MO", "TW", "JP", "KR", "SG", "TH", "AU", "US"]; // 留空保留所有地区节点
// -------------------------------------------------- 配置区 --------------------------------------------------

// -------------------------------------------------- 工具函数 --------------------------------------------------
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

function isValidNode(node) {
  return !!(node && node.type);
}

// IP 查询
async function getLocation(ip) {
  try {
    const data = geoip.lookup(ip);
    if (data) {
      return data.country; 
    }
    return '未知地区';
  } catch (e) {
    console.warn(`  ⚠️ IP 查询失败 (${ip}): ${e.message}`);
    return '未知地区';
  }
}
// -------------------------------------------------- 工具函数 --------------------------------------------------

// -------------------------------------------------- 主程序区 --------------------------------------------------
(async function main() {
  console.log(`===== 开始处理，共 ${SUBS.length} 个订阅 =====\n`);

  const allRawProxies = [];
  for (let i = 0; i < SUBS.length; i++) {
    const subUrl = SUBS[i];
    console.log(`--- [${i + 1}/${SUBS.length}] ${subUrl}`);
    try {
      const res = await fetchWithTimeout(subUrl);
      if (!res.ok) {
        console.log(`  ❌ HTTP ${res.status}`);
        continue;
      }
      const text = await res.text();
      const doc = yaml.parse(text);
      let proxies = doc?.proxies || (Array.isArray(doc) ? doc : []);
      if (!proxies.length) {
        console.log(`  ⚠️ 无 proxies 数组`);
        continue;
      }
      console.log(`  🌐 原始节点：${proxies.length}`);
      allRawProxies.push(...proxies);
    } catch (e) {
      console.log(`  ❌ 失败：${e.message}`);
    }
  }
  console.log(`\n总原始节点数：${allRawProxies.length}`);

  // 节点类型过滤
  const typeFiltered = [];
  for (const p of allRawProxies) {
    if (!isValidNode(p)) continue;
    const type = p.type.toLowerCase();
    if (SKIP_TYPES.has(type)) continue;
    if (type === 'vless') {
      const hasReality = !!p['reality-opts'];
      const hasXhttp = !!p['xhttp-opts'];
      if (!hasReality && !hasXhttp) continue;
      const enc = p.encryption;
      if (enc && typeof enc === 'string' && enc.length > 50) continue;
    }
    typeFiltered.push(p);
  }
  console.log(`类型过滤后节点数：${typeFiltered.length}`);

  // 去重
  const seen = new Set();
  const dedupList = [];
  for (const p of typeFiltered) {
    const type = p.type.toLowerCase();
    let fp;
    if (type === 'vless' && p['reality-opts']?.public_key) {
      fp = `${p.type}|${p.server}|${p.uuid}|${p['reality-opts'].public_key}`;
    } else {
      fp = `${p.type}|${p.server}|${p.port}`;
    }
    if (seen.has(fp)) continue;
    seen.add(fp);
    dedupList.push(p);
  }
  console.log(`去重后节点数：${dedupList.length}`);

  // 查询地区、过滤、重命名
  const finalProxies = [];
  const regionCount = {};
  let finalSeq = 0;

  for (const p of dedupList) {
    const region = await getLocation(p.server);
    if (ALLOWED_REGIONS.length > 0 && !ALLOWED_REGIONS.includes(region)) {
      continue;
    }
    
    finalSeq++;
    const seq = String(finalSeq).padStart(2, '0');
    p.name = `${seq} ${region} ${p.type}`;
    finalProxies.push(p);
    regionCount[region] = (regionCount[region] || 0) + 1;
  }

  console.log(`✅ 输出节点总数：${finalProxies.length}`);
  if (ALLOWED_REGIONS.length > 0) {
    console.log(`已过滤地区，保留${ALLOWED_REGIONS.join(', ')}节点`);
  } else {
    console.log('未过滤地区，保留所有节点');
  }
  console.log('各地区数量：');
  for (const [region, count] of Object.entries(regionCount)) {
    console.log(`  ${region}: ${count}`);
  }

  const doc = new yaml.Document();
  doc.set('proxies', finalProxies);
  fs.writeFileSync(OUTPUT_FILE, doc.toString({ indent: 2, lineWidth: 0 }));
  console.log(`\n✅ 已保存至 ${OUTPUT_FILE}`);
})();
// -------------------------------------------------- 主程序区 --------------------------------------------------
