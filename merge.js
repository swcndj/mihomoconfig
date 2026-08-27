// -------------------------------------------------- 配置区 --------------------------------------------------
const fs = require('fs');
const yaml = require('yaml');
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));
const SUBS = JSON.parse(fs.readFileSync("./subs.json", "utf8"));
const OUTPUT_FILE = "nodes.yaml";
const REGION_OUTPUT_FILE = "nodes_regionfiltered.yaml";
const REQUEST_TIMEOUT = 15000;
const SKIP_TYPES = new Set(["http", "socks5", "ss", "ssr", "vmess", "trojan", "hysteria", "wireguard", "tailscale", "ssh", "openvpn"]);

// 名称初筛正则：只要节点名称命中任意一条，就进入API校验候选池（仅用来减少API调用）
const PRE_FILTER_REGEX = /香港|Hong Kong|HK|台湾|Taiwan|TW|日本|Japen|JP|韩国|Korea|KR|新加坡|Singapore|SG|美国|United States|US/i;

// 目标地区：countryCode为key，对应显示名称
const TARGET_COUNTRY_MAP = {
  'HK': "🇭🇰 HK",
  'TW': "🇹🇼 TW",
  'JP': "🇯🇵 JP",
  'KR': "🇰🇷 KR",
  'SG': "🇸🇬 SG",
  'US': "🇺🇸 US",
};

// IP‑API免费限制：45次/分钟，间隔1500ms防429限流
const IP_QUERY_INTERVAL = 1500;
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

function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// 查询ip‑api，返回大写countryCode，失败返回null
async function getIpCountryCode(ipOrDomain) {
  try {
    const res = await fetchWithTimeout(`http://ip-api.com/json/${encodeURIComponent(ipOrDomain)}`);
    if (!res.ok) return null;
    const data = await res.json();
    return data.status === 'success' ? String(data.countryCode).toUpperCase() : null;
  } catch (e) {
    return null;
  }
}
// -------------------------------------------------- 工具函数 --------------------------------------------------

// -------------------------------------------------- 主程序区 --------------------------------------------------
(async function main() {
  console.log(`===== 开始处理，共 ${SUBS.length} 个订阅 =====\n`);
  const allRawProxies = [];

  // 1. 拉取所有订阅
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

  // 2. 节点类型过滤
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

  // 3. 节点去重
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

  // 4. 地区筛选逻辑：名称初筛进入候选池 → 调用ip‑api拿到countryCode，只要在TARGET_COUNTRY_MAP就保留
  const regionFiltered = [];
  // 4.1 名称初筛，仅用来减少API请求，不做最终判定
  const preFiltered = dedupList.filter(p => PRE_FILTER_REGEX.test(p.name || ''));
  console.log(`名称初筛候选节点数：${preFiltered.length}`);

  console.log(`\n开始IP地理校验，共 ${preFiltered.length} 个节点...`);
  for (let i = 0; i < preFiltered.length; i++) {
    const node = preFiltered[i];
    const server = node.server;
    if (!server) {
      console.log(`  [${i + 1}/${preFiltered.length}] ⚠️ 无server字段，跳过`);
      continue;
    }

    console.log(`  [${i + 1}/${preFiltered.length}] 查询 ${server} ...`);
    const cc = await getIpCountryCode(server);

    // 只要返回的countryCode在目标映射表里就保留，不再和原节点名称地区做比对
    if (cc && TARGET_COUNTRY_MAP[cc]) {
      regionFiltered.push({
        node: { ...node },
        countryCode: cc,
        displayName: TARGET_COUNTRY_MAP[cc]
      });
      console.log(`    ✅ 命中地区 ${cc}`);
    } else {
      console.log(`    ❌ 丢弃，countryCode: ${cc || "查询失败"}`);
    }
    await delay(IP_QUERY_INTERVAL);
  }

  // 4.2 根据接口返回的countryCode重命名节点，格式：序号 地区标识
  regionFiltered.forEach((item, idx) => {
    item.node.name = `${idx + 1} ${item.displayName}`;
  });
  console.log(`\n地区最终筛选后节点数：${regionFiltered.length}`);

  // 5. 输出结果
  const docAll = new yaml.Document();
  docAll.set('proxies', dedupList);
  fs.writeFileSync(OUTPUT_FILE, docAll.toString({ indent: 2, lineWidth: 0 }));
  console.log(`✅ 已保存去重后节点至 ${OUTPUT_FILE}`);

  if (regionFiltered.length > 0) {
    const nodesForRegion = regionFiltered.map(item => item.node);
    const docRegion = new yaml.Document();
    docRegion.set('proxies', nodesForRegion);
    fs.writeFileSync(REGION_OUTPUT_FILE, docRegion.toString({ indent: 2, lineWidth: 0 }));
    console.log(`✅ 已保存地区筛选节点至 ${REGION_OUTPUT_FILE}`);
  } else {
    fs.writeFileSync(REGION_OUTPUT_FILE, 'proxies: []\n');
    console.log(`⚠️ 地区筛选结果为空，已写入空文件 ${REGION_OUTPUT_FILE}`);
  }
})();
// -------------------------------------------------- 主程序区 --------------------------------------------------
