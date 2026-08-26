// -------------------------------------------------- 配置区 --------------------------------------------------
const fs = require('fs');
const yaml = require('yaml');
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));

const SUBS = JSON.parse(fs.readFileSync("./subs.json", "utf8"));
const OUTPUT_FILE = "nodes.yaml";
const REGION_OUTPUT_FILE = "nodes_regionfiltered.yaml";
const REQUEST_TIMEOUT = 15000;

const SKIP_TYPES = new Set(["http", "socks5", "ss", "ssr", "vmess", "trojan", "hysteria", "wireguard", "tailscale", "ssh", "openvpn"]);

// 地区筛选规则：匹配节点名称中的关键词，提取地区名
// 按顺序匹配，命中第一个即停止
const REGION_FILTERS = [
  { regex: /香港|Hong Kong|HK/i, name: "香港" },
  { regex: /台湾|Taiwan|TW/i, name: "台湾" },
  { regex: /日本|Japen|JP/i, name: "日本" },
  { regex: /韩国|Korea|KR/i, name: "韩国" },
  { regex: /新加坡|Singapore|SG/i, name: "新加坡" },
  { regex: /美国|United States|US/i, name: "美国" },
];
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

  // 4. 地区筛选（基于节点名称）
  const regionFiltered = [];
  if (REGION_FILTERS && REGION_FILTERS.length > 0) {
    console.log(`\n开始地区筛选，规则数：${REGION_FILTERS.length}`);
    for (const p of dedupList) {
      const name = p.name || '';
      let matchedRegion = null;
      for (const filter of REGION_FILTERS) {
        if (filter.regex.test(name)) {
          matchedRegion = filter.name;
          break;
        }
      }
      if (matchedRegion) {
        // 复制节点避免影响原列表
        const newNode = { ...p };
        newNode._region = matchedRegion; // 临时存储地区名
        regionFiltered.push(newNode);
      }
    }
    // 重命名：序号 + 地区
    regionFiltered.forEach((node, idx) => {
      node.name = `${idx + 1} ${node._region}`;
      delete node._region;
    });
    console.log(`地区筛选后节点数：${regionFiltered.length}`);
  } else {
    console.log(`⚠️ 未配置地区筛选规则，跳过地区筛选`);
  }

  // 5. 输出结果
  // 5a. 输出全部去重节点（nodes.yaml）
  console.log(`\n✅ 最终输出节点总数（全部）：${dedupList.length}`);
  const docAll = new yaml.Document();
  docAll.set('proxies', dedupList);
  fs.writeFileSync(OUTPUT_FILE, docAll.toString({ indent: 2, lineWidth: 0 }));
  console.log(`✅ 已保存全部节点至 ${OUTPUT_FILE}`);

  // 5b. 输出地区筛选后的节点（nodes_regionfiltered.yaml）
  if (regionFiltered.length > 0) {
    const docRegion = new yaml.Document();
    docRegion.set('proxies', regionFiltered);
    fs.writeFileSync(REGION_OUTPUT_FILE, docRegion.toString({ indent: 2, lineWidth: 0 }));
    console.log(`✅ 已保存地区筛选节点至 ${REGION_OUTPUT_FILE}`);
  } else {
    // 写入空文件或跳过
    fs.writeFileSync(REGION_OUTPUT_FILE, 'proxies: []\n');
    console.log(`⚠️ 地区筛选结果为空，已写入空文件 ${REGION_OUTPUT_FILE}`);
  }
})();
// -------------------------------------------------- 主程序区 --------------------------------------------------
