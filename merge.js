// -------------------------------------------------- 配置区 --------------------------------------------------
const fs = require('fs');
const path = require('path');
const yaml = require('yaml');
const dns = require('dns').promises;
const { Reader } = require('@maxmind/geoip2-node');
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));

const SUBS = JSON.parse(fs.readFileSync(path.join(__dirname, "./subs.json"), "utf8"));
const OUTPUT_FILE = path.join(__dirname, "nodes.yaml");
// MMDB 数据库文件路径，默认和脚本同目录（仓库根目录放这里也可以，路径对应就行）
const MMDB_PATH = path.join(__dirname, "country.mmdb");
const REQUEST_TIMEOUT = 15000;

const SKIP_TYPES = new Set(["http", "socks5", "ss", "ssr", "vmess", "trojan", "hysteria", "wireguard", "tailscale", "ssh", "openvpn"]);
const ALLOWED_REGIONS = ["HK", "MO", "TW", "JP", "KR", "SG", "TH", "AU", "US"]; // 留空保留所有地区节点

// 全局缓存：域名/IP → 地区代码，避免重复解析查询
const locationCache = new Map();
// 加载 MMDB 数据库到内存，只执行一次
const mmdbBuffer = fs.readFileSync(MMDB_PATH);
const ipReader = Reader.openBuffer(mmdbBuffer);
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

// IP/域名 → 国家地区代码（本地 MMDB 查询 + DNS 域名解析）
async function getLocation(server) {
  // 前置空值校验
  if (!server || typeof server !== 'string') {
    return '未知地区';
  }

  const raw = server.trim();
  // 命中缓存直接返回
  if (locationCache.has(raw)) {
    return locationCache.get(raw);
  }

  try {
    let target = raw;
    // 移除 IPv6 地址前后的方括号
    if (target.startsWith('[') && target.endsWith(']')) {
      target = target.slice(1, -1);
    }

    // 判断是否为 IP 格式，非 IP 则先通过 DNS 解析
    const ipRegex = /^(?:\d{1,3}\.){3}\d{1,3}$|^[0-9a-fA-F:]+$/;
    if (!ipRegex.test(target)) {
      const resolved = await dns.resolve4(target).catch(() => []);
      if (resolved.length === 0) {
        locationCache.set(raw, '未知地区');
        return '未知地区';
      }
      target = resolved[0];
    }

    // 本地 MMDB 查询国家代码
    const result = ipReader.country(target);
    const region = result.country.isoCode;
    locationCache.set(raw, region);
    return region;
  } catch (e) {
    console.warn(`  ⚠️ IP 查询失败 (${server}): ${e.message}`);
    locationCache.set(raw, '未知地区');
    return '未知地区';
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

  // 4. 地区查询、过滤、重命名
  const finalProxies = [];
  const regionCount = {};
  let finalSeq = 0;
  // 根据节点总数动态计算序号位数，保证字典序正确
  const seqWidth = String(dedupList.length).length;

  for (const p of dedupList) {
    const region = await getLocation(p.server);
    if (ALLOWED_REGIONS.length > 0 && !ALLOWED_REGIONS.includes(region)) {
      continue;
    }
    
    finalSeq++;
    const seq = String(finalSeq).padStart(seqWidth, '0');
    // 创建新对象，不修改原始节点数据
    const node = {
      ...p,
      name: `${seq} ${region} ${p.type} ${p.port}`
    };
    finalProxies.push(node);
    regionCount[region] = (regionCount[region] || 0) + 1;
  }

  // 5. 输出结果
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
