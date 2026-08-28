// -------------------------------------------------- 配置区 --------------------------------------------------
const fs = require('fs');
const yaml = require('yaml');
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));
const SUBS = JSON.parse(fs.readFileSync("./subs.json", "utf8"));
const OUTPUT_FILE = "nodes.yaml";
const REGION_OUTPUT_FILE = "nodes_regionfiltered.yaml";
const REQUEST_TIMEOUT = 15000;
const SKIP_TYPES = new Set(["http", "socks5", "ss", "ssr", "vmess", "trojan", "hysteria", "wireguard", "tailscale", "ssh", "openvpn"]);

// 名称初筛正则：仅用于减少查询量，不做最终判定
const PRE_FILTER_REGEX = /香港|Hong Kong|HK|澳门|Macau|MO|台湾|Taiwan|TW|日本|Japen|JP|韩国|Korea|KR|新加坡|Singapore|SG|马来西亚|Malaysia|MY|泰国|Thailand|TH|澳大利亚|Australia|AU|美国|United States|US/i;
// 目标地区代码集合：仅用于筛选，重命名直接使用 countryCode
const TARGET_COUNTRY_CODES = new Set(['HK', 'MO', 'TW', 'JP', 'KR', 'SG', 'MY', 'TH', 'AU', 'US']);

// IP 批量查询配置
const BATCH_ENDPOINT = 'http://ip-api.com/batch';
const BATCH_SIZE = 50;
const BATCH_INTERVAL = 3000;
const BATCH_FIELDS = 'status,countryCode';

// 域名单查配置
const SINGLE_ENDPOINT = 'http://ip-api.com/json';
const DOMAIN_QUERY_INTERVAL = 1500;

// 调试日志开关
const DEBUG_BATCH = false;
// -------------------------------------------------- 配置区 --------------------------------------------------

// -------------------------------------------------- 工具函数 --------------------------------------------------
async function fetchWithTimeout(url, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
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

// 判断是否为 IP 地址
function isIpAddress(str) {
  if (!str) return false;
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  const ipv6Regex = /^[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){2,7}$/;
  return ipv4Regex.test(str) || ipv6Regex.test(str);
}

// 批量查询 IP 的国家代码
async function batchQueryIpCountry(ipList) {
  try {
    const res = await fetchWithTimeout(`${BATCH_ENDPOINT}?fields=${encodeURIComponent(BATCH_FIELDS)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(ipList)
    });
    if (!res.ok) {
      console.log(`    ❌ 批量请求失败 HTTP ${res.status}`);
      return null;
    }
    const data = await res.json();
    const resultMap = new Map();
    data.forEach((item, index) => {
      const ip = ipList[index];
      const cc = item?.status === 'success' ? String(item.countryCode).toUpperCase() : null;
      resultMap.set(ip, cc);
      if (DEBUG_BATCH) {
        console.log(`      ${ip} -> ${cc ? `✅ ${cc}` : `❌ 失败: ${item?.message || '未知错误'}`}`);
      }
    });
    if (DEBUG_BATCH) {
      const success = [...resultMap.values()].filter(Boolean).length;
      console.log(`    --- 本批统计：成功 ${success}，失败 ${ipList.length - success} ---`);
    }
    return resultMap;
  } catch (e) {
    console.log(`    ❌ 批量请求异常：${e.message}`);
    return null;
  }
}

// 单个查询IP/域名的国家代码
async function getIpCountryCode(ipOrDomain) {
  try {
    const res = await fetchWithTimeout(`${SINGLE_ENDPOINT}/${encodeURIComponent(ipOrDomain)}?fields=status,countryCode`);
    if (!res.ok) return null;
    const data = await res.json();
    return data.status === 'success' ? String(data.countryCode).toUpperCase() : null;
  } catch {
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
      const proxies = doc?.proxies || (Array.isArray(doc) ? doc : []);
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
  const typeFiltered = allRawProxies.filter(p => {
    if (!isValidNode(p)) return false;
    const type = p.type.toLowerCase();
    if (SKIP_TYPES.has(type)) return false;
    if (type === 'vless') {
      const hasReality = !!p['reality-opts'];
      const hasXhttp = !!p['xhttp-opts'];
      if (!hasReality && !hasXhttp) return false;
      if (p.encryption && typeof p.encryption === 'string' && p.encryption.length > 50) return false;
    }
    return true;
  });
  console.log(`类型过滤后节点数：${typeFiltered.length}`);

  // 3. 节点去重
  const seen = new Set();
  const dedupList = typeFiltered.filter(p => {
    const type = p.type.toLowerCase();
    let fp = type === 'vless' && p['reality-opts']?.public_key
      ? `${type}|${p.server}|${p.uuid}|${p['reality-opts'].public_key}`
      : `${type}|${p.server}|${p.port}`;
    if (seen.has(fp)) return false;
    seen.add(fp);
    return true;
  });
  console.log(`去重后节点数：${dedupList.length}`);

  // 4. 地区筛选
  const regionFiltered = [];
  if (TARGET_COUNTRY_CODES.size > 0) {
    // 4.1 名称初筛
    const preFiltered = dedupList.filter(p => PRE_FILTER_REGEX.test(p.name || ''));
    console.log(`\n名称初筛候选节点数：${preFiltered.length}`);
    if (preFiltered.length > 0) {
      // 4.2 拆分 IP /域名节点
      const ipNodes = [];
      const domainNodes = [];
      for (const node of preFiltered) {
        if (!node.server) continue;
        isIpAddress(node.server) ? ipNodes.push(node) : domainNodes.push(node);
      }
      console.log(`节点拆分：IP ${ipNodes.length} 个，域名 ${domainNodes.length} 个`);
      const allResultMap = new Map();
      // 4.3 IP 批量查询
      if (ipNodes.length > 0) {
        const batchCount = Math.ceil(ipNodes.length / BATCH_SIZE);
        console.log(`--- IP批量查询，共 ${ipNodes.length} 个，分 ${batchCount} 批 ---`);
        for (let i = 0; i < batchCount; i++) {
          const batch = ipNodes.slice(i * BATCH_SIZE, (i + 1) * BATCH_SIZE);
          const batchIps = batch.map(p => p.server);
          console.log(`  [${i + 1}/${batchCount}] 第 ${i + 1} 批，${batchIps.length} 个IP`);
          const batchResult = await batchQueryIpCountry(batchIps);
          if (batchResult) batchResult.forEach((cc, ip) => allResultMap.set(ip, cc));
          if (i < batchCount - 1) await delay(BATCH_INTERVAL);
        }
      }
      // 4.4 域名单个查询
      if (domainNodes.length > 0) {
        console.log(`--- 域名单查，共 ${domainNodes.length} 个 ---`);
        for (let i = 0; i < domainNodes.length; i++) {
          const server = domainNodes[i].server;
          if (DEBUG_BATCH) console.log(`  [${i + 1}/${domainNodes.length}] 查询 ${server}`);
          const cc = await getIpCountryCode(server);
          allResultMap.set(server, cc);
          if (DEBUG_BATCH) console.log(`    ${cc ? `✅ ${cc}` : '❌ 失败'}`);
          if (i < domainNodes.length - 1) await delay(DOMAIN_QUERY_INTERVAL);
        }
      }
      // 4.5 匹配目标地区并重命名
      let matchCount = 0;
      let failCount = 0;
      for (const node of preFiltered) {
        const cc = allResultMap.get(node.server);
        if (!cc) { failCount++; continue; }
        if (TARGET_COUNTRY_CODES.has(cc)) {
          const newNode = { ...node, name: `${++matchCount} ${cc}` };
          regionFiltered.push(newNode);
        }
      }
      console.log(`地区校验统计：`);
      console.log(`  候选节点：${preFiltered.length}`);
      console.log(`  查询失败：${failCount}`);
      console.log(`  命中目标：${matchCount}`);
    }
    console.log(`地区最终筛选后节点数：${regionFiltered.length}`);
  } else {
    console.log(`⚠️ 未配置目标地区，跳过地区筛选`);
  }

  // 5. 输出结果（修复链式调用问题，改回分步写法）
  const docAll = new yaml.Document();
  docAll.set('proxies', dedupList);
  fs.writeFileSync(OUTPUT_FILE, docAll.toString({ indent: 2, lineWidth: 0 }));
  console.log(`\n✅ 已保存全量节点至 ${OUTPUT_FILE}`);

  if (regionFiltered.length) {
    const docRegion = new yaml.Document();
    docRegion.set('proxies', regionFiltered);
    fs.writeFileSync(REGION_OUTPUT_FILE, docRegion.toString({ indent: 2, lineWidth: 0 }));
    console.log(`✅ 已保存地区筛选节点至 ${REGION_OUTPUT_FILE}`);
  } else {
    fs.writeFileSync(REGION_OUTPUT_FILE, 'proxies: []\n');
    console.log(`⚠️ 地区筛选结果为空，已写入空文件`);
  }
})();
// -------------------------------------------------- 主程序区 --------------------------------------------------
