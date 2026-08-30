// -------------------------------------------------- 配置区 --------------------------------------------------
const fs = require('fs');
const yaml = require('yaml');
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));
const SUBS = JSON.parse(fs.readFileSync("./subs.json", "utf8"));
const OUTPUT_FILE = "nodes.yaml";
const REGION_OUTPUT_FILE = "nodes_regionfiltered.yaml";
const REQUEST_TIMEOUT = 15000;
// 协议黑名单
const SKIP_TYPES = new Set(["http", "socks5", "ss", "ssr", "vmess", "trojan", "hysteria", "wireguard", "tailscale", "ssh", "openvpn"]);
// 名称初筛正则：仅用于减少查询量，不做最终判定
const PRE_FILTER_REGEX = /香港|Hong Kong|HK|🇭🇰|澳门|Macau|MO|🇲🇴|台湾|Taiwan|TW|🇹🇼|日本|Japen|JP|🇯🇵|韩国|Korea|KR|🇰🇷|新加坡|Singapore|SG|🇸🇬|马来西亚|Malaysia|MY|🇲🇾|泰国|Thailand|TH|🇹🇭|澳大利亚|Australia|AU|🇦🇺|美国|United States|US|🇺🇸/iu;
// 目标地区代码集合：仅用于筛选，重命名直接使用 countryCode
const TARGET_COUNTRY_CODES = new Set(['HK', 'MO', 'TW', 'JP', 'KR', 'SG', 'MY', 'TH', 'AU', 'US']);
// IP 批量查询配置
const BATCH_ENDPOINT = 'http://ip-api.com/batch';
const BATCH_SIZE = 80;
const BATCH_INTERVAL = 4500;
const BATCH_FIELDS = 'status,countryCode';
// 域名单查配置
const SINGLE_ENDPOINT = 'http://ip-api.com/json';
const DOMAIN_QUERY_INTERVAL = 1500;
// -------------------------------------------------- 配置区 --------------------------------------------------
// -------------------------------------------------- 工具函数 --------------------------------------------------
// 带超时控制的网络请求封装函数
async function fetchWithTimeout(url, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}
// 节点合法性校验函数
function isValidNode(node) {
  return !!(node && node.type);
}
// 延时等待工具函数
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
    });
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
      console.log(`  原始节点：${proxies.length}`);
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
    const fp = type === 'vless' && p['reality-opts']?.public_key
      ? `${type}|${p.server}|${p.uuid}|${p['reality-opts'].public_key}`
      : `${type}|${p.server}|${p.port}`;
    if (seen.has(fp)) return false;
    seen.add(fp);
    return true;
  });
  console.log(`🌐 去重后节点数：${dedupList.length}`);

  // 4. 地区筛选
  const regionFiltered = [];
  if (TARGET_COUNTRY_CODES.size > 0) {
    const ipNodes = [];
    const domainNodes = [];
    // 一次拆分：IP节点全部进入查询；域名节点执行名称初筛
    for(const node of dedupList){
      if(!node.server) continue;
      if(isIpAddress(node.server)){
        ipNodes.push(node);
      }else{
        if(PRE_FILTER_REGEX.test(node.name || '')){
          domainNodes.push(node);
        }
      }
    }
    console.log(`地区初筛：IP 节点全部保留，域名节点根据节点名称初筛`);
    const allResultMap = new Map();
    let ipQueryFail = 0;
    let ipMatchTarget = 0;
    let ipSkipOtherCountry = 0;
    let domainQueryFail = 0;
    let domainMatchTarget = 0;
    let domainSkipOtherCountry = 0;
    // IP 批量查询
    if (ipNodes.length > 0) {
      const batchCount = Math.ceil(ipNodes.length / BATCH_SIZE);
      console.log(`--- IP 批量查询，共 ${ipNodes.length} 个 ---`);
      for (let i = 0; i < batchCount; i++) {
        const batch = ipNodes.slice(i * BATCH_SIZE, (i + 1) * BATCH_SIZE);
        const batchIps = batch.map(p => p.server);
        const batchResult = await batchQueryIpCountry(batchIps);
        if (batchResult) batchResult.forEach((cc, ip) => allResultMap.set(ip, cc));
        if (i < batchCount - 1) await delay(BATCH_INTERVAL);
      }
      // 统计IP节点
      for(const node of ipNodes){
        const cc = allResultMap.get(node.server);
        if(!cc){
          ipQueryFail++;
        }else if(TARGET_COUNTRY_CODES.has(cc)){
          ipMatchTarget++;
          const newNode = { ...node, name: `${regionFiltered.length+1} ${cc}` };
          regionFiltered.push(newNode);
        }else{
          ipSkipOtherCountry++;
        }
      }
    }
    console.log(`IP 节点查询统计：失败 ${ipQueryFail}，成功但非目标国家 ${ipSkipOtherCountry}，命中目标 ${ipMatchTarget}`);
    // 域名单个查询
    if (domainNodes.length > 0) {
      console.log(`--- 域名单个查询，共 ${domainNodes.length} 个 ---`);
      for (let i = 0; i < domainNodes.length; i++) {
        const server = domainNodes[i].server;
        const cc = await getIpCountryCode(server);
        allResultMap.set(server, cc);
        if (i < domainNodes.length - 1) await delay(DOMAIN_QUERY_INTERVAL);
      }
      // 统计域名节点
      for(const node of domainNodes){
        const cc = allResultMap.get(node.server);
        if(!cc){
          domainQueryFail++;
        }else if(TARGET_COUNTRY_CODES.has(cc)){
          domainMatchTarget++;
          const newNode = { ...node, name: `${regionFiltered.length+1} ${cc}` };
          regionFiltered.push(newNode);
        }else{
          domainSkipOtherCountry++;
        }
      }
    }
    console.log(`域名节点查询统计：失败 ${domainQueryFail}，成功但非目标国家 ${domainSkipOtherCountry}，命中目标 ${domainMatchTarget}`);
    console.log(`🌐 地区最终筛选后节点数：${regionFiltered.length}`);
  } else {
    console.log(`⚠️ 未配置目标地区，跳过地区筛选`);
  }

  // 5. 输出结果
  const docAll = new yaml.Document();
  docAll.set('proxies', dedupList);
  fs.writeFileSync(OUTPUT_FILE, docAll.toString({ indent: 2, lineWidth: 0 }));
  console.log(`\n✅ 已保存去重后节点至 ${OUTPUT_FILE}`);
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
