// -------------------------------------------------- 配置区 --------------------------------------------------
const fs = require('fs');
const yaml = require('yaml');
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));
const dns = require('dns').promises;

const SUBS = JSON.parse(fs.readFileSync("./nodes/subs.json", "utf8"));
const REQUEST_TIMEOUT = 15000;

// 协议白名单，只放行列表内协议
const PROTO_WHITELIST = new Set(["vless", "trojan", "hysteria2", "anytls", "tuic", "mieru"]);
// 地区过滤豁免协议：geo拿到cc就全部保留，不校验目标国家
const REGIONFILTER_SKIP_PROTOLIST = new Set(["hysteria2", "anytls", "tuic", "mieru"]);
// 目标国家代码集合，非豁免协议必须命中
const TARGET_COUNTRY_CODES = new Set(['HK', 'MO', 'TW', 'JP', 'KR', 'SG', 'US']);

// ip-api.com批量查询接口
const BATCH_ENDPOINT = 'http://ip-api.com/batch';
const BATCH_SIZE = 100;
const BATCH_INTERVAL = 4500;
const BATCH_FIELDS = 'status,countryCode';

// DNS解析配置
const DNS_CONCURRENCY = 30;
const DNS_TIMEOUT = 5000;
const DNS_UPSTREAM = ["1.1.1.1","8.8.8.8"];
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
  return !!(node && node.type && node.server);
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

// 域名DNS解析，获取第一个IPv4地址
async function dnsResolveHost(host) {
  const resolver = new dns.Resolver();
  resolver.setServers(DNS_UPSTREAM);
  const timeoutPromise = delay(DNS_TIMEOUT).then(()=>null);
  try {
    const ips = await Promise.race([resolver.resolve4(host), timeoutPromise]);
    if(!ips || !Array.isArray(ips) || ips.length ===0) return null;
    return ips[0];
  }catch{
    return null;
  }
}

// 简易异步并发任务池，控制最大并发数量
async function limitedTaskPool(taskList, concurrency){
  const results = new Array(taskList.length);
  let ptr = 0;
  const worker = async ()=>{
    while(ptr < taskList.length){
      const idx = ptr++;
      try{
        results[idx] = await taskList[idx]();
      }catch{
        results[idx] = null;
      }
    }
  };
  const workers = Array.from({length:concurrency}, worker);
  await Promise.all(workers);
  return results;
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
      console.log(`    ❌ 批量查询请求失败 HTTP ${res.status}`);
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
    console.log(`    ⚠️ 批量请求异常：${e.message}`);
    return null;
  }
}
// -------------------------------------------------- 主程序 --------------------------------------------------
(async function main() {
  console.log(`\n--- 开始拉取，共 ${SUBS.length} 个订阅 ---`);
  const allRawProxies = [];

  // 拉取订阅
  for (let i = 0; i < SUBS.length; i++) {
    const subUrl = SUBS[i];
    console.log(`--- [${i + 1}/${SUBS.length}] ${subUrl}`);
    try {
      const res = await fetchWithTimeout(subUrl);
      if (!res.ok) {
        console.log(`  ❌ 拉取订阅失败 HTTP ${res.status}`);
        continue;
      }
      const text = await res.text();
      const doc = yaml.parse(text);
      const proxies = doc?.proxies || (Array.isArray(doc) ? doc : []);
      if (!proxies.length) continue;
      console.log(`    节点数量：${proxies.length}`);
      allRawProxies.push(...proxies);
    } catch (e) {
      console.log(`  ❌ 失败：${e.message}`);
    }
  }
  console.log(`\n汇总节点数量：${allRawProxies.length}`);

  // 协议白名单 + 字段校验
  const typeFiltered = allRawProxies.filter(p => {
    if (!isValidNode(p)) return false;
    const type = p.type.toLowerCase();
    if (!PROTO_WHITELIST.has(type)) return false;

    if (type === 'vless') {
      const hasReality = !!p['reality-opts'];
      const hasXhttp = !!p['xhttp-opts'];
      const hasWs = !!p['ws-opts'];
      if (!hasReality && !hasXhttp && !hasWs) return false;
      if (p.encryption && typeof p.encryption === 'string' && p.encryption.length > 50) return false;
    } else if (type === 'trojan') {
      const hasWsOpts = !!p['ws-opts'];
      if (!hasWsOpts) return false;
    }
    return true;
  });
  console.log(`协议过滤后节点数量：${typeFiltered.length}`);

  // 节点去重
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
  console.log(`去重后节点数量：${dedupList.length}`);
  
  console.log(`--- ip-api.com 批量查询 ---`);
  // 拆分IP/域名节点
  const originIpNodes = [];
  const domainNodes = [];
  for(const node of dedupList){
    if(isIpAddress(node.server)) originIpNodes.push(node);
    else domainNodes.push(node);
  }
  console.log(`  IP 节点数量：${originIpNodes.length}，域名节点数量：${domainNodes.length}`);

  // ip -> 原始节点映射
  const ipToNodesMap = new Map();
  for(const n of originIpNodes){
    if(!ipToNodesMap.has(n.server)) ipToNodesMap.set(n.server,[]);
    ipToNodesMap.get(n.server).push(n);
  }

  // 域名并发DNS解析
  const dnsTasks = domainNodes.map(node=> async ()=>{
    const ip = await dnsResolveHost(node.server);
    if(!ip) return null;
    return {node, resolvedIp:ip};
  });
  const dnsResults = await limitedTaskPool(dnsTasks,DNS_CONCURRENCY);
  for(const item of dnsResults){
    if(!item) continue;
    const {node,resolvedIp} = item;
    if(!ipToNodesMap.has(resolvedIp)) ipToNodesMap.set(resolvedIp,[]);
    ipToNodesMap.get(resolvedIp).push(node);
  }

  const uniqueIpList = Array.from(ipToNodesMap.keys());
  console.log(`  待批量查询 IP 数量：${uniqueIpList.length}`);

  // ip‑api批量查询
  const ipCcMap = new Map();
  if(uniqueIpList.length>0){
    const batchCount = Math.ceil(uniqueIpList.length / BATCH_SIZE);
    for(let i=0;i<batchCount;i++){
      const chunk = uniqueIpList.slice(i*BATCH_SIZE,(i+1)*BATCH_SIZE);
      const batchRet = await batchQueryIpCountry(chunk);
      if(batchRet){
        for(const [ip,cc] of batchRet) ipCcMap.set(ip,cc);
      }
      if(i < batchCount-1) await delay(BATCH_INTERVAL);
    }
  }

  // 回填国家码，丢弃无cc节点
  const taggedAllNodes = [];
  for(const [ip,nodeList] of ipToNodesMap){
    const cc = ipCcMap.get(ip);
    if(!cc) continue;
    for(const rawNode of nodeList){
      taggedAllNodes.push({node:rawNode, cc});
    }
  }
  console.log(`  地区查询成功节点数量：${taggedAllNodes.length}`);
  console.log(`--- ip-api.com 批量查询 ---`);

  // 地区筛选
  const passList = [];
  for(const item of taggedAllNodes){
    const {node,cc} = item;
    const t = node.type.toLowerCase();
    if(REGIONFILTER_SKIP_PROTOLIST.has(t)){
      passList.push({node,cc});
    }else{
      if(TARGET_COUNTRY_CODES.has(cc)){
        passList.push({node,cc});
      }
    }
  }

  // 全局序号重命名
  passList.forEach((item,idx)=>{
    item.node.name = `${idx+1} ${item.cc}`;
  });
  const finalProxies = passList.map(i=>i.node);
  console.log(`🌐 地区筛选后节点数量：${finalProxies.length}\n`);

  // 按协议分组输出yaml
  const groupMap = {};
  for(const p of finalProxies){
    const tp = p.type.toLowerCase();
    if(!groupMap[tp]) groupMap[tp] = [];
    groupMap[tp].push(p);
  }
  for(const [proto,proxyList] of Object.entries(groupMap)){
    const docProto = new yaml.Document();
    docProto.set("proxies",proxyList);
    const outPath = `nodes/${proto}.yaml`;
    fs.writeFileSync(outPath, docProto.toString({ indent:2, lineWidth:0 }));
    console.log(`✅ ${outPath} 输出 ${proxyList.length} 个节点`);
  }

})().catch(err=>{
  console.error("脚本异常：",err);
  process.exit(1);
});
