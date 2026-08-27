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
const PRE_FILTER_REGEX = /香港|Hong Kong|HK|台湾|Taiwan|TW|日本|Japen|JP|韩国|Korea|KR|新加坡|Singapore|SG|美国|United States|US/i;
// 目标地区映射：countryCode -> 显示名称
const TARGET_COUNTRY_MAP = {
  'HK': "🇭🇰 HK",
  'TW': "🇹🇼 TW",
  'JP': "🇯🇵 JP",
  'KR': "🇰🇷 KR",
  'SG': "🇸🇬 SG",
  'US': "🇺🇸 US",
};

// IP批量查询配置
const BATCH_ENDPOINT = 'http://ip-api.com/batch'; // 免费批量接口仅支持HTTP
const BATCH_SIZE = 50;          // 每批50个IP（官方上限100）
const BATCH_INTERVAL = 4500;    // 批间间隔4.5秒，低于官方15次/分钟限流
const BATCH_FIELDS = 'status,countryCode,query';

// 域名单查配置
const SINGLE_ENDPOINT = 'http://ip-api.com/json'; // 单查接口
const DOMAIN_QUERY_INTERVAL = 1500; // 域名查询间隔

const DEBUG_BATCH = false;       // 开启详细调试日志
// -------------------------------------------------- 配置区 --------------------------------------------------

// -------------------------------------------------- 工具函数 --------------------------------------------------
async function fetchWithTimeout(url, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT);
  try {
    const res = await fetch(url, {
      ...options,
      signal: controller.signal
    });
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

// 判断字符串是否为IP地址（IPv4/IPv6）
function isIpAddress(str) {
  if (!str) return false;
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  const ipv6Regex = /^[0-9a-fA-F:]+$/;
  return ipv4Regex.test(str) || ipv6Regex.test(str);
}

// 批量查询IP的国家代码
async function batchQueryIpCountry(ipList) {
  try {
    const url = `${BATCH_ENDPOINT}?fields=${encodeURIComponent(BATCH_FIELDS)}`;
    const res = await fetchWithTimeout(url, {
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
    let successCount = 0;
    let failCount = 0;

    data.forEach((item, index) => {
      const ip = ipList[index];
      const isSuccess = item?.status === 'success';
      const cc = isSuccess ? String(item.countryCode).toUpperCase() : null;
      resultMap.set(ip, cc);

      if (isSuccess) {
        successCount++;
      } else {
        failCount++;
      }

      if (DEBUG_BATCH) {
        const status = isSuccess ? `✅ ${cc}` : `❌ 失败: ${item?.message || '未知错误'}`;
        console.log(`      ${ip} -> ${status}`);
      }
    });

    if (DEBUG_BATCH) {
      console.log(`    --- 本批统计：成功 ${successCount}，失败 ${failCount} ---`);
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

  // 4. 地区筛选：名称初筛 → 拆分IP/域名 → 混合查询 → 按countryCode最终保留
  const regionFiltered = [];
  if (Object.keys(TARGET_COUNTRY_MAP).length > 0) {
    // 4.1 名称初筛
    const preFiltered = dedupList.filter(p => PRE_FILTER_REGEX.test(p.name || ''));
    console.log(`名称初筛候选节点数：${preFiltered.length}`);

    if (preFiltered.length > 0) {
      // 4.2 拆分IP节点和域名节点
      const ipNodes = [];
      const domainNodes = [];
      for (const node of preFiltered) {
        const server = node.server;
        if (!server) continue;
        if (isIpAddress(server)) {
          ipNodes.push(node);
        } else {
          domainNodes.push(node);
        }
      }
      console.log(`\n📊 节点拆分：IP节点 ${ipNodes.length} 个，域名节点 ${domainNodes.length} 个`);

      const allResultMap = new Map();

      // 4.3 IP节点：批量查询
      if (ipNodes.length > 0) {
        const total = ipNodes.length;
        const batchCount = Math.ceil(total / BATCH_SIZE);
        console.log(`\n--- 开始IP批量查询，共 ${total} 个，分 ${batchCount} 批 ---`);

        for (let i = 0; i < batchCount; i++) {
          const start = i * BATCH_SIZE;
          const batch = ipNodes.slice(start, start + BATCH_SIZE);
          const batchIps = batch.map(p => p.server);

          console.log(`  [${i + 1}/${batchCount}] 第 ${i + 1} 批，共 ${batchIps.length} 个IP`);
          const batchResult = await batchQueryIpCountry(batchIps);

          if (batchResult) {
            for (const [ip, cc] of batchResult.entries()) {
              allResultMap.set(ip, cc);
            }
          }

          if (i < batchCount - 1) {
            await delay(BATCH_INTERVAL);
          }
        }
      }

      // 4.4 域名节点：串行单查
      if (domainNodes.length > 0) {
        console.log(`\n--- 开始域名单查，共 ${domainNodes.length} 个 ---`);
        for (let i = 0; i < domainNodes.length; i++) {
          const node = domainNodes[i];
          const server = node.server;

          if (DEBUG_BATCH) {
            console.log(`  [${i + 1}/${domainNodes.length}] 查询 ${server} ...`);
          }

          const cc = await getIpCountryCode(server);
          allResultMap.set(server, cc);

          if (DEBUG_BATCH) {
            if (cc) {
              console.log(`    ✅ ${server} -> ${cc}`);
            } else {
              console.log(`    ❌ ${server} -> 查询失败`);
            }
          }

          if (i < domainNodes.length - 1) {
            await delay(DOMAIN_QUERY_INTERVAL);
          }
        }
      }

      // 4.5 统一匹配目标地区
      let matchCount = 0;
      let noResultCount = 0;
      for (const node of preFiltered) {
        const server = node.server;
        if (!server) {
          noResultCount++;
          continue;
        }
        const cc = allResultMap.get(server);
        if (!cc) {
          noResultCount++;
          continue;
        }
        if (TARGET_COUNTRY_MAP[cc]) {
          regionFiltered.push({
            node: { ...node },
            displayName: TARGET_COUNTRY_MAP[cc]
          });
          matchCount++;
        }
      }

      console.log(`\n📊 地区校验总统计：`);
      console.log(`  候选节点：${preFiltered.length}`);
      console.log(`  查询失败/无结果：${noResultCount}`);
      console.log(`  命中目标地区：${matchCount}`);

      // 4.6 按序号+地区重命名节点
      regionFiltered.forEach((item, idx) => {
        item.node.name = `${idx + 1} ${item.displayName}`;
      });
    }

    console.log(`\n地区最终筛选后节点数：${regionFiltered.length}`);
  } else {
    console.log(`⚠️ 未配置目标地区，跳过地区筛选`);
  }

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
