// -------------------------------------------------- 配置区 --------------------------------------------------
const fs = require('fs');
const yaml = require('yaml');
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));
const SUBS = JSON.parse(fs.readFileSync("./subs.json", "utf8"));
const OUTPUT_FILE = "nodes.yaml";
const REGION_OUTPUT_FILE = "nodes_regionfiltered.yaml";
const REQUEST_TIMEOUT = 15000;
const SKIP_TYPES = new Set(["http", "socks5", "ss", "ssr", "vmess", "trojan", "hysteria", "wireguard", "tailscale", "ssh", "openvpn"]);

// 名称初筛正则：仅用于减少批量查询量，不做最终判定
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

// 批量IP查询配置
const BATCH_ENDPOINT = 'http://ip-api.com/batch'; // 免费批量接口
const BATCH_SIZE = 50;          // 每批50个节点（官方上限100，留余量更稳定）
const BATCH_INTERVAL = 4500;    // 批间间隔4.5秒，约13批/分钟，低于官方15次/分钟限流
const BATCH_FIELDS = 'status,countryCode'; // 只保留必需字段，减少带宽
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

// 批量查询IP/域名的国家代码
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
    data.forEach((item, index) => {
      const ip = ipList[index];
      resultMap.set(ip, item?.status === 'success' ? String(item.countryCode).toUpperCase() : null);
    });
    return resultMap;
  } catch (e) {
    console.log(`    ❌ 批量请求异常：${e.message}`);
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

  // 4. 地区筛选：名称初筛 → 批量IP地理校验 → 按countryCode最终保留
  const regionFiltered = [];
  if (Object.keys(TARGET_COUNTRY_MAP).length > 0) {
    // 4.1 名称初筛，减少批量查询量
    const preFiltered = dedupList.filter(p => PRE_FILTER_REGEX.test(p.name || ''));
    console.log(`名称初筛候选节点数：${preFiltered.length}`);

    if (preFiltered.length > 0) {
      const total = preFiltered.length;
      const batchCount = Math.ceil(total / BATCH_SIZE);
      console.log(`\n开始批量IP地理校验，共 ${total} 个节点，分 ${batchCount} 批`);

      const allResultMap = new Map();

      // 4.2 分批查询
      for (let i = 0; i < batchCount; i++) {
        const start = i * BATCH_SIZE;
        const batchNodes = preFiltered.slice(start, start + BATCH_SIZE);
        const batchIps = batchNodes.map(p => p.server).filter(Boolean);

        console.log(`  [${i + 1}/${batchCount}] 处理第 ${i + 1} 批`);
        const batchResult = await batchQueryIpCountry(batchIps);
        
        if (batchResult) {
          for (const [ip, cc] of batchResult.entries()) {
            allResultMap.set(ip, cc);
          }
        }

        // 最后一批无需等待
        if (i < batchCount - 1) {
          await delay(BATCH_INTERVAL);
        }
      }

      // 4.3 匹配目标地区，生成最终列表
      for (const node of preFiltered) {
        const server = node.server;
        if (!server) continue;
        const cc = allResultMap.get(server);
        if (cc && TARGET_COUNTRY_MAP[cc]) {
          regionFiltered.push({
            node: { ...node },
            displayName: TARGET_COUNTRY_MAP[cc]
          });
        }
      }

      // 4.4 按序号+地区重命名节点
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
