const fs = require('fs');
const yaml = require('yaml');
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));

// ========== 配置区 ==========
// 需要匹配的地区（正则 + 国旗 + 显示名称）
const REGION_RULES = [
  { reg: /香港|HK|HKG|hk|🇭🇰/, flag: "🇭🇰", name: "香港" },
  { reg: /台湾|TW|tw|🇹🇼/, flag: "🇹🇼", name: "台湾" },
  { reg: /日本|JP|JPN|jp|🇯🇵/, flag: "🇯🇵", name: "日本" },
  { reg: /韩国|KR|KOR|kr|🇰🇷/, flag: "🇰🇷", name: "韩国" },
  { reg: /新加坡|SG|SGP|sg|🇸🇬/, flag: "🇸🇬", name: "新加坡" },
  { reg: /美国|US|USA|us|🇺🇸/, flag: "🇺🇸", name: "美国" },
];

// 黑名单协议（直接丢弃）
const SKIP_TYPES = new Set([
  "http", "socks5", "ss", "ssr", "snell", "vmess",
  "trojan", "hysteria", "wireguard", "tailscale", "ssh", "openvpn"
]);

const SUBS = JSON.parse(fs.readFileSync("./subs.json", "utf8"));
const OUTPUT_FILE = "nodes.yaml";
const REQUEST_TIMEOUT = 15000; // 单个订阅超时（毫秒）
// ========================================================

// 带超时的请求
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

// 基础有效性检查
function isValidNode(node) {
  return !!(node && node.type);
}

(async function main() {
  console.log(`===== 开始处理，共 ${SUBS.length} 个订阅 =====\n`);

  // 1. 抓取所有订阅的原始节点
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
      console.log(`  📥 原始节点：${proxies.length}`);
      allRawProxies.push(...proxies);
    } catch (e) {
      console.log(`  ❌ 失败：${e.message}`);
    }
  }

  console.log(`\n总原始节点数：${allRawProxies.length}`);

  // 2. 过滤：类型 + 地区匹配（无 encryption 校验）
  const matchedNodes = [];
  for (const p of allRawProxies) {
    // ① 基础校验
    if (!isValidNode(p)) continue;
    const type = p.type.toLowerCase();
    if (SKIP_TYPES.has(type)) continue;

    // ② 只保留 vless 且含 reality 或 xhttp 的节点
    if (type === 'vless') {
      const hasReality = !!p['reality-opts'];
      const hasXhttp = !!p['xhttp-opts'];
      if (!hasReality && !hasXhttp) continue;
    }

    // ③ 地区匹配
    const hit = REGION_RULES.find(r => r.reg.test(p.name || ''));
    if (!hit) continue; // 不匹配的地区直接跳过

    matchedNodes.push({ p, hit });
  }

  console.log(`✅ 地区匹配节点数：${matchedNodes.length}`);

  // 3. 去重（复合指纹）
  const seen = new Set();
  const dedupList = [];
  for (const { p, hit } of matchedNodes) {
    const type = p.type.toLowerCase();
    let fp;
    if (type === 'vless' && p['reality-opts']?.public_key) {
      fp = `${p.type}|${p.server}|${p.uuid}|${p['reality-opts'].public_key}`;
    } else {
      fp = `${p.type}|${p.server}|${p.port}`;
    }
    if (seen.has(fp)) continue;
    seen.add(fp);
    dedupList.push({ p, hit });
  }

  console.log(`✅ 去重后节点数：${dedupList.length}`);

  // 4. 重命名：全局顺序编号（不区分地区）
  let globalSeq = 0;
  const finalProxies = [];
  for (const { p, hit } of dedupList) {
    globalSeq++;
    const seq = String(globalSeq).padStart(2, '0');
    p.name = `${seq} ${hit.flag} ${hit.name} | ${p.type}`;
    finalProxies.push(p);
  }

  // 5. 输出统计（各地区数量）
  const countMap = {};
  for (const { hit } of dedupList) {
    countMap[hit.name] = (countMap[hit.name] || 0) + 1;
  }
  console.log(`✅ 最终输出节点总数：${finalProxies.length}`);
  console.log('各地区数量：');
  for (const [name, count] of Object.entries(countMap)) {
    console.log(`  ${name}：${count}`);
  }

  // 6. 写入 YAML
  const doc = new yaml.Document();
  doc.set('proxies', finalProxies);
  fs.writeFileSync(OUTPUT_FILE, doc.toString({ indent: 2, lineWidth: 0 }));
  console.log(`\n✅ 已保存至 ${OUTPUT_FILE}`);
})();
