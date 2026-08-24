// -------------------------------------------------- 配置区 --------------------------------------------------
const fs = require('fs');
const yaml = require('yaml');
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));
const SUBS = JSON.parse(fs.readFileSync("./subs.json", "utf8"));
const OUTPUT_FILE = "nodes.yaml";
const REQUEST_TIMEOUT = 15000; 

// 黑名单协议
const SKIP_TYPES = new Set(["http", "socks5", "ss", "ssr", "vmess", "trojan", "hysteria", "wireguard", "tailscale", "ssh", "openvpn"]);

// 需要匹配的地区
const REGION_RULES = [
  { reg: /香港|Hong Kong|HK|hk|🇭🇰/, flag: "🇭🇰", name: "香港" },
  { reg: /澳门|Macau|MO|mo|🇲🇴/, flag: "🇲🇴", name: "澳门" },
  { reg: /台湾|Taiwan|TW|tw|🇹🇼/, flag: "🇹🇼", name: "台湾" },
  { reg: /日本|Japan|JP|jp|🇯🇵/, flag: "🇯🇵", name: "日本" },
  { reg: /韩国|Korea|KR|kr|🇰🇷/, flag: "🇰🇷", name: "韩国" },
  { reg: /新加坡|Singapore|SG|sg|🇸🇬/, flag: "🇸🇬", name: "新加坡" },
  { reg: /马来西亚|Malaysia|MY|my|🇲🇾/, flag: "🇲🇾", name: "马来西亚" },
  { reg: /泰国|Thailand|TH|th|🇹🇭/, flag: "🇹🇭", name: "泰国" },
  { reg: /越南|Vietnam|VN|vn|🇻🇳/, flag: "🇻🇳", name: "越南" },
  { reg: /菲律宾|Philippines|PH|ph|🇵🇭/, flag: "🇵🇭", name: "菲律宾" },
  { reg: /印尼|Indonesia|ID|id|🇮🇩/, flag: "🇮🇩", name: "印尼" },
  { reg: /澳大利亚|Australia|AU|au|🇦🇺/, flag: "🇦🇺", name: "澳大利亚" },
  { reg: /美国|United States|US|us|🇺🇸/, flag: "🇺🇸", name: "美国" },
];
// -------------------------------------------------- 配置区 --------------------------------------------------

// -------------------------------------------------- 工具函数 --------------------------------------------------
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
// -------------------------------------------------- 工具函数 --------------------------------------------------

// -------------------------------------------------- 主程序区 --------------------------------------------------
(async function main() {
  console.log(`===== 开始处理，共 ${SUBS.length} 个订阅 =====\n`);

  // 1. 抓取所有原始订阅节点
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

  // 2. 类型过滤
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

  // 3. 地区匹配
  const regionFiltered = [];
  for (const p of typeFiltered) {
    const hit = REGION_RULES.find(r => r.reg.test(p.name || ''));
    if (!hit) continue;
    regionFiltered.push({ p, hit });
  }
  console.log(`地区匹配后节点数：${regionFiltered.length}`);

  // 4. 去重（复合指纹）
  const seen = new Set();
  const dedupList = [];
  for (const { p, hit } of regionFiltered) {
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
  console.log(`去重后节点数：${dedupList.length}`);

  // 5. 重命名：全局顺序编号（不区分地区）
  let globalSeq = 0;
  const finalProxies = [];
  for (const { p, hit } of dedupList) {
    globalSeq++;
    const seq = String(globalSeq).padStart(2, '0');
    p.name = `${seq} ${hit.flag} ${hit.name} | ${p.type}`;
    finalProxies.push(p);
  }

  // 6. 输出统计（各地区数量）
  const countMap = {};
  for (const { hit } of dedupList) {
    countMap[hit.name] = (countMap[hit.name] || 0) + 1;
  }
  console.log(`✅ 输出节点总数：${finalProxies.length}`);
  console.log('各地区数量：');
  for (const rule of REGION_RULES) {
    const count = countMap[rule.name] || 0;
    console.log(`  ${rule.name}: ${count}`);
  }
  
  // 7. 写入 YAML
  const doc = new yaml.Document();
  doc.set('proxies', finalProxies);
  fs.writeFileSync(OUTPUT_FILE, doc.toString({ indent: 2, lineWidth: 0 }));
  console.log(`\n✅ 已保存至 ${OUTPUT_FILE}`);
})();
// -------------------------------------------------- 主程序区 --------------------------------------------------
