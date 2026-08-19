const fs = require('fs');
const yaml = require('yaml');

// ========== 配置区 ==========
// 地区匹配规则：国旗 + 中文 + 大小写缩写
const REGION_RULES = [
  { reg: /香港|HK|HKG|hk|🇭🇰/, flag: "🇭🇰", name: "香港" },
  { reg: /台湾|TW|tw|🇹🇼/, flag: "🇹🇼", name: "台湾" },
  { reg: /日本|JP|JPN|jp|🇯🇵/, flag: "🇯🇵", name: "日本" },
  { reg: /美国|US|USA|us|🇺🇸/, flag: "🇺🇸", name: "美国" },
  { reg: /新加坡|SG|SGP|sg|🇸🇬/, flag: "🇸🇬", name: "新加坡" },
  { reg: /韩国|KR|KOR|kr|🇰🇷/, flag: "🇰🇷", name: "韩国" },
];

// 排除的节点类型：只排除策略组和非代理协议，主流代理协议全部保留
const SKIP_TYPES = new Set(["http","socks5","ss","ssr","snell","vmess","trojan","hysteria","wireguard","tailscale","ssh","openvpn"]);

const SUBS = JSON.parse(fs.readFileSync("./subs.json", "utf8"));
const OUTPUT_FILE = "nodes.yaml";
const REQUEST_TIMEOUT = 15000; // 单个订阅超时时间（毫秒）
// ========================================================

const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));
const regionCounter = {};
const seen = new Set();
let allProxies = [];

/**
 * 带超时的请求，兼容 node-fetch v3
 */
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

/**
 * 深度清洗对象：消除 yaml 内部特殊标记，根治输出乱 "-" 问题
 */
function cleanProxyObj(obj) {
  return JSON.parse(JSON.stringify(obj));
}

(async function main() {
  console.log(`===== 开始处理，共 ${SUBS.length} 个订阅 =====\n`);

  for (let i = 0; i < SUBS.length; i++) {
    const subUrl = SUBS[i];
    console.log(`--- [${i + 1}/${SUBS.length}] ${subUrl}`);

    try {
      const res = await fetchWithTimeout(subUrl);
      if (!res.ok) {
        console.log(`  ❌ HTTP 失败，状态码：${res.status}`);
        continue;
      }

      const text = await res.text();
      const doc = yaml.parse(text);

      // 兼容两种格式：完整配置（有proxies字段） / 纯节点数组
      let rawProxies = [];
      if (Array.isArray(doc)) {
        rawProxies = doc;
      } else if (doc && Array.isArray(doc.proxies)) {
        rawProxies = doc.proxies;
      } else {
        console.log(`  ⚠️ 未找到 proxies 数组，跳过`);
        continue;
      }
      console.log(`  📥 原始节点数：${rawProxies.length}`);

      // 第一步：类型过滤
      const typeFiltered = rawProxies.filter(p => {
        if (!p || !p.type) return false;
        return !SKIP_TYPES.has(p.type.toLowerCase());
      });
      console.log(`  🔍 类型过滤后：${typeFiltered.length}`);

      // 第二步：地区匹配 + 去重 + 重命名
      let validCount = 0;
      for (const rawP of typeFiltered) {
        const p = cleanProxyObj(rawP);
        if (!p.name || !p.server || !p.port) continue;

        const hit = REGION_RULES.find(r => r.reg.test(p.name));
        if (!hit) continue;

        // server+port 去重
        const fp = `${p.server}:${p.port}`;
        if (seen.has(fp)) continue;
        seen.add(fp);

        // 同地区自增编号
        regionCounter[hit.name] = (regionCounter[hit.name] || 0) + 1;
        const seq = String(regionCounter[hit.name]).padStart(2, "0");
        p.name = `${hit.flag} ${hit.name} ${seq} | ${p.type}`;

        allProxies.push(p);
        validCount++;
      }
      console.log(`  ✅ 地区匹配有效节点：${validCount}\n`);

    } catch (e) {
      console.log(`  ❌ 处理失败：${e.message}\n`);
    }
  }

  // 输出统计
  console.log('===== 处理完成 =====');
  console.log(`总有效节点数：${allProxies.length}`);
  console.log('各地区数量：');
  for (const [name, count] of Object.entries(regionCounter)) {
    console.log(`  ${name}：${count}`);
  }

  // 生成标准 yaml，强制块模式，禁用流式大括号
  const outputDoc = new yaml.Document();
  outputDoc.set("proxies", allProxies);
  const outputYaml = outputDoc.toString({
    indent: 2,
    flow: false,
    singleQuote: false,
    doubleQuote: false,
    lineWidth: 0
  });

  fs.writeFileSync(OUTPUT_FILE, outputYaml);
  console.log(`\n✅ 已输出至 ${OUTPUT_FILE}`);
})();
