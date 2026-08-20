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
// 排除的节点类型：黑名单协议直接丢弃
const SKIP_TYPES = new Set(["http","socks5","ss","ssr","snell","vmess","trojan","hysteria","wireguard","tailscale","ssh","openvpn"]);
const SUBS = JSON.parse(fs.readFileSync("./subs.json", "utf8"));
const OUTPUT_FILE = "nodes.yaml";
const REQUEST_TIMEOUT = 15000; // 单个订阅超时时间（毫秒）
// ========================================================
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));

// 带超时的请求，兼容 node‑fetch v3
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

// 数组随机抽样（保留以备将来使用，但本脚本未调用）
function sampleRandom(arr, count) {
  const copy = [...arr];
  const result = [];
  const take = Math.min(count, copy.length);
  for(let i = 0; i < take; i++){
    const idx = Math.floor(Math.random() * copy.length);
    result.push(copy.splice(idx,1)[0]);
  }
  return result;
}

(async function main() {
  const allRawProxies = [];
  console.log(`===== 开始处理，共 ${SUBS.length} 个订阅 =====\n`);

  // 1. 遍历所有订阅，仅收集原始节点，不做过滤处理
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
      let rawProxies = [];
      if (Array.isArray(doc)) {
        rawProxies = doc;
      } else if (doc && Array.isArray(doc.proxies)) {
        rawProxies = doc.proxies;
      } else {
        console.log(`  ⚠️ 未找到 proxies 数组，跳过`);
        continue;
      }
      console.log(`  📥 当前订阅原始节点：${rawProxies.length}`);
      allRawProxies.push(...rawProxies);
    } catch (e) {
      console.log(`  ❌ 处理失败：${e.message}\n`);
    }
  }

  console.log("\n===== 全部订阅抓取完成，开始全局统一处理 =====");
  console.log(`总原始汇总节点数：${allRawProxies.length}`);

  // --------------------------
  // ① 类型过滤 + encryption 异常检查
  // --------------------------
  const typeFiltered = allRawProxies.filter(rawP => {
    // encryption 异常校验
    if (rawP.type && rawP.type.toLowerCase() === 'vless') {
      const enc = rawP.encryption;
      if (enc && typeof enc === 'string' && enc.length > 50) {
        return false; // 丢弃该节点
      }
    }

    const p = rawP;
    if (!p || !p.type) return false;
    const t = p.type.toLowerCase();
    if (SKIP_TYPES.has(t)) return false;
    if (t === "vless") {
      const hasReality = !!p["reality-opts"];
      const hasXhttp = !!p["xhttp-opts"];
      return hasReality || hasXhttp;
    }
    return true;
  });
  console.log(`✅【类型过滤后剩余】：${typeFiltered.length}`);

  // --------------------------
  // ② 只保留匹配地区的节点，不再保留其他地区
  // --------------------------
  const matchRegionList = [];
  for (const p of typeFiltered) {
    if (!p.name || !p.server || !p.port) continue;
    const hit = REGION_RULES.find(r => r.reg.test(p.name));
    if (hit) {
      matchRegionList.push({ p, hit });
    }
    // 不匹配的地区直接忽略，不加入其他候选池
  }
  console.log(`✅【地区匹配节点】：${matchRegionList.length}`);

  // 直接使用匹配地区的节点池，不再进行随机抽取
  const totalPool = [...matchRegionList];
  console.log(`✅【合并节点池（仅匹配地区）】：${totalPool.length}`);

  // --------------------------
  // ③ 全局复合指纹去重
  // --------------------------
  const seen = new Set();
  const dedupList = [];
  for (const item of totalPool) {
    const { p } = item;
    let fp;
    if (p.type.toLowerCase() === 'vless' && p['reality-opts']?.['public-key']) {
      fp = `${p.type}|${p.server}|${p.uuid}|${p['reality-opts']['public-key']}`;
    } else {
      fp = `${p.type}|${p.server}|${p.port}`;
    }
    if (seen.has(fp)) continue;
    seen.add(fp);
    dedupList.push(item);
  }
  console.log(`✅【节点池去重后剩余】：${dedupList.length}`);

  // --------------------------
  // ④ 重命名：各地区独立编号
  // --------------------------
  const regionCounter = {};
  const finalProxies = [];
  for (const item of dedupList) {
    const { p, hit } = item;
    regionCounter[hit.name] = (regionCounter[hit.name] || 0) + 1;
    const seq = String(regionCounter[hit.name]).padStart(2, "0");
    p.name = `${hit.flag} ${hit.name} ${seq} | ${p.type}`;
    finalProxies.push(p);
  }

  // 输出统计
  console.log(`✅【最终输出节点总数】：${finalProxies.length}`);
  console.log('各地区数量：');
  for (const [name, count] of Object.entries(regionCounter)) {
    console.log(`  ${name}：${count}`);
  }

  // 写出yaml
  const outputDoc = new yaml.Document();
  outputDoc.set("proxies", finalProxies);
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
