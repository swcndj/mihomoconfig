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
const OTHER_SAMPLE_RATIO = 0.20; // 非匹配地区随机抽取比例
// ========================================================
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));

// 深度清洗对象：消除 yaml 内部特殊标记，reality协议删除无效 skip-cert-verify
function cleanProxyObj(obj) {
  const o = JSON.parse(JSON.stringify(obj));
  if(o.type?.toLowerCase() === "vless" && (o["reality-opts"] || o["xhttp-opts"])){
    delete o["skip-cert-verify"];
  }
  return o;
}

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

// 数组随机抽样，不修改原数组，@param {Array} arr，@param {number} count 需要抽取数量
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
  // ① 类型过滤，先清洗对象
  // --------------------------
  const typeFiltered = allRawProxies.filter(rawP => {
    const p = cleanProxyObj(rawP);
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
  // ② 拆分为【匹配地区】、【其他候选池】两组
  // --------------------------
  const matchRegionList = [];
  const otherCandidateList = [];

  for (const p of typeFiltered) {
    if (!p.name || !p.server || !p.port) continue;
    const hit = REGION_RULES.find(r => r.reg.test(p.name));
    if(hit){
      matchRegionList.push({ p, hit });
    }else{
      // 类型合格，但地区不匹配，进入其他候选池
      otherCandidateList.push({ p, hit: { flag:"", name:"其他" } });
    }
  }
  console.log(`✅【地区匹配节点】：${matchRegionList.length}`);
  console.log(`✅【其他候选节点】：${otherCandidateList.length}`);

  // 随机抽取10%
  const sampleCount = Math.floor(otherCandidateList.length * OTHER_SAMPLE_RATIO);
  const sampledOtherList = sampleRandom(otherCandidateList, sampleCount);
  console.log(`✅【其他候选节点随机抽取数量 ${OTHER_SAMPLE_RATIO*100}%】：${sampledOtherList.length}`);

  // 合并总池：匹配地区 + 抽样出来的其他节点
  const totalPool = [...matchRegionList, ...sampledOtherList];
  console.log(`✅【合并节点池】：${totalPool.length}`);

  // --------------------------
  // ③ 全局复合指纹去重（A组B组一起去重，跨组去重）
  // --------------------------
  const seen = new Set();
  const dedupList = [];
  for(const item of totalPool){
    const {p} = item;
    let fp;
    if(p.type.toLowerCase() === 'vless' && p['reality-opts']?.['public-key']){
      fp = `${p.type}|${p.server}|${p.uuid}|${p['reality-opts']['public-key']}`;
    }else{
      fp = `${p.type}|${p.server}|${p.port}`;
    }
    if(seen.has(fp)) continue;
    seen.add(fp);
    dedupList.push(item);
  }
  console.log(`✅【节点池去重后剩余】：${dedupList.length}`);

  // --------------------------
  // ④ 重命名：各地区独立编号，“其他”独立编号
  // --------------------------
  const regionCounter = {};
  const finalProxies = [];
  for(const item of dedupList){
    const {p, hit} = item;
    regionCounter[hit.name] = (regionCounter[hit.name] || 0) + 1;
    const seq = String(regionCounter[hit.name]).padStart(2, "0");
    if(hit.name === "其他"){
      p.name = `其他 ${seq} | ${p.type}`;
    }else{
      p.name = `${hit.flag} ${hit.name} ${seq} | ${p.type}`;
    }
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
