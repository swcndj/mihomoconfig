const fs = require('fs');
const yaml = require('yaml');

// ========== 配置区 ==========
const REGION_RULES = [
  { reg: /香港|HK|HKG|hk|🇭🇰/, flag: "🇭🇰", name: "香港" },
  { reg: /台湾|TW|tw|🇹🇼/, flag: "🇹🇼", name: "台湾" },
  { reg: /日本|JP|JPN|jp|🇯🇵/, flag: "🇯🇵", name: "日本" },
  { reg: /美国|US|USA|us|🇺🇸/, flag: "🇺🇸", name: "美国" },
  { reg: /新加坡|SG|SGP|sg|🇸🇬/, flag: "🇸🇬", name: "新加坡" },
  { reg: /韩国|KR|KOR|kr|🇰🇷/, flag: "🇰🇷", name: "韩国" },
];
const SKIP_TYPES = new Set(["http","socks5","ss","ssr","snell","hysteria","wireguard","tailscale","ssh","openvpn"]);
const SUBS = JSON.parse(fs.readFileSync("./subs.json","utf8"));
const OUTPUT_FILE = "nodes.yaml";
// ========================================================

const fetch = (...args) => import('node‑fetch').then(({default:fetch})=>fetch(...args));
const regionCounter = {};
const seen = new Set();
let allProxies = [];

/**
 * 深度清洗对象：把yaml库内部特殊对象转普通JS plain object，消除流式标记，解决输出乱"-"问题
 */
function cleanProxyObj(obj) {
  return JSON.parse(JSON.stringify(obj));
}

(async function main(){
  for(const subUrl of SUBS){
    try{
      const res = await fetch(subUrl, {timeout:15000});
      if(!res.ok) {
        console.log(`skip http not ok: ${subUrl}`);
        continue;
      }
      const text = await res.text();
      const doc = yaml.parse(text);
      // 兼容：订阅可能是完整clash配置（带mixed‑port等），只取proxies
      if(!doc || !Array.isArray(doc.proxies)){
        console.log(`skip no proxies array: ${subUrl}`);
        continue;
      }
      const rawProxies = doc.proxies;

      for(const rawP of rawProxies){
        // 清洗，彻底消除yaml内部特殊对象
        const p = cleanProxyObj(rawP);
        if(!p.type || SKIP_TYPES.has(p.type.toLowerCase())) continue;

        const hit = REGION_RULES.find(r => r.reg.test(p.name || ""));
        if(!hit) continue;

        const fp = `${p.server}:${p.port}`;
        if(seen.has(fp)) continue;
        seen.add(fp);

        regionCounter[hit.name] = (regionCounter[hit.name] || 0)+1;
        const seq = String(regionCounter[hit.name]).padStart(2,"0");
        p.name = `${hit.flag} ${hit.name} #${seq} | ${p.type}`;
        allProxies.push(p);
      }
    }catch(e){
      console.log("订阅拉取/解析失败:", subUrl, e.message);
    }
  }

  // 构建输出，强制块模式，禁止任何flow大括号单行格式
  const outputDoc = new yaml.Document();
  outputDoc.set("proxies", allProxies);
  // 关键配置：flow:false，完全禁用 { } 流式语法，全部输出多行缩进
  const outputYaml = outputDoc.toString({
    indent: 2,
    flow: false,
    singleQuote: false,
    doubleQuote: false,
    lineWidth: 0
  });

  fs.writeFileSync(OUTPUT_FILE, outputYaml);
  console.log(`✅ 完成，有效节点：${allProxies.length}，输出 ${OUTPUT_FILE}`);
})();
