const fs = require('fs');
const yaml = require('yaml');

// ========== 【配置区】 ==========
const REGION_RULES = [
  { reg: /香港|HK|HKG|hk|🇭🇰/, flag: "🇭🇰", name: "香港" },
  { reg: /台湾|TW|tw|🇹🇼/, flag: "🇹🇼", name: "台湾" },
  { reg: /日本|JP|JPN|jp|🇯🇵/, flag: "🇯🇵", name: "日本" },
  { reg: /美国|US|USA|us|🇺🇸/, flag: "🇺🇸", name: "美国" },
  { reg: /新加坡|SG|SGP|sg|🇸🇬/, flag: "🇸🇬", name: "新加坡" },
  { reg: /韩国|KR|KOR|kr|🇰🇷/, flag: "🇰🇷", name: "韩国" },
];
const SKIP_TYPES = new Set(["rematch","http","socks5","ss","ssr","snell","vmess","trojan","hysteria","wireguard","tailscale","ssh","openvpn"]);
const SUBS = JSON.parse(fs.readFileSync("./subs.json","utf8"));
const OUTPUT_FILE = "nodes.yaml"; 
// ========================================================

const fetch = (...args) => import('node-fetch').then(({default:fetch})=>fetch(...args));
const regionCounter = {};
const seen = new Set();
let allProxies = [];

(async function main(){
  for(const subUrl of SUBS){
    try{
      const res = await fetch(subUrl, {timeout:15000});
      if(!res.ok) continue;
      const text = await res.text();
      const doc = yaml.parse(text);
      if(!doc || !Array.isArray(doc.proxies)) continue;

      for(const p of doc.proxies){
        if(!p.type || SKIP_TYPES.has(p.type)) continue;

        const hit = REGION_RULES.find(r => r.reg.test(p.name));
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
      console.log("订阅拉取失败:", subUrl, e.message);
    }
  }

  const out = yaml.stringify({ proxies: allProxies });
  fs.writeFileSync(OUTPUT_FILE, out);
  console.log(`✅ 完成，有效节点：${allProxies.length}，输出至 ${OUTPUT_FILE}`);
})();
