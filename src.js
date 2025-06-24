import { connect } from "cloudflare:sockets";

// 配置区块
let 订阅路径 = "订阅路径";

let 验证UUID;

let 优选链接 = "https://raw.githubusercontent.com/ImLTHQ/edgetunnel/main/AutoTest.txt";
let 优选列表 = [];

let SOCKS5代理 = false;
let SOCKS5全局代理 = false;

let 反代IP = "ts.hpc.tw";

let NAT64前缀 = "2001:67c:2960:6464::";
let DOH地址 = "1.1.1.1";

// 网页入口
export default {
  async fetch(访问请求, env) {
    订阅路径 = env.SUB_PATH ?? 订阅路径;
    验证UUID = 生成UUID();
    优选链接 = env.TXT_URL ?? 优选链接;
    SOCKS5代理 = env.SOCKS5 ?? SOCKS5代理;
    SOCKS5全局代理 = env.SOCKS5_GLOBAL ?? SOCKS5全局代理;
    反代IP = env.PROXY_IP ?? 反代IP;
    NAT64前缀 = env.NAT64 ?? NAT64前缀;
    DOH地址 = env.DOH ?? DOH地址;

    const url = new URL(访问请求.url);
    const 读取我的请求标头 = 访问请求.headers.get("Upgrade");
    const WS请求 = 读取我的请求标头 == "websocket";
    const 不是WS请求 = 读取我的请求标头?.toLowerCase() !== "websocket";

    // 只允许 /订阅路径/ 开头的路径反代
    const 反代前缀 = `/${encodeURIComponent(订阅路径)}/`;
    if (url.pathname.startsWith(反代前缀)) {
      // 取出目标链接
      let target = decodeURIComponent(url.pathname.slice(反代前缀.length));
      try {
          const 请求对象 = new Request(target + url.search, {
            method: 访问请求.method,
            headers: 访问请求.headers,
            body: 访问请求.body,
          });
          const 响应对象 = await fetch(请求对象);
          return 响应对象;
      } catch {
        return new Response(null, { status: 404 });
      }
    }

    if (不是WS请求) {
      if (url.pathname == `/${encodeURIComponent(订阅路径)}`) {
        const 用户代理 = 访问请求.headers.get("User-Agent").toLowerCase();
        const 配置生成器 = {
          v2ray: v2ray配置文件,
          clash: clash配置文件,
          tips: 提示界面,
        };
        const 工具 = Object.keys(配置生成器).find((工具) => 用户代理.includes(工具));
        优选列表 = await 获取优选列表();
        const 生成配置 = 配置生成器[工具 || "tips"];
        return 生成配置(访问请求.headers.get("Host"));
      } else {
          return new Response(null, { status: 404 });
      }
    }

    if (WS请求) {
      return await 升级WS请求(访问请求);
    }
  },
};

// 脚本主要架构
// 第一步，读取和构建基础访问结构
async function 升级WS请求(访问请求) {
  const [客户端, WS接口] = new WebSocketPair(); //创建WS接口对象
  const 读取我的加密访问内容数据头 = 访问请求.headers.get('sec-websocket-protocol'); //读取访问标头中的WS通信数据
  const 解密数据 = 使用64位加解密(读取我的加密访问内容数据头); //解密目标访问数据，传递给TCP握手进程
  await 解析VL标头(解密数据, WS接口); //解析VL数据并进行TCP握手
  return new Response(null, { status: 101, webSocket: 客户端 }); //一切准备就绪后，回复客户端WS连接升级成功
}

function 使用64位加解密(还原混淆字符) {
  还原混淆字符 = 还原混淆字符.replace(/-/g, "+").replace(/_/g, "/");
  const 解密数据 = atob(还原混淆字符);
  const 解密 = Uint8Array.from(解密数据, (c) => c.charCodeAt(0));
  return 解密.buffer;
}

// 第二步，解读VL协议数据，创建TCP握手（直连、SOCKS5、反代、NAT64）
async function 解析VL标头(VL数据, WS接口, TCP接口) {
  if (验证VL的密钥(new Uint8Array(VL数据.slice(1, 17))) !== 验证UUID) {
    return null;
  }

  const 获取数据定位 = new Uint8Array(VL数据)[17];
  const 提取端口索引 = 18 + 获取数据定位 + 1;
  const 建立端口缓存 = VL数据.slice(提取端口索引, 提取端口索引 + 2);
  const 访问端口 = new DataView(建立端口缓存).getUint16(0);

  const 提取地址索引 = 提取端口索引 + 2;
  const 建立地址缓存 = new Uint8Array(VL数据.slice(提取地址索引, 提取地址索引 + 1));
  const 识别地址类型 = 建立地址缓存[0];

  let 地址长度 = 0;
  let 访问地址 = "";
  let 地址信息索引 = 提取地址索引 + 1;

  switch (识别地址类型) {
    case 1:
      地址长度 = 4;
      访问地址 = new Uint8Array(VL数据.slice(地址信息索引, 地址信息索引 + 地址长度)).join(".");
      break;
    case 2:
      地址长度 = new Uint8Array(VL数据.slice(地址信息索引, 地址信息索引 + 1))[0];
      地址信息索引 += 1;
      访问地址 = new TextDecoder().decode(VL数据.slice(地址信息索引, 地址信息索引 + 地址长度));
      break;
    case 3:
      地址长度 = 16;
      const dataView = new DataView(VL数据.slice(地址信息索引, 地址信息索引 + 地址长度));
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      访问地址 = ipv6.join(":");
      break;
  }

  const 写入初始数据 = VL数据.slice(地址信息索引 + 地址长度);

  // 优先SOCKS5全局
  if (SOCKS5全局代理 && SOCKS5代理) {
    TCP接口 = await 创建SOCKS5接口(识别地址类型, 访问地址, 访问端口);
    await TCP接口.opened;
  } else {
    try {
      TCP接口 = await connect({ hostname: 访问地址, port: 访问端口, allowHalfOpen: true });
      await TCP接口.opened;
    } catch {
      // 尝试SOCKS5
      if (SOCKS5代理) {
        try {
          TCP接口 = await 创建SOCKS5接口(识别地址类型, 访问地址, 访问端口);
          await TCP接口.opened;
        } catch {
          // SOCKS5失败 尝试NAT64
          try {
            const NAT64地址 = 识别地址类型 === 1
              ? 转换IPv4到NAT64(访问地址)
              : 转换IPv4到NAT64(await 解析域名到IPv4(访问地址));
            TCP接口 = await connect({ hostname: NAT64地址, port: 访问端口 });
            await TCP接口.opened;
          } catch {
            // NAT64失败 尝试反代
            let [反代IP地址, 反代IP端口] = 反代IP.split(":");
            TCP接口 = await connect({
              hostname: 反代IP地址,
              port: 反代IP端口 || 443,
            });
            await TCP接口.opened;
          }
        }
      } else {
        // 没有SOCKS5 尝试NAT64
        try {
          const NAT64地址 = 识别地址类型 === 1
            ? 转换IPv4到NAT64(访问地址)
            : 转换IPv4到NAT64(await 解析域名到IPv4(访问地址));
          TCP接口 = await connect({ hostname: NAT64地址, port: 访问端口 });
          await TCP接口.opened;
        } catch {
          // NAT64失败 尝试反代
          let [反代IP地址, 反代IP端口] = 反代IP.split(":");
          TCP接口 = await connect({
            hostname: 反代IP地址,
            port: 反代IP端口 || 443,
          });
          await TCP接口.opened;
        }
      }
    }
  }
  建立传输管道(WS接口, TCP接口, 写入初始数据);
}

// 将IPv4地址转换为NAT64 IPv6地址
function 转换IPv4到NAT64(ipv4地址) {
  const 十六进制 = ipv4地址.split(".").map(段 => (+段).toString(16).padStart(2, "0"));
  return `[${NAT64前缀}${十六进制[0]}${十六进制[1]}:${十六进制[2]}${十六进制[3]}]`;
}

// 解析域名到IPv4地址
async function 解析域名到IPv4(域名) {
  const { Answer } = await (await fetch(`https://${DOH地址}/dns-query?name=${域名}&type=A`, {
    headers: { "Accept": "application/dns-json" }
  })).json();
  return Answer.find(({ type }) => type === 1).data;
}

function 验证VL的密钥(arr, offset = 0) {
  const uuid = (
    转换密钥格式[arr[offset + 0]] +
    转换密钥格式[arr[offset + 1]] +
    转换密钥格式[arr[offset + 2]] +
    转换密钥格式[arr[offset + 3]] +
    "-" +
    转换密钥格式[arr[offset + 4]] +
    转换密钥格式[arr[offset + 5]] +
    "-" +
    转换密钥格式[arr[offset + 6]] +
    转换密钥格式[arr[offset + 7]] +
    "-" +
    转换密钥格式[arr[offset + 8]] +
    转换密钥格式[arr[offset + 9]] +
    "-" +
    转换密钥格式[arr[offset + 10]] +
    转换密钥格式[arr[offset + 11]] +
    转换密钥格式[arr[offset + 12]] +
    转换密钥格式[arr[offset + 13]] +
    转换密钥格式[arr[offset + 14]] +
    转换密钥格式[arr[offset + 15]]
  ).toLowerCase();
  return uuid;
}

const 转换密钥格式 = [];
for (let i = 0; i < 256; ++i) {
  转换密钥格式.push((i + 256).toString(16).slice(1));
}

// 第三步，创建客户端WS-CF-目标的传输通道并监听状态
async function 建立传输管道(WS接口, TCP接口, 写入初始数据) {
  WS接口.accept();
  await WS接口.send(new Uint8Array([0, 0]).buffer);

  const 传输数据 = TCP接口.writable.getWriter();
  const 读取数据 = TCP接口.readable.getReader();

  if (写入初始数据) await 传输数据.write(写入初始数据);

  WS接口.addEventListener("message", async (event) => {
    await 传输数据.write(event.data);
  });
  定时双端保活();
  (async () => {
    while (true) {
      const { value: 返回数据, done } = await 读取数据.read();
      if (done) break;
      if (返回数据) await WS接口.send(返回数据);
    }
  })();
  async function 定时双端保活() {
    while (true) {
      await new Promise(resolve => setTimeout(resolve, 10000));
      传输数据.write(new Uint8Array(0));
      WS接口.send('');
    }
  }
}

// SOCKS5部分
async function 创建SOCKS5接口(识别地址类型, 访问地址, 访问端口) {
  const { username, password, hostname, port } = await 获取SOCKS5代理(SOCKS5代理);
  const SOCKS5接口 = connect({ hostname, port });
  try {
    await SOCKS5接口.opened;
  } catch {
    return new Response("SOCKS5未连通", { status: 400 });
  }
  const writer = SOCKS5接口.writable.getWriter();
  const reader = SOCKS5接口.readable.getReader();
  const encoder = new TextEncoder();
  const socksGreeting = new Uint8Array([5, 2, 0, 2]); //支持无认证和用户名/密码认证
  await writer.write(socksGreeting);
  let res = (await reader.read()).value;
  if (res[1] === 0x02) {
    //用户名/密码认证
    if (!username || !password) {
      return 关闭接口并退出();
    }
    const authRequest = new Uint8Array([1, username.length, ...encoder.encode(username), password.length, ...encoder.encode(password)]);
    await writer.write(authRequest);
    res = (await reader.read()).value;
    if (res[0] !== 0x01 || res[1] !== 0x00) {
      return 关闭接口并退出();
    }
  }
  let 转换访问地址;
  switch (识别地址类型) {
    case 1: // IPv4
      转换访问地址 = new Uint8Array([1, ...访问地址.split(".").map(Number)]);
      break;
    case 2: // 域名
      转换访问地址 = new Uint8Array([3, 访问地址.length, ...encoder.encode(访问地址)]);
      break;
    case 3: // IPv6
      转换访问地址 = new Uint8Array([4, ...访问地址.split(":").flatMap((x) => [parseInt(x.slice(0, 2), 16), parseInt(x.slice(2), 16)])]);
      break;
    default:
      return 关闭接口并退出();
  }
  const socksRequest = new Uint8Array([5, 1, 0, ...转换访问地址, 访问端口 >> 8, 访问端口 & 0xff]);
  await writer.write(socksRequest);
  res = (await reader.read()).value;
  if (res[0] !== 0x05 || res[1] !== 0x00) {
    return 关闭接口并退出();
  }
  writer.releaseLock();
  reader.releaseLock();
  return SOCKS5接口;
  function 关闭接口并退出() {
    writer.releaseLock();
    reader.releaseLock();
    SOCKS5接口.close();
    return new Response("SOCKS5握手失败", { status: 400 });
  }
}
async function 获取SOCKS5代理(SOCKS5) {
  const [latter, former] = SOCKS5.split("@").reverse();
  let username, password, hostname, port;
  if (former) {
    const formers = former.split(":");
    username = formers[0];
    password = formers[1];
  }
  const latters = latter.split(":");
  port = Number(latters.pop());
  hostname = latters.join(":");
  return { username, password, hostname, port };
}

// 其它
function 生成UUID() {
  const 二十位 = Array.from(new TextEncoder().encode(订阅路径))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("")
    .slice(0, 20)
    .padEnd(20, "0");

  const 前八位 = 二十位
    .slice(0, 8);
  const 后十二位 = 二十位
    .slice(-12);

  return `${前八位}-0000-4000-8000-${后十二位}`;
}

async function 提示界面() {
  const 提示界面 = `
<title>订阅-${订阅路径}</title>
<style>
  body {
    font-size: 25px;
    text-align: center;
  }
</style>
<strong>请把链接导入 Clash 或 V2Ray</strong>
`;

  return new Response(提示界面, {
    status: 200,
    headers: { "Content-Type": "text/html;charset=utf-8" },
  });
}

async function 获取优选列表() {
  if (优选链接) {
    const 读取优选文本 = await fetch(优选链接);
    const 转换优选文本 = await 读取优选文本.text();
    return 转换优选文本
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line);
  }
  return [];
}

function 处理优选列表(优选列表, hostName) {
  优选列表.unshift(`${hostName}#原生节点`);
  return 优选列表.map((获取优选, index) => {
    const [地址端口, 节点名字 = `节点 ${index + 1}`] = 获取优选.split("#");
    const 拆分地址端口 = 地址端口.split(":");
    const 端口 = 拆分地址端口.length > 1 ? Number(拆分地址端口.pop()) : 443;
    const 地址 = 拆分地址端口.join(":");
    return { 地址, 端口, 节点名字 };
  });
}

// 订阅页面
function v2ray配置文件(hostName) {
  const 节点列表 = 处理优选列表(优选列表, hostName);
  const 配置内容 = 节点列表
    .map(({ 地址, 端口, 节点名字 }) => {
      return `vless://${验证UUID}@${地址}:${端口}?encryption=none&security=tls&sni=${hostName}&fp=chrome&type=ws&host=${hostName}&path=${encodeURIComponent("/?ed=2560")}#${节点名字}`;
    })
    .join("\n");

  return new Response(配置内容, {
    status: 200,
    headers: { "Content-Type": "text/plain;charset=utf-8" },
  });
}

function clash配置文件(hostName) {
  const 节点列表 = 处理优选列表(优选列表, hostName);
  const 生成节点 = (节点列表) => {
    return 节点列表.map(({ 地址, 端口, 节点名字 }) => {
      return {
        nodeConfig: `- name: ${节点名字}
  type: vless
  server: ${地址}
  port: ${端口}
  uuid: ${验证UUID}
  udp: true
  tls: true
  sni: ${hostName}
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}
      User-Agent: Chrome`,
        proxyConfig: `    - ${节点名字}`,
      };
    });
  };

  const 节点配置 = 生成节点(节点列表)
    .map((node) => node.nodeConfig)
    .join("\n");
  const 代理配置 = 生成节点(节点列表)
    .map((node) => node.proxyConfig)
    .join("\n");

  const 配置内容 = `
proxies:
${节点配置}

proxy-groups:
- name: 海外规则
  type: select
  proxies:
    - 延迟优选
    - 故障转移
    - DIRECT
    - REJECT
${代理配置}
- name: 国内规则
  type: select
  proxies:
    - DIRECT
    - 延迟优选
    - 故障转移
    - REJECT
${代理配置}
- name: 广告屏蔽
  type: select
  proxies:
    - REJECT
    - DIRECT
    - 延迟优选
    - 故障转移
${代理配置}
- name: 延迟优选
  type: url-test
  url: https://www.google.com/generate_204
  interval: 30
  tolerance: 50
  proxies:
${代理配置}
- name: 故障转移
  type: fallback
  url: https://www.google.com/generate_204
  interval: 30
  proxies:
${代理配置}

rules:
  - GEOSITE,category-ads-all,广告屏蔽
  - GEOSITE,cn,国内规则
  - GEOIP,CN,国内规则,no-resolve
  - MATCH,海外规则
`;

  return new Response(配置内容, {
    status: 200,
    headers: { "Content-Type": "text/plain;charset=utf-8" },
  });
}
