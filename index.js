#!/usr/bin/env node

const os = require('os');
const http = require('http');
const fs = require('fs');
const net = require('net');
const dns = require('dns');
const path = require('path');
const https = require('https');
const crypto = require('crypto');
const { Buffer } = require('buffer');
const axios = require('axios');
const si = require('systeminformation');
const grpc = require('@grpc/grpc-js');
const { spawn } = require('child_process');
const protoLoader = require('@grpc/proto-loader');
const { WebSocket, createWebSocketStream } = require('ws');

// ========================== 环境变量配置 ==========================
const UUID = process.env.UUID || 'd1cf4b9c-3e57-085d-b34a-797fcf601381';
const NEZHA_SERVER = process.env.NEZHA_SERVER || '';
const NEZHA_KEY = process.env.NEZHA_KEY || '';             
const DOMAIN = process.env.DOMAIN || 'your-domain.com';    
const AUTO_ACCESS = process.env.AUTO_ACCESS || false;      
const SUB_PATH = process.env.SUB_PATH || 'vercel';           
const NAME = process.env.NAME || 'Vercel';                       
const PORT = process.env.PORT || 3000;                    

// NZ-Agent
const AGENT_VERSION = 'nodejs-9.9.9';
const REPORT_DELAY = 4;
const RETRY_DELAY = 10000;
const IP_REPORT_PERIOD = 1800;
const NETWORK_TIMEOUT = 8000;

// 日志控制 
const SHOW_LOG = !!(process.env.SHOW_LOG);
function log(...args) { if (SHOW_LOG) console.log(...args); }
function logErr(...args) { if (SHOW_LOG) console.error(...args); }
function logWarn(...args) { if (SHOW_LOG) console.warn(...args); }

// 辅助工具
const WSPATH = process.env.WSPATH || UUID.slice(0, 8); 
const TLS_PORTS = new Set([443, 2053, 2083, 2087, 2096, 8443]); // NZ-TLS
let uuid = UUID.replace(/-/g, ""), CurrentDomain = DOMAIN, Tls = 'tls', CurrentPort = 443, ISP = '';
const DNS_SERVERS = ['8.8.4.4', '1.1.1.1'];
const BLOCKED_DOMAINS = [
  'speedtest.net', 'fast.com', 'speedtest.cn', 'speed.cloudflare.com', 'speedof.me',
   'testmy.net', 'bandwidth.place', 'speed.io', 'librespeed.org', 'speedcheck.org'
];

//  TLS 检测
function shouldUseTLS(server) {
    const parts = server.split(':');
    if (parts.length < 2) return false;
    const port = parseInt(parts[parts.length - 1], 10);
    return TLS_PORTS.has(port);
}

// block speedtest domains
function isBlockedDomain(host) {
  if (!host) return false;
  const hostLower = host.toLowerCase();
  return BLOCKED_DOMAINS.some(blocked => {
    return hostLower === blocked || hostLower.endsWith('.' + blocked);
  });
}

// 获取isp
async function getisp() {
  try {
    const res = await axios.get('https://api.ip.sb/geoip', { headers: { 'User-Agent': 'Mozilla/5.0', timeout: 3000 }});
    const data = res.data;
    ISP = `${data.country_code}-${data.isp}`.replace(/ /g, '_');
  } catch (e) {
    try {
      const res2 = await axios.get('http://ip-api.com/json', { headers: { 'User-Agent': 'Mozilla/5.0', timeout: 3000 }});
      const data2 = res2.data;
      ISP = `${data2.countryCode}-${data2.org}`.replace(/ /g, '_');
    } catch (e2) {
      ISP = 'Unknown';
    }
  }
}

// 获取ip
async function getip() {
  if (!DOMAIN || DOMAIN === 'your-domain.com') {
      try {
          const res = await axios.get('https://api-ipv4.ip.sb/ip', { timeout: 5000 });
          const ip = res.data.trim();
          CurrentDomain = ip, Tls = 'none', CurrentPort = PORT;
      } catch (e) {
          console.error('Failed to get IP', e.message);
          CurrentDomain = 'cahnge-your-domain.com', Tls = 'tls', CurrentPort = 443;
      }
  } else {
      CurrentDomain = DOMAIN, Tls = 'tls', CurrentPort = 443;
  }
}

// HTTP 路由
const httpServer = http.createServer(async (req, res) => {
  if (req.url === '/') {
    const filePath = path.join(__dirname, 'index.html');
    fs.readFile(filePath, 'utf8', (err, content) => {
      if (err) {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('Hello world!');
        return;
      }
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(content);
    });
    return;
  } else if (req.url === `/${SUB_PATH}`) {
    await getisp();await getip();
    const namePart = NAME ? `${NAME}-${ISP}` : ISP;
    const tlsParam = Tls === 'tls' ? 'tls' : 'none';
    const ssTlsParam = Tls === 'tls' ? 'tls;' : '';
    const vlsURL = `vless://${UUID}@${CurrentDomain}:${CurrentPort}?encryption=none&security=${tlsParam}&sni=${CurrentDomain}&fp=chrome&type=ws&host=${CurrentDomain}&path=%2F${WSPATH}#${namePart}`;
    const troURL = `trojan://${UUID}@${CurrentDomain}:${CurrentPort}?security=${tlsParam}&sni=${CurrentDomain}&fp=chrome&type=ws&host=${CurrentDomain}&path=%2F${WSPATH}#${namePart}`;
    const ssMethodPassword = Buffer.from(`none:${UUID}`).toString('base64');
    const ssURL = `ss://${ssMethodPassword}@${CurrentDomain}:${CurrentPort}?plugin=v2ray-plugin;mode%3Dwebsocket;host%3D${CurrentDomain};path%3D%2F${WSPATH};${ssTlsParam}sni%3D${CurrentDomain};skip-cert-verify%3Dtrue;mux%3D0#${namePart}`;
    const subscription = vlsURL + '\n' + troURL + '\n' + ssURL;
    const base64Content = Buffer.from(subscription).toString('base64');

    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end(base64Content + '\n');
  } else {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found\n');
  }
});

// Custom DNS
function resolveHost(host) {
  return new Promise((resolve, reject) => {
    if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(host)) {
      resolve(host);
      return;
    }
    let attempts = 0;
    function tryNextDNS() {
      if (attempts >= DNS_SERVERS.length) {
        reject(new Error(`Failed to resolve ${host} with all DNS servers`));
        return;
      }
      const dnsServer = DNS_SERVERS[attempts];
      attempts++;
      const dnsQuery = `https://dns.google/resolve?name=${encodeURIComponent(host)}&type=A`;
      axios.get(dnsQuery, {
        timeout: 5000,
        headers: { 'Accept': 'application/dns-json' }
      })
        .then(response => {
          const data = response.data;
          if (data.Status === 0 && data.Answer && data.Answer.length > 0) {
            const ip = data.Answer.find(record => record.type === 1);
            if (ip) { resolve(ip.data); return; }
          }
          tryNextDNS();
        })
        .catch(error => { tryNextDNS(); });
    }
    tryNextDNS();
  });
}

// VLE-SS处理
function handleVlsConnection(ws, msg) {
  const [VERSION] = msg;
  const id = msg.slice(1, 17);
  if (!id.every((v, i) => v == parseInt(uuid.substr(i * 2, 2), 16))) return false;

  let i = msg.slice(17, 18).readUInt8() + 19;
  const port = msg.slice(i, i += 2).readUInt16BE(0);
  const ATYP = msg.slice(i, i += 1).readUInt8();
  const host = ATYP == 1 ? msg.slice(i, i += 4).join('.') :
    (ATYP == 2 ? new TextDecoder().decode(msg.slice(i + 1, i += 1 + msg.slice(i, i + 1).readUInt8())) :
      (ATYP == 3 ? msg.slice(i, i += 16).reduce((s, b, i, a) => (i % 2 ? s.concat(a.slice(i - 1, i + 1)) : s), []).map(b => b.readUInt16BE(0).toString(16)).join(':') : ''));

  if (isBlockedDomain(host)) { ws.close(); return false; }
  ws.send(new Uint8Array([VERSION, 0]));
  const duplex = createWebSocketStream(ws);
  resolveHost(host)
    .then(resolvedIP => {
      net.connect({ host: resolvedIP, port }, function () {
        this.write(msg.slice(i));
        duplex.on('error', () => { }).pipe(this).on('error', () => { }).pipe(duplex);
      }).on('error', () => { });
    })
    .catch(error => {
      net.connect({ host, port }, function () {
        this.write(msg.slice(i));
        duplex.on('error', () => { }).pipe(this).on('error', () => { }).pipe(duplex);
      }).on('error', () => { });
    });
  return true;
}

// Tro-jan处理
function handleTrojConnection(ws, msg) {
  try {
    if (msg.length < 58) return false;
    const receivedPasswordHash = msg.slice(0, 56).toString();
    const possiblePasswords = [UUID];
    let matchedPassword = null;
    for (const pwd of possiblePasswords) {
      const hash = crypto.createHash('sha224').update(pwd).digest('hex');
      if (hash === receivedPasswordHash) { matchedPassword = pwd; break; }
    }
    if (!matchedPassword) return false;
    let offset = 56;
    if (msg[offset] === 0x0d && msg[offset + 1] === 0x0a) offset += 2;
    const cmd = msg[offset];
    if (cmd !== 0x01) return false;
    offset += 1;
    const atyp = msg[offset];
    offset += 1;
    let host, port;
    if (atyp === 0x01) {
      host = msg.slice(offset, offset + 4).join('.'); offset += 4;
    } else if (atyp === 0x03) {
      const hostLen = msg[offset]; offset += 1;
      host = msg.slice(offset, offset + hostLen).toString(); offset += hostLen;
    } else if (atyp === 0x04) {
      host = msg.slice(offset, offset + 16).reduce((s, b, i, a) => (i % 2 ? s.concat(a.slice(i - 1, i + 1)) : s), []).map(b => b.readUInt16BE(0).toString(16)).join(':'); offset += 16;
    } else { return false; }
    port = msg.readUInt16BE(offset); offset += 2;
    if (offset < msg.length && msg[offset] === 0x0d && msg[offset + 1] === 0x0a) offset += 2;
    if (isBlockedDomain(host)) { ws.close(); return false; }
    const duplex = createWebSocketStream(ws);
    resolveHost(host)
      .then(resolvedIP => {
        net.connect({ host: resolvedIP, port }, function () {
          if (offset < msg.length) this.write(msg.slice(offset));
          duplex.on('error', () => { }).pipe(this).on('error', () => { }).pipe(duplex);
        }).on('error', () => { });
      })
      .catch(error => {
        net.connect({ host, port }, function () {
          if (offset < msg.length) this.write(msg.slice(offset));
          duplex.on('error', () => { }).pipe(this).on('error', () => { }).pipe(duplex);
        }).on('error', () => { });
      });
    return true;
  } catch (error) { return false; }
}

// Ss处理
function handleSsConnection(ws, msg) {
  try {
    let offset = 0;
    const atyp = msg[offset]; offset += 1;
    let host, port;
    if (atyp === 0x01) {
      host = msg.slice(offset, offset + 4).join('.'); offset += 4;
    } else if (atyp === 0x03) {
      const hostLen = msg[offset]; offset += 1;
      host = msg.slice(offset, offset + hostLen).toString(); offset += hostLen;
    } else if (atyp === 0x04) {
      host = msg.slice(offset, offset + 16).reduce((s, b, i, a) => (i % 2 ? s.concat(a.slice(i - 1, i + 1)) : s), []).map(b => b.readUInt16BE(0).toString(16)).join(':'); offset += 16;
    } else { return false; }
    port = msg.readUInt16BE(offset); offset += 2;
    if (isBlockedDomain(host)) { ws.close(); return false; }
    const duplex = createWebSocketStream(ws);
    resolveHost(host)
      .then(resolvedIP => {
        net.connect({ host: resolvedIP, port }, function () {
          if (offset < msg.length) this.write(msg.slice(offset));
          duplex.on('error', () => { }).pipe(this).on('error', () => { }).pipe(duplex);
        }).on('error', () => { });
      })
      .catch(error => {
        net.connect({ host, port }, function () {
          if (offset < msg.length) this.write(msg.slice(offset));
          duplex.on('error', () => { }).pipe(this).on('error', () => { }).pipe(duplex);
        }).on('error', () => { });
      });
    return true;
  } catch (error) { return false; }
}

// Ws handler
const wss = new WebSocket.Server({ server: httpServer });
wss.on('connection', (ws, req) => {
  const url = req.url || '';
  const expectedPath = `/${WSPATH}`;
  if (!url.startsWith(expectedPath)) { ws.close(); return; }

  ws.once('message', msg => {
    if (msg.length > 17 && msg[0] === 0) {
      const id = msg.slice(1, 17);
      const isVless = id.every((v, i) => v == parseInt(uuid.substr(i * 2, 2), 16));
      if (isVless) { if (!handleVlsConnection(ws, msg)) ws.close(); return; }
    }
    if (msg.length >= 58) { if (handleTrojConnection(ws, msg)) return; }
    if (msg.length > 0 && (msg[0] === 0x01 || msg[0] === 0x03 || msg[0] === 0x04)) {
      if (handleSsConnection(ws, msg)) return;
    }
    ws.close();
  }).on('error', () => { });
});

// 添加自动保活任务
async function addAccessTask() {
  if (!AUTO_ACCESS) return;
  if (!DOMAIN) return;
  const fullURL = `https://${DOMAIN}/${SUB_PATH}`;
  try {
    const res = await axios.post("https://oooo.serv00.net/add-url", { url: fullURL }, { headers: { 'Content-Type': 'application/json' } });
    console.log('Automatic Access Task added successfully');
  } catch (error) { }
}

// NZ-Agent: Proto 定义 
const PROTO_CONTENT = `
syntax = "proto3";
option go_package = "./proto";
package proto;

service NezhaService {
  rpc ReportSystemState(stream State) returns (stream Receipt) {}
  rpc ReportSystemInfo(Host) returns (Receipt) {}
  rpc RequestTask(stream TaskResult) returns (stream Task) {}
  rpc IOStream(stream IOStreamData) returns (stream IOStreamData) {}
  rpc ReportGeoIP(GeoIP) returns (GeoIP) {}
  rpc ReportSystemInfo2(Host) returns (Uint64Receipt) {}
}

message Host {
  string platform = 1;
  string platform_version = 2;
  repeated string cpu = 3;
  uint64 mem_total = 4;
  uint64 disk_total = 5;
  uint64 swap_total = 6;
  string arch = 7;
  string virtualization = 8;
  uint64 boot_time = 9;
  string version = 10;
  repeated string gpu = 11;
}

message State {
  double cpu = 1;
  uint64 mem_used = 2;
  uint64 swap_used = 3;
  uint64 disk_used = 4;
  uint64 net_in_transfer = 5;
  uint64 net_out_transfer = 6;
  uint64 net_in_speed = 7;
  uint64 net_out_speed = 8;
  uint64 uptime = 9;
  double load1 = 10;
  double load5 = 11;
  double load15 = 12;
  uint64 tcp_conn_count = 13;
  uint64 udp_conn_count = 14;
  uint64 process_count = 15;
  repeated State_SensorTemperature temperatures = 16;
  repeated double gpu = 17;
}

message State_SensorTemperature {
  string name = 1;
  double temperature = 2;
}

message Task {
  uint64 id = 1;
  uint64 type = 2;
  string data = 3;
}

message TaskResult {
  uint64 id = 1;
  uint64 type = 2;
  float delay = 3;
  string data = 4;
  bool successful = 5;
}

message Receipt { bool proced = 1; }
message Uint64Receipt { uint64 data = 1; }
message IOStreamData { bytes data = 1; }

message GeoIP {
  bool use6 = 1;
  IP ip = 2;
  string country_code = 3;
  uint64 dashboard_boot_time = 4;
}

message IP {
  string ipv4 = 1;
  string ipv6 = 2;
}
`;

function loadProto() {
    const tmpFile = path.join(os.tmpdir(), `nezha_${process.pid}.proto`);
    fs.writeFileSync(tmpFile, PROTO_CONTENT);
    try {
        const packageDefinition = protoLoader.loadSync(tmpFile, {
            keepCase: false, longs: Number, enums: Number, defaults: true, oneofs: true,
        });
        const protoDescriptor = grpc.loadPackageDefinition(packageDefinition);
        return protoDescriptor.proto;
    } finally {
        try { fs.unlinkSync(tmpFile); } catch (e) {}
    }
}

// NZ-Agent: gRPC 认证
function buildMetadata() {
    const meta = new grpc.Metadata();
    meta.add('client-secret', NEZHA_KEY);
    meta.add('client-uuid', UUID);
    meta.add('client_secret', NEZHA_KEY);
    meta.add('client_uuid', UUID);
    return meta;
}

// NZ-Agent: 系统监控
let netInTransfer = 0, netOutTransfer = 0;
let netInSpeed = 0, netOutSpeed = 0;
let lastNetUpdate = 0;
let activeIOStreams = 0;
let lastReportedIP = null;

const EXCLUDE_INTERFACES = ['lo', 'tun', 'docker', 'veth', 'br-', 'vmbr', 'vnet', 'kube', 'Meta', 'tailscale', 'fw', 'tap'];
const EXPECT_FS_TYPES = new Set(['apfs', 'ext4', 'ext3', 'ext2', 'f2fs', 'reiserfs', 'jfs', 'bcachefs', 'btrfs', 'fuseblk', 'zfs', 'simfs', 'ntfs', 'fat32', 'exfat', 'xfs', 'fuse.rclone']);

function shouldExcludeInterface(name) { return EXCLUDE_INTERFACES.some(ex => name.includes(ex)); }

function getArch() {
    switch (process.arch) {
        case 'x64': return 'x86_64';
        case 'arm64': return 'aarch64';
        case 'ia32': return 'i386';
        default: return process.arch;
    }
}

async function getHost() {
    const [osInfo, cpuInfo, memInfo, fsSize] = await Promise.all([
        si.osInfo(), si.cpu(), si.mem(), si.fsSize(),
    ]);
    let platform = osInfo.distro || process.platform;
    let platformVersion = osInfo.release || '';
    const cpuStr = `${cpuInfo.manufacturer} ${cpuInfo.brand} ${cpuInfo.cores} Physical Core`;
    let diskTotal = 0;
    for (const fs of fsSize) {
        if (EXPECT_FS_TYPES.has((fs.type || '').toLowerCase())) diskTotal += fs.size || 0;
    }
    const bootTime = Math.floor(Date.now() / 1000 - os.uptime());
    return {
        platform, platformVersion, cpu: [cpuStr], memTotal: memInfo.total,
        diskTotal, swapTotal: memInfo.swaptotal || 0, arch: getArch(),
        virtualization: '', bootTime, version: AGENT_VERSION, gpu: [],
    };
}

async function trackNetworkSpeed() {
    try {
        const networkStats = await si.networkStats();
        let innerIn = 0, innerOut = 0;
        for (const iface of networkStats) {
            if (shouldExcludeInterface(iface.iface)) continue;
            innerIn += iface.rx_bytes || 0;
            innerOut += iface.tx_bytes || 0;
        }
        const now = Math.floor(Date.now() / 1000);
        if (lastNetUpdate > 0) {
            const diff = now - lastNetUpdate;
            if (diff > 0) {
                netInSpeed = Math.max(0, (innerIn - netInTransfer) / diff);
                netOutSpeed = Math.max(0, (innerOut - netOutTransfer) / diff);
            }
        }
        netInTransfer = innerIn;
        netOutTransfer = innerOut;
        lastNetUpdate = now;
    } catch (e) { }
}

function getConnCount() {
    if (process.platform === 'linux') {
        try {
            const tcp = fs.readFileSync('/proc/net/tcp', 'utf8');
            const tcp6 = fs.readFileSync('/proc/net/tcp6', 'utf8');
            const udp = fs.readFileSync('/proc/net/udp', 'utf8');
            const udp6 = fs.readFileSync('/proc/net/udp6', 'utf8');
            const tcpCount = Math.max(0, tcp.split('\n').length - 2) + Math.max(0, tcp6.split('\n').length - 2);
            const udpCount = Math.max(0, udp.split('\n').length - 2) + Math.max(0, udp6.split('\n').length - 2);
            return [tcpCount, udpCount];
        } catch (e) { return [0, 0]; }
    }
    return [0, 0];
}

function getProcessCountSync() {
    if (process.platform === 'linux') {
        try {
            const dirs = fs.readdirSync('/proc');
            let count = 0;
            for (let i = 0; i < dirs.length; i++) { if (/^\d+$/.test(dirs[i])) count++; }
            return count;
        } catch (e) { return 0; }
    }
    return -1;
}

async function getState() {
    const [currentLoad, memInfo, fsSize] = await Promise.all([
        si.currentLoad(), si.mem(), si.fsSize(),
    ]);
    const cpu = currentLoad.currentLoad || 0;
    let memUsed;
    if (process.platform === 'linux' && memInfo.active) {
        memUsed = memInfo.active;
    } else if (process.platform === 'linux') {
        memUsed = Math.max(0, (memInfo.used || 0) - (memInfo.buffcache || 0));
    } else {
        memUsed = memInfo.used || 0;
    }
    const swapUsed = memInfo.swapused || 0;
    let diskUsed = 0;
    for (const fs of fsSize) {
        if (EXPECT_FS_TYPES.has((fs.type || '').toLowerCase())) diskUsed += fs.used || 0;
    }
    const load = os.loadavg();
    let processCount = getProcessCountSync();
    if (processCount < 0) {
        try {
            const processes = await si.processes();
            processCount = processes.all || 0;
        } catch (e) { processCount = 0; }
    }
    const uptime = Math.floor(os.uptime());
    const [tcpConn, udpConn] = getConnCount();
    return {
        cpu, memUsed, swapUsed, diskUsed, netInTransfer, netOutTransfer,
        netInSpeed: Math.floor(netInSpeed), netOutSpeed: Math.floor(netOutSpeed),
        uptime, load1: load[0] || 0, load5: load[1] || 0, load15: load[2] || 0,
        tcpConnCount: tcpConn, udpConnCount: udpConn, processCount, temperatures: [], gpu: [],
    };
}

// NZ-Agent: GeoIP
function makeLookup(family) {
    return (hostname, opts, callback) => { dns.lookup(hostname, { family }, callback); };
}

function parseIPFromResponse(body, family) {
    const trimmed = body.trim();
    if (family === 4 && net.isIPv4(trimmed)) return trimmed;
    if (family === 6 && net.isIPv6(trimmed)) return trimmed;
    const lines = trimmed.split('\n');
    for (const line of lines) {
        if (line.startsWith('ip=')) {
            const ip = line.substring(3).trim();
            if (family === 4 && net.isIPv4(ip)) return ip;
            if (family === 6 && net.isIPv6(ip)) return ip;
        }
    }
    return '';
}

async function fetchIP() {
    const ipv4Endpoints = ['https://ipv4.ip.sb/ip', 'https://blog.cloudflare.com/cdn-cgi/trace', 'https://developers.cloudflare.com/cdn-cgi/trace'];
    const ipv6Endpoints = ['https://ipv6.ip.sb/ip', 'https://blog.cloudflare.com/cdn-cgi/trace', 'https://developers.cloudflare.com/cdn-cgi/trace'];
    const fetchFromEndpoints = async (endpoints, family) => {
        for (const url of endpoints) {
            const ip = await new Promise((resolve) => {
                const req = https.get(url, { timeout: 10000, headers: { 'User-Agent': 'Mozilla/5.0' }, lookup: makeLookup(family) }, (res) => {
                    let data = '';
                    res.on('data', (chunk) => data += chunk);
                    res.on('end', () => { resolve(parseIPFromResponse(data, family)); });
                });
                req.on('error', () => resolve(''));
                req.on('timeout', () => { req.destroy(); resolve(''); });
            });
            if (ip) return ip;
        }
        return '';
    };
    const [ipv4, ipv6] = await Promise.all([fetchFromEndpoints(ipv4Endpoints, 4), fetchFromEndpoints(ipv6Endpoints, 6)]);
    return { ipv4, ipv6 };
}

async function reportGeoIP(client, metadata, forceUpdate = false) {
    try {
        const { ipv4, ipv6 } = await fetchIP();
        const currentIPKey = ipv4 || ipv6 || '';
        if (!forceUpdate && lastReportedIP !== null && currentIPKey === lastReportedIP) return true;
        if (!ipv4 && !ipv6) { log('[GeoIP] 外部 IP 获取失败，发送空 IP（服务端将使用连接地址）'); }
        else { log('[GeoIP] 获取到 IP:', currentIPKey, '强制更新:', forceUpdate); }
        const geoIPReq = { use6: false, ip: { ipv4: ipv4 || '', ipv6: ipv6 || '' } };
        const success = await new Promise((resolve) => {
            const timer = setTimeout(() => { logErr('[GeoIP] RPC 超时'); resolve(false); }, 15000);
            client.ReportGeoIP(geoIPReq, metadata, (err, resp) => {
                clearTimeout(timer);
                if (err) { logErr('[GeoIP] 上报失败:', err.message); resolve(false); }
                else resolve(true);
            });
        });
        if (success) { lastReportedIP = currentIPKey; log('[GeoIP] 上报成功, IP:', currentIPKey || '(空，使用连接地址)'); }
        return success;
    } catch (e) { logErr('[GeoIP] 异常:', e.message); return false; }
}

// NZ-Agent: 终端任务
const TaskType = { TerminalGRPC: 8, FM: 11 };

function handleTerminalTask(task, client, metadata) {
    let terminal;
    try { terminal = JSON.parse(task.data); } catch (e) { logErr('[Terminal] 任务解析错误:', e.message); return; }

    const ioStream = client.IOStream(metadata);
    let streamClosed = false;
    let ptyProcess = null;
    let keepAlive = null;
    activeIOStreams++;

    function cleanup() {
        if (streamClosed) return;
        streamClosed = true;
        activeIOStreams--;
        if (keepAlive) clearInterval(keepAlive);
        try { ioStream.end(); } catch (e) {}
        if (ptyProcess) { try { ptyProcess.kill(); } catch (e) {} }
    }

    ioStream.on('error', (err) => { logErr('[Terminal] IOStream 错误:', err.message); cleanup(); });
    ioStream.on('end', () => { cleanup(); });
    ioStream.on('status', (status) => {
        if (status.code !== 0 && status.code !== grpc.status.OK) { logErr('[Terminal] IOStream 状态异常:', status.code, status.details); cleanup(); }
    });

    const streamIDData = Buffer.concat([Buffer.from([0xff, 0x05, 0xff, 0x05]), Buffer.from(terminal.StreamID || '')]);
    try { ioStream.write({ data: streamIDData }); }
    catch (e) { logErr('[Terminal] 发送 StreamID 失败:', e.message); cleanup(); return; }

    const shell = process.env.SHELL || (process.platform === 'win32' ? 'powershell.exe' : 'bash');
    let ptyModule = null;
    try { ptyModule = require('node-pty'); } catch (e) { }

    if (ptyModule) {
        try {
            ptyProcess = ptyModule.spawn(shell, [], {
                name: 'xterm', cols: 80, rows: 40,
                cwd: process.env.HOME || process.cwd(),
                env: { ...process.env, TERM: 'xterm' },
            });
        } catch (e) { logErr('[Terminal] PTY 启动失败:', e.message); }
    }

    if (!ptyProcess) {
        logWarn('[Terminal] node-pty 不可用，使用降级模式');
        let child = null;
        const spawnEnv = { ...process.env, TERM: 'xterm' };
        const spawnCwd = process.env.HOME || process.cwd();

        if (process.platform !== 'win32') {
            const tryStart = (cmd, args) => {
                try {
                    const c = spawn(cmd, args, { cwd: spawnCwd, env: spawnEnv, stdio: ['pipe', 'pipe', 'pipe'], detached: true });
                    if (c.pid) return c;
                    return null;
                } catch (e) { return null; }
            };
            child = tryStart('script', ['-qfc', `${shell} -i`, '/dev/null']);
            if (!child) {
                log('[Terminal] script 不可用，尝试 python3 pty');
                child = tryStart('python3', ['-c', 'import pty,os,sys;pty.spawn([os.environ.get("SHELL","/bin/bash"),"-i"])']);
            }
            if (!child) {
                child = tryStart('python', ['-c', 'import pty,os,sys;pty.spawn([os.environ.get("SHELL","/bin/bash"),"-i"])']);
            }
            if (!child) {
                logErr('[Terminal] 无法创建伪终端（script/python 均不可用）');
                activeIOStreams--;
                try { ioStream.end(); } catch (e) {}
                return;
            }
        } else {
            child = spawn(shell, [], { cwd: spawnCwd, env: spawnEnv, stdio: ['pipe', 'pipe', 'pipe'], shell: true });
        }

        child.on('error', (err) => { logErr('[Terminal] 子进程启动失败:', err.message); });

        ptyProcess = {
            write: (data) => { try { child.stdin.write(data); } catch (e) {} },
            onData: (cb) => { child.stdout.on('data', cb); child.stderr.on('data', cb); },
            resize: () => {},
            kill: () => {
                try {
                    if (process.platform !== 'win32' && child.pid) { try { process.kill(-child.pid, 'SIGKILL'); } catch (e) {} }
                    child.kill('SIGKILL');
                } catch (e) {}
            },
            onExit: (cb) => {
                child.on('exit', (code) => cb({ exitCode: code || 0 }));
                child.on('error', (err) => { logErr('[Terminal] 子进程错误:', err.message); cb({ exitCode: -1 }); });
            },
        };
    }

    log('[Terminal] 初始化, StreamID:', terminal.StreamID);

    ptyProcess.onData((data) => {
        if (streamClosed) return;
        try { ioStream.write({ data: Buffer.from(data) }); } catch (e) { }
    });

    ioStream.on('data', (msg) => {
        const data = Buffer.from(msg.data || []);
        if (data.length === 0) return;
        switch (data[0]) {
            case 0: try { ptyProcess.write(data.slice(1)); } catch (e) {} break;
            case 1: try { const resize = JSON.parse(data.slice(1).toString()); if (ptyProcess.resize) ptyProcess.resize(resize.Cols || 80, resize.Rows || 40); } catch (e) {} break;
        }
    });

    keepAlive = setInterval(() => {
        if (streamClosed) return;
        try { ioStream.write({ data: Buffer.alloc(0) }); } catch (e) {}
    }, 30000);

    ptyProcess.onExit((e) => { log('[Terminal] 退出, StreamID:', terminal.StreamID, 'code:', e.exitCode); cleanup(); });
}

// NZ-Agent: SFTP
const FM_NZFN = Buffer.from([0x4E, 0x5A, 0x46, 0x4E]);
const FM_NZTD = Buffer.from([0x4E, 0x5A, 0x54, 0x44]);
const FM_NERR = Buffer.from([0x4E, 0x45, 0x52, 0x52]);
const FM_NZUP = Buffer.from([0x4E, 0x5A, 0x55, 0x50]);

function handleFMTask(task, client, metadata) {
    let fmTask;
    try { fmTask = JSON.parse(task.data); } catch (e) { logErr('[FM] 任务解析错误:', e.message); return; }

    const ioStream = client.IOStream(metadata);
    let streamClosed = false;
    let uploadState = null;
    activeIOStreams++;

    const streamIDData = Buffer.concat([Buffer.from([0xff, 0x05, 0xff, 0x05]), Buffer.from(fmTask.StreamID || '')]);
    try { ioStream.write({ data: streamIDData }); }
    catch (e) { logErr('[FM] 发送 StreamID 失败:', e.message); activeIOStreams--; return; }

    log('[FM] 初始化, StreamID:', fmTask.StreamID);

    const keepAlive = setInterval(() => {
        if (streamClosed) return;
        try { ioStream.write({ data: Buffer.alloc(0) }); } catch (e) {}
    }, 30000);

    function sendError(msg) {
        if (streamClosed) return;
        try { ioStream.write({ data: Buffer.concat([FM_NERR, Buffer.from(msg)]) }); } catch (e) {}
    }

    function listDir(dir) {
        try {
            const entries = fs.readdirSync(dir, { withFileTypes: true });
            const parts = [];
            const pathBuf = Buffer.from(dir);
            const pathLen = Buffer.alloc(4);
            pathLen.writeUInt32BE(pathBuf.length, 0);
            parts.push(FM_NZFN, pathLen, pathBuf);
            for (const entry of entries) {
                const isDir = entry.isDirectory() ? 1 : 0;
                const nameBuf = Buffer.from(entry.name);
                parts.push(Buffer.from([isDir, nameBuf.length & 0xFF]), nameBuf);
            }
            ioStream.write({ data: Buffer.concat(parts) });
        } catch (err) {
            const homeDir = os.homedir() + path.sep;
            if (dir !== homeDir) listDir(homeDir);
            else sendError(err.message);
        }
    }

    function downloadFile(filePath) {
        try {
            const stat = fs.statSync(filePath);
            if (stat.size <= 0) { sendError('requested file is empty'); return; }
            const sizeBuf = Buffer.alloc(8);
            sizeBuf.writeBigUInt64BE(BigInt(stat.size), 0);
            ioStream.write({ data: Buffer.concat([FM_NZTD, sizeBuf]) });
            const stream = fs.createReadStream(filePath, { highWaterMark: 1024 * 1024 });
            stream.on('data', (chunk) => {
                if (streamClosed) { stream.destroy(); return; }
                ioStream.write({ data: chunk });
            });
            stream.on('error', (err) => sendError(err.message));
        } catch (err) { sendError(err.message); }
    }

    function startUpload(data) {
        if (data.length < 8) { sendError('data is invalid'); return; }
        const fileSize = Number(data.readBigUInt64BE(0));
        const filePath = data.slice(8).toString();
        try {
            const dir = path.dirname(filePath);
            if (dir && !fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
            const writeStream = fs.createWriteStream(filePath);
            uploadState = { writeStream, fileSize, received: 0, finished: false };
            writeStream.on('error', (err) => { if (uploadState) { sendError(err.message); uploadState = null; } });
            writeStream.on('finish', () => {
                if (uploadState && !uploadState.finished) {
                    uploadState.finished = true;
                    log('[FM] 文件接收完成');
                    ioStream.write({ data: FM_NZUP });
                    uploadState = null;
                }
            });
            log('[FM] 接收文件:', filePath, '大小:', fileSize);
        } catch (err) { sendError(err.message); }
    }

    ioStream.on('data', (msg) => {
        const data = Buffer.from(msg.data || []);
        if (data.length === 0) return;
        if (uploadState) {
            const ok = uploadState.writeStream.write(data);
            uploadState.received += data.length;
            if (!ok) uploadState.writeStream.once('drain', () => {});
            if (uploadState.received >= uploadState.fileSize) uploadState.writeStream.end();
            return;
        }
        switch (data[0]) {
            case 0: listDir(data.slice(1).toString()); break;
            case 1: downloadFile(data.slice(1).toString()); break;
            case 2: startUpload(data.slice(1)); break;
        }
    });

    const cleanup = () => {
        clearInterval(keepAlive);
        if (!streamClosed) {
            streamClosed = true;
            activeIOStreams--;
            if (uploadState) { try { uploadState.writeStream.destroy(); } catch (e) {} uploadState = null; }
        }
    };
    ioStream.on('error', (err) => { logErr('[FM] IOStream 错误:', err.message); cleanup(); });
    ioStream.on('end', () => { log('[FM] IOStream 结束, StreamID:', fmTask.StreamID); cleanup(); });
}

// NZ-Agent: 任务分发 
function dispatchTask(task, taskStream, client, metadata) {
    switch (task.type) {
        case TaskType.TerminalGRPC: handleTerminalTask(task, client, metadata); break;
        case TaskType.FM: handleFMTask(task, client, metadata); break;
    }
}

// NZ-Agent: 辅助函数
function sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }

function callWithTimeout(fn, timeoutMs) {
    return new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('timeout')), timeoutMs);
        fn((err, resp) => { clearTimeout(timer); if (err) reject(err); else resolve(resp); });
    });
}

// NZ-Agent: 主循环
async function startNezhaAgent() {
    if (!NEZHA_SERVER || !NEZHA_KEY) {
        console.log('[Nezha] NEZHA_SERVER 或 NEZHA_KEY 未配置，跳过哪吒 agent');
        return;
    }

    log('[Nezha] 服务器:', NEZHA_SERVER);
    log('[Nezha] TLS:', shouldUseTLS(NEZHA_SERVER) ? '启用' : '禁用');
    log('[Nezha] UUID:', UUID);

    const proto = loadProto();
    const useTLS = shouldUseTLS(NEZHA_SERVER);
    const credentials = useTLS ? grpc.credentials.createSsl() : grpc.credentials.createInsecure();
    const metadata = buildMetadata();

    let lastReportHostInfo = 0;
    let lastReportIPInfo = 0;
    let geoipReported = false;
    let prevDashboardBootTime = 0;

    while (true) {
        let client = null;
        let taskStream = null;
        let stateStream = null;
        let workerCancelled = false;

        try {
            client = new proto.NezhaService(NEZHA_SERVER, credentials);
            console.log('nzbot is running...');

            const hostInfo = await getHost();
            let dashboardBootTime = 0;
            try {
                const receipt = await callWithTimeout(
                    (cb) => client.ReportSystemInfo2(hostInfo, metadata, cb), NETWORK_TIMEOUT
                );
                dashboardBootTime = receipt.data || 0;
                log('[Agent] 上报系统信息成功, Dashboard BootTime:', dashboardBootTime);
            } catch (err) {
                logErr('[Agent] 上报系统信息失败:', err.message);
                throw err;
            }

            geoipReported = false;
            prevDashboardBootTime = dashboardBootTime;

            try {
                const success = await reportGeoIP(client, metadata, true);
                if (success) { lastReportIPInfo = Date.now(); geoipReported = true; }
            } catch (e) { logErr('[GeoIP] 首次上报异常:', e.message); }

            taskStream = client.RequestTask(metadata);
            log('[Agent] RequestTask strem connect');

            stateStream = client.ReportSystemState(metadata);
            log('[Agent] ReportSystemState strem connect');

            taskStream.on('data', (task) => { dispatchTask(task, taskStream, client, metadata); });
            taskStream.on('error', (err) => { logErr('[Agent] RequestTask strem error:', err.message); workerCancelled = true; });
            taskStream.on('end', () => { log('[Agent] RequestTask strem finished'); workerCancelled = true; });

            const stateLoop = (async () => {
                while (!workerCancelled) {
                    try {
                        await trackNetworkSpeed();
                        const state = await getState();
                        await new Promise((resolve, reject) => {
                            stateStream.write(state, (err) => { if (err) reject(err); else resolve(); });
                        });
                        await new Promise((resolve, reject) => {
                            const timer = setTimeout(() => {
                                stateStream.removeListener('data', onReceipt);
                                stateStream.removeListener('error', onError);
                                reject(new Error('receipt timeout'));
                            }, NETWORK_TIMEOUT);
                            const onReceipt = (msg) => { clearTimeout(timer); stateStream.removeListener('error', onError); resolve(msg); };
                            const onError = (err) => { clearTimeout(timer); stateStream.removeListener('data', onReceipt); reject(err); };
                            stateStream.once('data', onReceipt);
                            stateStream.once('error', onError);
                        });
                        const now = Date.now();
                        if (now - lastReportHostInfo > 10 * 60 * 1000) {
                            try {
                                const hostRefresh = await getHost();
                                await callWithTimeout((cb) => client.ReportSystemInfo2(hostRefresh, metadata, cb), 10000);
                                lastReportHostInfo = now;
                            } catch (e) { }
                        }
                        if (now - lastReportIPInfo > IP_REPORT_PERIOD * 1000 || !geoipReported) {
                            const forceUpdate = !geoipReported;
                            const success = await reportGeoIP(client, metadata, forceUpdate);
                            if (success) { lastReportIPInfo = now; geoipReported = true; }
                        }
                    } catch (err) {
                        logErr('[Agent] error:', err.message);
                        workerCancelled = true;
                        break;
                    }
                    await sleep(REPORT_DELAY * 1000);
                }
            })();

            await stateLoop;

        } catch (err) {
            logErr('[Agent] connect error:', err.message);
        } finally {
            if (activeIOStreams > 0) {
                log(`[Agent] 等待 ${activeIOStreams} 个活跃 IOStream 会话结束...`);
                const waitStart = Date.now();
                while (activeIOStreams > 0 && Date.now() - waitStart < 5000) await sleep(100);
                if (activeIOStreams > 0) logWarn(`[Agent] 仍有 ${activeIOStreams} 个 IOStream 会话未结束，强制关闭`);
            }
            try { if (taskStream) taskStream.end(); } catch (e) {}
            try { if (stateStream) stateStream.end(); } catch (e) {}
            try { if (client) client.close(); } catch (e) {}
        }

        log('[Agent] retry connect...');
        await sleep(RETRY_DELAY);
    }
}

// start service
httpServer.listen(PORT, () => {
  startNezhaAgent().catch(err => console.error('error', err));
  addAccessTask();
  console.log(`Server is running on ${PORT}`);
});
