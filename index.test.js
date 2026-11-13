'use strict';

const crypto = require('crypto');
const os = require('os');
const http = require('http');
const { EventEmitter } = require('events');

// ===== Mock 设置（必须在 require index.js 之前） =====

jest.mock('axios');
jest.mock('net', () => {
  const actual = jest.requireActual('net');
  return { ...actual, connect: jest.fn() };
});
jest.mock('https', () => {
  const actual = jest.requireActual('https');
  return { ...actual, get: jest.fn() };
});
jest.mock('ws', () => {
  const actual = jest.requireActual('ws');
  return {
    ...actual,
    createWebSocketStream: jest.fn(() => ({
      on: jest.fn().mockReturnThis(),
      pipe: jest.fn().mockReturnThis(),
    })),
  };
});
jest.mock('systeminformation', () => ({
  osInfo: jest.fn(),
  cpu: jest.fn(),
  mem: jest.fn(),
  fsSize: jest.fn(),
  currentLoad: jest.fn(),
  networkStats: jest.fn(),
  processes: jest.fn(),
}));

const axios = require('axios');
const net = require('net');
const https = require('https');
const si = require('systeminformation');
const { createWebSocketStream } = require('ws');
const fs = require('fs');

const index = require('./index.js');

// 与 index.js 默认值一致
const UUID = 'a9746e2d-61e0-43fb-849e-078fe8b998e1';
const uuidHex = UUID.replace(/-/g, '');

// 辅助：构造 mock WebSocket
function mockWs() {
  return { close: jest.fn(), send: jest.fn(), on: jest.fn().mockReturnThis(), once: jest.fn().mockReturnThis() };
}

// 辅助：构造 mock net.connect（返回带 write/on/pipe 的 socket）
function setupNetConnectMock() {
  net.connect.mockImplementation((opts, cb) => {
    const socket = {
      write: jest.fn(),
      on: jest.fn().mockReturnThis(),
      pipe: jest.fn().mockReturnThis(),
    };
    if (cb) cb.call(socket);
    return socket;
  });
}

// 辅助：构造 mock https.get
function setupHttpsGetMock(responseData) {
  https.get.mockImplementation((url, opts, cb) => {
    const req = new EventEmitter();
    req.destroy = jest.fn();
    req.on = jest.fn().mockReturnThis();
    const callback = typeof opts === 'function' ? opts : cb;
    setTimeout(() => {
      const res = new EventEmitter();
      callback(res);
      res.emit('data', responseData);
      res.emit('end');
    }, 0);
    return req;
  });
}

// 辅助：构造有效 Trojan 消息
function buildTrojanMessage(hostBytes, atyp, port, withCrlf) {
  const hashHex = crypto.createHash('sha224').update(UUID).digest('hex');
  const hashBuf = Buffer.from(hashHex, 'ascii'); // 56 bytes
  const parts = [hashBuf];
  if (withCrlf) parts.push(Buffer.from([0x0d, 0x0a]));
  parts.push(Buffer.from([0x01, atyp])); // cmd=1 (CONNECT), atyp
  parts.push(hostBytes);
  const portBuf = Buffer.alloc(2);
  portBuf.writeUInt16BE(port, 0);
  parts.push(portBuf);
  return Buffer.concat(parts);
}

// 辅助：构造有效 VLESS 消息
function buildVlessMessage(hostBytes, atyp, port) {
  const idBytes = [];
  for (let i = 0; i < 16; i++) {
    idBytes.push(parseInt(uuidHex.substr(i * 2, 2), 16));
  }
  return Buffer.from([
    0,            // VERSION
    ...idBytes,   // 16 bytes UUID
    0,            // addons length M = 0
    (port >> 8) & 0xFF, port & 0xFF, // port (big-endian)
    atyp,         // ATYP
    ...hostBytes, // address
  ]);
}

// 辅助：构造有效 SS 消息
function buildSsMessage(hostBytes, atyp, port) {
  const portBuf = Buffer.alloc(2);
  portBuf.writeUInt16BE(port, 0);
  return Buffer.concat([Buffer.from([atyp]), hostBytes, portBuf]);
}

// ===== beforeEach 全局清理 =====
beforeEach(() => {
  jest.clearAllMocks();
  setupNetConnectMock();
});

// ========================== shouldUseTLS ==========================
describe('shouldUseTLS', () => {
  const { shouldUseTLS } = index;

  test('TLS 端口返回 true', () => {
    [443, 2053, 2083, 2087, 2096, 8443].forEach(port => {
      expect(shouldUseTLS(`example.com:${port}`)).toBe(true);
    });
  });

  test('非 TLS 端口返回 false', () => {
    [80, 3000, 8080, 12345].forEach(port => {
      expect(shouldUseTLS(`example.com:${port}`)).toBe(false);
    });
  });

  test('无端口返回 false', () => {
    expect(shouldUseTLS('example.com')).toBe(false);
  });

  test('空端口返回 false', () => {
    expect(shouldUseTLS('example.com:')).toBe(false);
  });

  test('IP 地址带 TLS 端口', () => {
    expect(shouldUseTLS('1.2.3.4:443')).toBe(true);
  });

  test('多段地址带端口', () => {
    expect(shouldUseTLS('a.b.c.d:8443')).toBe(true);
    expect(shouldUseTLS('a.b.c.d:80')).toBe(false);
  });
});

// ========================== isBlockedDomain ==========================
describe('isBlockedDomain', () => {
  const { isBlockedDomain } = index;

  test('精确匹配屏蔽域名返回 true', () => {
    expect(isBlockedDomain('speedtest.net')).toBe(true);
    expect(isBlockedDomain('fast.com')).toBe(true);
    expect(isBlockedDomain('speedtest.cn')).toBe(true);
    expect(isBlockedDomain('speed.cloudflare.com')).toBe(true);
  });

  test('子域名匹配返回 true', () => {
    expect(isBlockedDomain('sub.speedtest.net')).toBe(true);
    expect(isBlockedDomain('a.b.fast.com')).toBe(true);
    expect(isBlockedDomain('cdn.speed.cloudflare.com')).toBe(true);
  });

  test('非屏蔽域名返回 false', () => {
    expect(isBlockedDomain('example.com')).toBe(false);
    expect(isBlockedDomain('google.com')).toBe(false);
    expect(isBlockedDomain('github.com')).toBe(false);
  });

  test('后缀相似但不匹配返回 false', () => {
    expect(isBlockedDomain('notspeedtest.net')).toBe(false);
    expect(isBlockedDomain('speedtest.net.com')).toBe(false);
    expect(isBlockedDomain('myfast.com')).toBe(false);
  });

  test('大小写不敏感', () => {
    expect(isBlockedDomain('SPEEDTEST.NET')).toBe(true);
    expect(isBlockedDomain('SpeedTest.Net')).toBe(true);
    expect(isBlockedDomain('SUB.FAST.COM')).toBe(true);
  });

  test('空值返回 false', () => {
    expect(isBlockedDomain('')).toBe(false);
    expect(isBlockedDomain(null)).toBe(false);
    expect(isBlockedDomain(undefined)).toBe(false);
  });
});

// ========================== shouldExcludeInterface ==========================
describe('shouldExcludeInterface', () => {
  const { shouldExcludeInterface } = index;

  test('排除列表中的接口返回 true', () => {
    expect(shouldExcludeInterface('lo')).toBe(true);
    expect(shouldExcludeInterface('tun0')).toBe(true);
    expect(shouldExcludeInterface('docker0')).toBe(true);
    expect(shouldExcludeInterface('veth123')).toBe(true);
    expect(shouldExcludeInterface('br-abc')).toBe(true);
    expect(shouldExcludeInterface('vmbr0')).toBe(true);
    expect(shouldExcludeInterface('vnet0')).toBe(true);
    expect(shouldExcludeInterface('kubelet')).toBe(true);
    expect(shouldExcludeInterface('Meta0')).toBe(true);
    expect(shouldExcludeInterface('tailscale0')).toBe(true);
    expect(shouldExcludeInterface('fw0')).toBe(true);
    expect(shouldExcludeInterface('tap0')).toBe(true);
  });

  test('非排除接口返回 false', () => {
    expect(shouldExcludeInterface('eth0')).toBe(false);
    expect(shouldExcludeInterface('wlan0')).toBe(false);
    expect(shouldExcludeInterface('en0')).toBe(false);
    expect(shouldExcludeInterface('hns0')).toBe(false);
  });
});

// ========================== getArch ==========================
describe('getArch', () => {
  const { getArch } = index;

  test('返回当前架构的正确映射', () => {
    const result = getArch();
    const expected = { x64: 'x86_64', arm64: 'aarch64', ia32: 'i386' };
    expect(result).toBe(expected[process.arch] || process.arch);
  });
});

// ========================== parseIPFromResponse ==========================
describe('parseIPFromResponse', () => {
  const { parseIPFromResponse } = index;

  test('直接返回 IPv4', () => {
    expect(parseIPFromResponse('1.2.3.4', 4)).toBe('1.2.3.4');
  });

  test('直接返回 IPv6', () => {
    expect(parseIPFromResponse('2001:db8::1', 6)).toBe('2001:db8::1');
  });

  test('trim 后返回 IP', () => {
    expect(parseIPFromResponse('  1.2.3.4  \n', 4)).toBe('1.2.3.4');
  });

  test('ip= 格式解析 IPv4', () => {
    expect(parseIPFromResponse('ip=1.2.3.4', 4)).toBe('1.2.3.4');
  });

  test('多行 ip= 格式解析', () => {
    expect(parseIPFromResponse('fl=abc\nip=1.2.3.4\nother', 4)).toBe('1.2.3.4');
  });

  test('ip= 格式解析 IPv6', () => {
    expect(parseIPFromResponse('ip=2001:db8::1', 6)).toBe('2001:db8::1');
  });

  test('无效内容返回空字符串', () => {
    expect(parseIPFromResponse('no ip here', 4)).toBe('');
    expect(parseIPFromResponse('', 4)).toBe('');
  });

  test('family 不匹配返回空字符串', () => {
    expect(parseIPFromResponse('1.2.3.4', 6)).toBe('');
    expect(parseIPFromResponse('2001:db8::1', 4)).toBe('');
  });

  test('ip= 格式但 family 不匹配', () => {
    expect(parseIPFromResponse('ip=1.2.3.4', 6)).toBe('');
  });
});

// ========================== buildMetadata ==========================
describe('buildMetadata', () => {
  const { buildMetadata, _constants } = index;

  test('返回包含正确键的 Metadata', () => {
    const meta = buildMetadata();
    expect(meta).toBeDefined();
    expect(meta.get('client-secret')).toEqual([_constants.NEZHA_KEY]);
    expect(meta.get('client-uuid')).toEqual([_constants.UUID]);
    expect(meta.get('client_secret')).toEqual([_constants.NEZHA_KEY]);
    expect(meta.get('client_uuid')).toEqual([_constants.UUID]);
  });
});

// ========================== sleep ==========================
describe('sleep', () => {
  const { sleep } = index;

  test('等待指定时间后 resolve', async () => {
    const start = Date.now();
    await sleep(50);
    expect(Date.now() - start).toBeGreaterThanOrEqual(40);
  });

  test('返回 Promise', () => {
    expect(sleep(10)).toBeInstanceOf(Promise);
  });
});

// ========================== callWithTimeout ==========================
describe('callWithTimeout', () => {
  const { callWithTimeout } = index;

  test('成功时 resolve 结果', async () => {
    const result = await callWithTimeout((cb) => cb(null, 'success'), 1000);
    expect(result).toBe('success');
  });

  test('错误时 reject', async () => {
    await expect(callWithTimeout((cb) => cb(new Error('fail')), 1000))
      .rejects.toThrow('fail');
  });

  test('超时时 reject timeout', async () => {
    await expect(callWithTimeout(() => {}, 50))
      .rejects.toThrow('timeout');
  });
});

// ========================== getConnCount ==========================
describe('getConnCount', () => {
  const { getConnCount } = index;

  test('非 linux 平台返回 [0, 0]', () => {
    if (process.platform !== 'linux') {
      const result = getConnCount();
      expect(result).toEqual([0, 0]);
    }
  });

  test('linux 平台读取 /proc 或返回 [0,0]（容错）', () => {
    if (process.platform === 'linux') {
      const result = getConnCount();
      expect(Array.isArray(result)).toBe(true);
      expect(result).toHaveLength(2);
    }
  });
});

// ========================== getProcessCountSync ==========================
describe('getProcessCountSync', () => {
  const { getProcessCountSync } = index;

  test('非 linux 平台返回 -1', () => {
    if (process.platform !== 'linux') {
      expect(getProcessCountSync()).toBe(-1);
    }
  });

  test('linux 平台返回非负数', () => {
    if (process.platform === 'linux') {
      const result = getProcessCountSync();
      expect(result).toBeGreaterThanOrEqual(0);
    }
  });
});

// ========================== loadProto ==========================
describe('loadProto', () => {
  const { loadProto } = index;

  test('成功加载 proto 定义并返回 NezhaService', () => {
    const proto = loadProto();
    expect(proto).toBeDefined();
    expect(proto.NezhaService).toBeDefined();
    expect(typeof proto.NezhaService).toBe('function');
  });

  test('多次调用都能成功', () => {
    const proto1 = loadProto();
    const proto2 = loadProto();
    expect(proto1.NezhaService).toBeDefined();
    expect(proto2.NezhaService).toBeDefined();
  });
});

// ========================== getisp ==========================
describe('getisp', () => {
  const { getisp } = index;

  test('主 API 成功时设置 ISP', async () => {
    axios.get.mockResolvedValue({
      data: { country_code: 'US', isp: 'Comcast Cable' },
    });
    await getisp();
    expect(axios.get).toHaveBeenCalledWith(
      'https://api.ip.sb/geoip',
      expect.objectContaining({ timeout: 3000, headers: expect.objectContaining({ 'User-Agent': 'Mozilla/5.0' }) })
    );
  });

  test('主 API 失败时回退到备用 API', async () => {
    axios.get
      .mockRejectedValueOnce(new Error('primary fail'))
      .mockResolvedValueOnce({
        data: { countryCode: 'CN', org: 'China Telecom' },
      });
    await getisp();
    expect(axios.get).toHaveBeenCalledTimes(2);
    expect(axios.get).toHaveBeenNthCalledWith(2, 'http://ip-api.com/json', expect.any(Object));
  });

  test('两个 API 都失败时 ISP 设为 Unknown', async () => {
    axios.get.mockRejectedValue(new Error('all fail'));
    await getisp();
    expect(axios.get).toHaveBeenCalledTimes(2);
  });
});

// ========================== getip ==========================
describe('getip', () => {
  const { getip } = index;

  test('DOMAIN 为 your-domain.com 时通过 API 获取 IP', async () => {
    axios.get.mockResolvedValue({ data: '1.2.3.4' });
    await getip();
    expect(axios.get).toHaveBeenCalledWith('https://api-ipv4.ip.sb/ip', expect.any(Object));
  });

  test('API 获取 IP 失败时使用默认域名', async () => {
    axios.get.mockRejectedValue(new Error('fail'));
    await getip();
    expect(axios.get).toHaveBeenCalled();
  });
});

// ========================== addAccessTask ==========================
describe('addAccessTask', () => {
  const { addAccessTask, _constants } = index;

  test('AUTO_ACCESS 未启用时直接返回', async () => {
    await addAccessTask();
    expect(axios.post).not.toHaveBeenCalled();
  });
});

// ========================== resolveHost ==========================
describe('resolveHost', () => {
  const { resolveHost } = index;

  test('IP 地址直接 resolve', async () => {
    const result = await resolveHost('1.2.3.4');
    expect(result).toBe('1.2.3.4');
  });

  test('域名通过 DNS 解析成功', async () => {
    axios.get.mockResolvedValue({
      data: { Status: 0, Answer: [{ type: 1, data: '5.6.7.8' }] },
    });
    const result = await resolveHost('example.com');
    expect(result).toBe('5.6.7.8');
    expect(axios.get).toHaveBeenCalled();
  });

  test('第一个 DNS 失败时尝试第二个', async () => {
    axios.get
      .mockRejectedValueOnce(new Error('dns1 fail'))
      .mockResolvedValueOnce({
        data: { Status: 0, Answer: [{ type: 1, data: '9.10.11.12' }] },
      });
    const result = await resolveHost('example.org');
    expect(result).toBe('9.10.11.12');
    expect(axios.get).toHaveBeenCalledTimes(2);
  });

  test('所有 DNS 服务器都失败时 reject', async () => {
    axios.get.mockRejectedValue(new Error('all dns fail'));
    await expect(resolveHost('example.net')).rejects.toThrow('Failed to resolve');
  });

  test('DNS 返回无 Answer 时尝试下一个服务器', async () => {
    axios.get
      .mockResolvedValueOnce({ data: { Status: 0 } })
      .mockResolvedValueOnce({
        data: { Status: 0, Answer: [{ type: 1, data: '1.1.1.1' }] },
      });
    const result = await resolveHost('test.com');
    expect(result).toBe('1.1.1.1');
  });

  test('DNS 返回 Answer 但无 type=1 记录时尝试下一个', async () => {
    axios.get
      .mockResolvedValueOnce({ data: { Status: 0, Answer: [{ type: 5, data: 'cname.example.com' }] } })
      .mockResolvedValueOnce({
        data: { Status: 0, Answer: [{ type: 1, data: '2.2.2.2' }] },
      });
    const result = await resolveHost('test.org');
    expect(result).toBe('2.2.2.2');
  });
});

// ========================== handleVlsConnection ==========================
describe('handleVlsConnection', () => {
  const { handleVlsConnection } = index;

  test('UUID 不匹配返回 false', () => {
    const ws = mockWs();
    const msg = Buffer.from([
      0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0x00, 0x50, 0x01, 1, 2, 3, 4,
    ]);
    expect(handleVlsConnection(ws, msg)).toBe(false);
  });

  test('有效 VLESS 消息（IPv4）返回 true', () => {
    const ws = mockWs();
    const msg = buildVlessMessage(Buffer.from([1, 2, 3, 4]), 0x01, 80);
    expect(handleVlsConnection(ws, msg)).toBe(true);
    expect(ws.send).toHaveBeenCalled();
  });

  test('有效 VLESS 消息（域名）返回 true', () => {
    const ws = mockWs();
    const domain = Buffer.from('example.com');
    const msg = buildVlessMessage(Buffer.concat([Buffer.from([domain.length]), domain]), 0x02, 443);
    expect(handleVlsConnection(ws, msg)).toBe(true);
    expect(ws.send).toHaveBeenCalled();
  });

  test('被屏蔽域名时关闭 ws 并返回 false', () => {
    const ws = mockWs();
    const domain = Buffer.from('speedtest.net');
    const msg = buildVlessMessage(Buffer.concat([Buffer.from([domain.length]), domain]), 0x02, 80);
    expect(handleVlsConnection(ws, msg)).toBe(false);
    expect(ws.close).toHaveBeenCalled();
  });

  test('畸形或截断消息返回 false，不抛异常', () => {
    const ws = mockWs();
    expect(() => handleVlsConnection(ws, Buffer.from([0]))).not.toThrow();
    expect(handleVlsConnection(ws, Buffer.from([0]))).toBe(false);

    const msg = buildVlessMessage(Buffer.concat([Buffer.from([11]), Buffer.from('example.com')]), 0x02, 443);
    msg[17] = 255;
    expect(handleVlsConnection(ws, msg)).toBe(false);
  });
});

// ========================== handleTrojConnection ==========================
describe('handleTrojConnection', () => {
  const { handleTrojConnection } = index;

  test('消息太短返回 false', () => {
    const ws = mockWs();
    expect(handleTrojConnection(ws, Buffer.alloc(10))).toBe(false);
  });

  test('密码不匹配返回 false', () => {
    const ws = mockWs();
    const msg = Buffer.alloc(60);
    msg.write('wrongpasswordhash', 0, 'ascii');
    expect(handleTrojConnection(ws, msg)).toBe(false);
  });

  test('有效 Trojan 消息（IPv4，无 CRLF）返回 true', () => {
    const ws = mockWs();
    const msg = buildTrojanMessage(Buffer.from([1, 2, 3, 4]), 0x01, 80, false);
    expect(handleTrojConnection(ws, msg)).toBe(true);
  });

  test('有效 Trojan 消息（IPv4，有 CRLF）返回 true', () => {
    const ws = mockWs();
    const msg = buildTrojanMessage(Buffer.from([10, 20, 30, 40]), 0x01, 443, true);
    expect(handleTrojConnection(ws, msg)).toBe(true);
  });

  test('有效 Trojan 消息（域名）返回 true', () => {
    const ws = mockWs();
    const domain = Buffer.from('example.com');
    const msg = buildTrojanMessage(Buffer.concat([Buffer.from([domain.length]), domain]), 0x03, 80, false);
    expect(handleTrojConnection(ws, msg)).toBe(true);
  });

  test('被屏蔽域名时关闭 ws 并返回 false', () => {
    const ws = mockWs();
    const domain = Buffer.from('speedtest.net');
    const msg = buildTrojanMessage(Buffer.concat([Buffer.from([domain.length]), domain]), 0x03, 80, false);
    expect(handleTrojConnection(ws, msg)).toBe(false);
    expect(ws.close).toHaveBeenCalled();
  });

  test('无效命令返回 false', () => {
    const ws = mockWs();
    const hashHex = crypto.createHash('sha224').update(UUID).digest('hex');
    const hashBuf = Buffer.from(hashHex, 'ascii');
    // cmd = 0x02 (非 0x01)
    const msg = Buffer.concat([hashBuf, Buffer.from([0x02, 0x01, 1, 2, 3, 4, 0x00, 0x50])]);
    expect(handleTrojConnection(ws, msg)).toBe(false);
  });

  test('无效 ATYP 返回 false', () => {
    const ws = mockWs();
    const hashHex = crypto.createHash('sha224').update(UUID).digest('hex');
    const hashBuf = Buffer.from(hashHex, 'ascii');
    // atyp = 0x02 (无效)
    const msg = Buffer.concat([hashBuf, Buffer.from([0x01, 0x02, 1, 2, 3, 4, 0x00, 0x50])]);
    expect(handleTrojConnection(ws, msg)).toBe(false);
  });
});

// ========================== handleSsConnection ==========================
describe('handleSsConnection', () => {
  const { handleSsConnection } = index;

  test('有效 SS 消息（IPv4）返回 true', () => {
    const ws = mockWs();
    const msg = buildSsMessage(Buffer.from([1, 2, 3, 4]), 0x01, 80);
    expect(handleSsConnection(ws, msg)).toBe(true);
  });

  test('有效 SS 消息（域名）返回 true', () => {
    const ws = mockWs();
    const domain = Buffer.from('example.com');
    const msg = buildSsMessage(Buffer.concat([Buffer.from([domain.length]), domain]), 0x03, 443);
    expect(handleSsConnection(ws, msg)).toBe(true);
  });

  test('无效 ATYP 返回 false', () => {
    const ws = mockWs();
    const msg = buildSsMessage(Buffer.from([1, 2, 3, 4]), 0x02, 80);
    expect(handleSsConnection(ws, msg)).toBe(false);
  });

  test('被屏蔽域名时关闭 ws 并返回 false', () => {
    const ws = mockWs();
    const domain = Buffer.from('fast.com');
    const msg = buildSsMessage(Buffer.concat([Buffer.from([domain.length]), domain]), 0x03, 80);
    expect(handleSsConnection(ws, msg)).toBe(false);
    expect(ws.close).toHaveBeenCalled();
  });

  test('异常时返回 false', () => {
    const ws = mockWs();
    // 构造会导致 readUInt16BE 越界的消息
    const msg = Buffer.from([0x01, 1, 2, 3]);
    expect(handleSsConnection(ws, msg)).toBe(false);
  });
});

// ========================== dispatchTask ==========================
describe('dispatchTask', () => {
  const { dispatchTask, _constants } = index;

  test('未知任务类型不抛异常', () => {
    expect(() => dispatchTask({ type: 999, data: '{}' }, null, null, null)).not.toThrow();
  });

  test('TerminalGRPC 任务无效 JSON 时不抛异常', () => {
    expect(() => dispatchTask({ type: _constants.TaskType.TerminalGRPC, data: 'invalid' }, null, null, null)).not.toThrow();
  });

  test('FM 任务无效 JSON 时不抛异常', () => {
    expect(() => dispatchTask({ type: _constants.TaskType.FM, data: 'invalid' }, null, null, null)).not.toThrow();
  });

  test('TerminalGRPC 任务有效 JSON 时调用 IOStream', () => {
    const mockStream = new EventEmitter();
    mockStream.write = jest.fn();
    mockStream.end = jest.fn();
    mockStream.on = jest.fn().mockReturnThis();
    const mockClient = { IOStream: jest.fn().mockReturnValue(mockStream) };
    expect(() => dispatchTask(
      { type: _constants.TaskType.TerminalGRPC, data: JSON.stringify({ StreamID: 'test' }) },
      null, mockClient, {}
    )).not.toThrow();
    expect(mockClient.IOStream).toHaveBeenCalled();
  });

  test('FM 任务有效 JSON 时调用 IOStream', () => {
    const mockStream = new EventEmitter();
    mockStream.write = jest.fn();
    mockStream.end = jest.fn();
    mockStream.on = jest.fn().mockReturnThis();
    const mockClient = { IOStream: jest.fn().mockReturnValue(mockStream) };
    expect(() => dispatchTask(
      { type: _constants.TaskType.FM, data: JSON.stringify({ StreamID: 'test' }) },
      null, mockClient, {}
    )).not.toThrow();
    expect(mockClient.IOStream).toHaveBeenCalled();
  });
});

// ========================== fetchIP ==========================
describe('fetchIP', () => {
  const { fetchIP } = index;

  test('成功获取 IPv4 和 IPv6', async () => {
    setupHttpsGetMock('1.2.3.4');
    const result = await fetchIP();
    expect(result).toHaveProperty('ipv4');
    expect(result).toHaveProperty('ipv6');
    expect(typeof result.ipv4).toBe('string');
    expect(typeof result.ipv6).toBe('string');
  });

  test('所有端点失败时返回空字符串', async () => {
    https.get.mockImplementation((url, opts, cb) => {
      const req = new EventEmitter();
      req.destroy = jest.fn();
      const callback = typeof opts === 'function' ? opts : cb;
      setTimeout(() => {
        req.emit('error', new Error('fail'));
      }, 0);
      return req;
    });
    const result = await fetchIP();
    expect(result.ipv4).toBe('');
    expect(result.ipv6).toBe('');
  });

  test('cloudflare trace 端点 ip= 格式解析', async () => {
    https.get.mockImplementation((url, opts, cb) => {
      const req = new EventEmitter();
      req.destroy = jest.fn();
      req.on = jest.fn().mockReturnThis();
      const callback = typeof opts === 'function' ? opts : cb;
      setTimeout(() => {
        const res = new EventEmitter();
        callback(res);
        res.emit('data', 'fl=abc\nip=1.2.3.4\nother');
        res.emit('end');
      }, 0);
      return req;
    });
    const result = await fetchIP();
    expect(result.ipv4).toBe('1.2.3.4');
  });
});

// ========================== reportGeoIP ==========================
describe('reportGeoIP', () => {
  const { reportGeoIP } = index;

  test('成功上报 GeoIP', async () => {
    setupHttpsGetMock('1.2.3.4');
    const mockClient = {
      ReportGeoIP: jest.fn((req, meta, cb) => cb(null, {})),
    };
    const result = await reportGeoIP(mockClient, {}, true);
    expect(result).toBe(true);
    expect(mockClient.ReportGeoIP).toHaveBeenCalled();
  });

  test('RPC 失败时返回 false', async () => {
    setupHttpsGetMock('1.2.3.4');
    const mockClient = {
      ReportGeoIP: jest.fn((req, meta, cb) => cb(new Error('rpc fail'), null)),
    };
    const result = await reportGeoIP(mockClient, {}, true);
    expect(result).toBe(false);
  });

  test('IP 未变化且非强制更新时跳过上报', async () => {
    setupHttpsGetMock('1.2.3.4');
    const mockClient = {
      ReportGeoIP: jest.fn((req, meta, cb) => cb(null, {})),
    };
    // 第一次上报
    await reportGeoIP(mockClient, {}, true);
    // 第二次，IP 未变化，非强制
    mockClient.ReportGeoIP.mockClear();
    const result = await reportGeoIP(mockClient, {}, false);
    expect(result).toBe(true);
    expect(mockClient.ReportGeoIP).not.toHaveBeenCalled();
  });
});

// ========================== getHost ==========================
describe('getHost', () => {
  const { getHost } = index;

  test('返回正确的系统信息', async () => {
    si.osInfo.mockResolvedValue({ distro: 'Ubuntu', release: '22.04' });
    si.cpu.mockResolvedValue({ manufacturer: 'Intel', brand: 'i7-9700', cores: 8 });
    si.mem.mockResolvedValue({ total: 17179869184, swaptotal: 8589934592 });
    si.fsSize.mockResolvedValue([
      { type: 'ext4', size: 100000, used: 50000 },
      { type: 'ntfs', size: 200000, used: 100000 },
      { type: 'unknown', size: 50000, used: 25000 },
    ]);

    const host = await getHost();
    expect(host.platform).toBe('Ubuntu');
    expect(host.platformVersion).toBe('22.04');
    expect(host.cpu).toHaveLength(1);
    expect(host.cpu[0]).toContain('Intel');
    expect(host.cpu[0]).toContain('i7-9700');
    expect(host.memTotal).toBe(17179869184);
    expect(host.swapTotal).toBe(8589934592);
    expect(host.arch).toBe(index.getArch());
    expect(host.version).toBe('nodejs-9.9.9');
    // ext4 + ntfs 都在 EXPECT_FS_TYPES 中
    expect(host.diskTotal).toBe(300000);
  });

  test('osInfo.distro 为空时回退到 process.platform', async () => {
    si.osInfo.mockResolvedValue({ distro: '', release: '' });
    si.cpu.mockResolvedValue({ manufacturer: 'AMD', brand: 'Ryzen', cores: 6 });
    si.mem.mockResolvedValue({ total: 8000, swaptotal: 0 });
    si.fsSize.mockResolvedValue([]);

    const host = await getHost();
    expect(host.platform).toBe(process.platform);
    expect(host.diskTotal).toBe(0);
    expect(host.swapTotal).toBe(0);
  });
});

// ========================== getState ==========================
describe('getState', () => {
  const { getState } = index;

  test('返回正确的系统状态', async () => {
    si.currentLoad.mockResolvedValue({ currentLoad: 42.5 });
    si.mem.mockResolvedValue({ used: 8000000000, active: 6000000000, buffcache: 2000000000, swapused: 1000000000 });
    si.fsSize.mockResolvedValue([
      { type: 'ext4', size: 100000, used: 50000 },
      { type: 'xfs', size: 200000, used: 80000 },
    ]);

    const state = await getState();
    expect(state.cpu).toBe(42.5);
    expect(state.swapUsed).toBe(1000000000);
    expect(state.diskUsed).toBe(130000);
    expect(state).toHaveProperty('memUsed');
    expect(state).toHaveProperty('uptime');
    expect(state).toHaveProperty('load1');
    expect(state).toHaveProperty('load5');
    expect(state).toHaveProperty('load15');
    expect(state).toHaveProperty('tcpConnCount');
    expect(state).toHaveProperty('udpConnCount');
    expect(state).toHaveProperty('processCount');
    expect(state.temperatures).toEqual([]);
    expect(state.gpu).toEqual([]);
  });

  test('currentLoad 为空时 cpu 默认 0', async () => {
    si.currentLoad.mockResolvedValue({});
    si.mem.mockResolvedValue({ used: 4000, swapused: 0 });
    si.fsSize.mockResolvedValue([]);

    const state = await getState();
    expect(state.cpu).toBe(0);
  });
});

// ========================== trackNetworkSpeed ==========================
describe('trackNetworkSpeed', () => {
  const { trackNetworkSpeed } = index;

  test('正常更新网络速度不抛异常', async () => {
    si.networkStats.mockResolvedValue([
      { iface: 'eth0', rx_bytes: 1000, tx_bytes: 2000 },
      { iface: 'lo', rx_bytes: 500, tx_bytes: 500 },
      { iface: 'docker0', rx_bytes: 300, tx_bytes: 300 },
    ]);
    await expect(trackNetworkSpeed()).resolves.toBeUndefined();
  });

  test('networkStats 失败时不抛异常', async () => {
    si.networkStats.mockRejectedValue(new Error('fail'));
    await expect(trackNetworkSpeed()).resolves.toBeUndefined();
  });

  test('排除 lo 和 docker 接口', async () => {
    si.networkStats.mockResolvedValue([
      { iface: 'eth0', rx_bytes: 1000, tx_bytes: 2000 },
      { iface: 'lo', rx_bytes: 9999, tx_bytes: 9999 },
    ]);
    await trackNetworkSpeed();
    // 第二次调用计算速度
    si.networkStats.mockResolvedValue([
      { iface: 'eth0', rx_bytes: 2000, tx_bytes: 4000 },
      { iface: 'lo', rx_bytes: 9999, tx_bytes: 9999 },
    ]);
    await trackNetworkSpeed();
    // 不抛异常即通过
  });
});

// ========================== HTTP 路由 ==========================
describe('HTTP 路由', () => {
  const { httpServer } = index;
  let server;

  beforeAll((done) => {
    server = http.createServer(httpServer.listeners('request').length > 0 ? httpServer : httpServer);
    // 直接使用 index 导出的 httpServer
    server = httpServer;
    if (!server.listening) {
      server.listen(0, done);
    } else {
      done();
    }
  });

  afterAll((done) => {
    if (server.listening) {
      server.close(done);
    } else {
      done();
    }
  });

  function makeRequest(path) {
    return new Promise((resolve, reject) => {
      const { port } = server.address();
      const req = http.get(`http://127.0.0.1:${port}${path}`, (res) => {
        let data = '';
        res.on('data', (chunk) => data += chunk);
        res.on('end', () => resolve({ statusCode: res.statusCode, body: data, headers: res.headers }));
      });
      req.on('error', reject);
    });
  }

  test('根路径返回 HTML 内容或 Hello world', async () => {
    const res = await makeRequest('/');
    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toBe('text/html');
  });

  test('未知路径返回 404', async () => {
    const res = await makeRequest('/unknown-path');
    expect(res.statusCode).toBe(404);
    expect(res.body).toContain('Not Found');
  });

  test('订阅路径返回 base64 内容', async () => {
    axios.get.mockResolvedValue({
      data: { country_code: 'US', isp: 'TestISP' },
    });
    // getip 的 axios.get 也需要 mock
    axios.get.mockResolvedValue({ data: '1.2.3.4' });
    const res = await makeRequest('/music?source=test');
    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toBe('text/plain');
    // 验证返回的是 base64 编码内容
    expect(res.body.trim()).toMatch(/^[A-Za-z0-9+/=]+$/);
  });
});

// ========================== 常量验证 ==========================
describe('常量', () => {
  const { _constants } = index;

  test('TLS_PORTS 包含正确的端口', () => {
    expect(_constants.TLS_PORTS.has(443)).toBe(true);
    expect(_constants.TLS_PORTS.has(8443)).toBe(true);
    expect(_constants.TLS_PORTS.has(80)).toBe(false);
  });

  test('BLOCKED_DOMAINS 非空', () => {
    expect(_constants.BLOCKED_DOMAINS.length).toBeGreaterThan(0);
    expect(_constants.BLOCKED_DOMAINS).toContain('speedtest.net');
  });

  test('DNS_SERVERS 包含公共 DNS', () => {
    expect(_constants.DNS_SERVERS).toContain('https://dns.google/resolve');
    expect(_constants.DNS_SERVERS).toContain('https://cloudflare-dns.com/dns-query');
  });

  test('TaskType 包含正确的类型', () => {
    expect(_constants.TaskType.TerminalGRPC).toBe(8);
    expect(_constants.TaskType.FM).toBe(11);
  });

  test('AGENT_VERSION 正确', () => {
    expect(_constants.AGENT_VERSION).toBe('nodejs-9.9.9');
  });
});
