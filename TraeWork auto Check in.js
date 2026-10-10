#!/usr/bin/env node
/**
 * 说明：登录态解密与接口路径为逆向自官方客户端的非公开实现，
 * 参考 MIT 开源项目 auphaser/trae-work-checkin-plus（保留版权声明），
 * 可能随客户端版本更新而失效。
 */
"use strict";

const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");

function storageCandidates() {
  const home = os.homedir();
  const roots = [
    path.join(home, "Library", "Application Support"), // macOS
    process.env.APPDATA || path.join(home, "AppData", "Roaming"), // Windows
  ];
  const names = ["Trae CN", "TRAE SOLO CN", "Trae", "TRAE SOLO"];
  const out = [];
  for (const root of roots)
    for (const n of names)
      out.push(path.join(root, n, "User", "globalStorage", "storage.json"));
  return out;
}

function candidateOrder() {
  return storageCandidates()
    .filter((p) => fs.existsSync(p))
    .sort((a, b) => fs.statSync(b).mtimeMs - fs.statSync(a).mtimeMs);
}

const SALT_A = Uint8Array.from([82,9,106,213,48,54,165,56,191,64,163,158,129,243,215,251,124,227,57,130,155,47,255,135,52,142,67,68,196,222,233,203,84,123,148,50,166,194,35,61,238,76,149,11,66,250,195,78,8,46,161,102,40,217,36,178,118,91,162,73,109,139,209,37]);
const SALT_B = Uint8Array.from([31,221,168,51,136,7,199,49,177,18,16,89,39,128,236,95,96,81,127,169,25,181,74,13,45,229,122,159,147,201,156,239,160,224,59,77,174,42,245,176,200,235,187,60,131,83,153,97,23,43,4,126,186,119,214,38,225,105,20,99,85,33,12,125]);

function xorBytes(a, b, n) {
  const r = new Uint8Array(n);
  for (let i = 0; i < n; i++) r[i] = a[i] ^ b[i];
  return r;
}

function decryptAuthValue(b64) {
  const buf = Buffer.from(b64, "base64");
  const hd = buf.subarray(0, 6);
  const rb = buf.subarray(6, 38);
  const enc = buf.subarray(38);
  if (!(hd[0] === 0x74 && hd[1] === 0x63 && hd[2] === 0x05 && hd[3] === 0x10 && hd[4] === 0 && hd[5] === 0)) {
    throw new Error("登录态加密格式不匹配（可能客户端已更新加密方式）");
  }
  const salt = xorBytes(SALT_A, SALT_B, 64);
  const finalHash = crypto
    .createHash("sha512")
    .update(Buffer.concat([crypto.createHash("sha512").update(rb).digest(), Buffer.from(salt)]))
    .digest();
  const dec = crypto.createDecipheriv("aes-128-cbc", finalHash.subarray(0, 16), finalHash.subarray(16, 32));
  const plain = Buffer.concat([dec.update(enc), dec.final()]);
  const stored = plain.subarray(0, 64);
  const payload = plain.subarray(64);
  const computed = crypto.createHash("sha512").update(payload).digest();
  if (!stored.equals(computed)) throw new Error("登录态校验失败（SHA-512 不符）");
  return JSON.parse(payload.toString("utf8"));
}

function loadAuth() {
  for (const p of candidateOrder()) {
    let storage;
    try {
      storage = JSON.parse(fs.readFileSync(p, "utf8"));
    } catch {
      continue;
    }
    const enc = storage["iCubeAuthInfo://icube.cloudide"];
    if (!enc) continue;
    if (String(enc).trim().startsWith("{")) return JSON.parse(enc); // 国际版明文
    return decryptAuthValue(String(enc));
  }
  throw new Error("未找到 Trae 登录态：请先在本机安装并登录 TraeWork/Trae 桌面客户端。");
}

function readDeviceIds() {
  const out = {};
  for (const p of candidateOrder()) {
    let s;
    try {
      s = JSON.parse(fs.readFileSync(p, "utf8"));
    } catch {
      continue;
    }
    if (typeof s["telemetry.machineId"] === "string" && s["telemetry.machineId"]) {
      out.machineId = s["telemetry.machineId"];
    }
    for (const k of Object.keys(s)) {
      const m = /^iCubeAuthInfo:\/\/icube-dc:(\d+)$/.exec(k);
      if (m && m[1]) {
        out.deviceId = m[1];
        break;
      }
    }
    break;
  }
  return out;
}

function readClientVersion() {
  for (const p of candidateOrder()) {
    let s;
    try {
      s = JSON.parse(fs.readFileSync(p, "utf8"));
    } catch {
      continue;
    }
    const v = s["iCubeLastVersion"];
    if (typeof v === "string" && v.trim()) {
      return { ideVersion: v.trim(), ideVersionCode: v.trim().replace(/\./g, "") || v.trim() };
    }
    break;
  }
  return null;
}

function detectOs() {
  const release = os.release();
  if (process.platform === "darwin") return { deviceType: "mac", osVersion: `Darwin ${release}` };
  if (process.platform === "win32") return { deviceType: "windows", osVersion: `Windows ${release}` };
  if (process.platform === "linux") return { deviceType: "linux", osVersion: `Linux ${release}` };
  return { deviceType: "unknown", osVersion: process.platform };
}

function buildHeaders(token, uid, fp) {
  const osInfo = detectOs();
  return {
    "Authorization": `Cloud-IDE-JWT ${token}`,
    "X-Cloudide-Token": token,
    "x-uid": String(uid),
    "x-app-id": "6eefa01c-1036-4c7e-9ca5-d891f63bfcd8",
    "x-device-id": fp.deviceId || crypto.createHash("sha256").update(crypto.randomBytes(32).toString("hex")).digest("hex").substring(0, 32),
    "x-machine-id": fp.machineId || crypto.randomBytes(32).toString("hex"),
    "x-request-id": crypto.randomUUID(),
    "x-ide-version": fp.ideVersion || "3.3.67",
    "x-ide-version-code": fp.ideVersionCode || "20260401",
    "x-device-type": osInfo.deviceType,
    "x-os-version": osInfo.osVersion,
    "Content-Type": "application/json",
    "Accept": "application/json",
  };
}

async function createClient() {
  const auth = loadAuth();
  const host = auth.host || "https://api.trae.cn";
  const uid = String(auth.userId || "");
  const device = readDeviceIds();
  const ver = readClientVersion();
  const fp = {
    deviceId: device.deviceId,
    machineId: device.machineId,
    ideVersion: ver && ver.ideVersion,
    ideVersionCode: ver && ver.ideVersionCode,
  };

  let token = auth.token;
  let refreshing = null;
  async function refresh() {
    if (!auth.refreshToken) return false;
    if (refreshing) return refreshing;
    refreshing = (async () => {
      const r = await fetch(`${host}/cloudide/api/v3/trae/oauth/ExchangeToken`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ClientID: "ono9krqynydwx5",
          RefreshToken: auth.refreshToken,
          ClientSecret: "-",
          UserID: uid,
        }),
      });
      const j = await r.json().catch(() => ({}));
      if (j && j.Result && j.Result.Token) {
        token = j.Result.Token;
        return true;
      }
      return false;
    })();
    try {
      return await refreshing;
    } finally {
      refreshing = null;
    }
  }

  if (!auth.expiredAt || new Date(auth.expiredAt).getTime() - Date.now() < 30 * 60 * 1000) {
    await refresh();
  }

  return {
    async post(apiPath, body) {
      const doFetch = () =>
        fetch(`${host}${apiPath}`, {
          method: "POST",
          headers: buildHeaders(token, uid, fp),
          body: JSON.stringify(body),
        });
      let resp = await doFetch();
      if (resp.status === 401) {
        await refresh();
        resp = await doFetch();
      }
      const json = await resp.json().catch(() => ({}));
      return { status: resp.status, json };
    },
  };
}

// ===== 语言读取 =====
function readLanguage() {
  const candidates = [
    path.join(__dirname, ".log"),
    path.join(process.cwd(), ".log"),
  ];
  for (const p of candidates) {
    try {
      const text = fs.readFileSync(p, "utf8");
      const m = /language\s*=\s*([A-Za-z]+)/i.exec(text);
      if (m) {
        const v = m[1].toLowerCase();
        if (v === "english") return "en";
        if (v === "chinese") return "zh";
      }
    } catch {}
  }
  return "zh";
}

// ===== 文案 =====
const TEXTS = {
  zh: {
    title: "== TraeWork 每日自动签到 ==",
    date: "日期     :",
    checkedLabel: "今日已签 :",
    yes: "是（跳过领取）",
    no: "否",
    resultLabel: "结果     :",
    already: "今日已签到，无需重复操作",
    todayGet: "今日可得",
    base: "基础",
    extra: "额外",
    success: "签到成功",
    earned: "领取积分",
    rewards: "奖励明细 :",
    statusFail: "签到状态读取失败",
    claimFail: "签到失败",
    rawResp: "原始返回 :",
    error: "错误",
  },
  en: {
    title: "== TraeWork Daily Auto Check-in ==",
    date: "Date     :",
    checkedLabel: "Checked  :",
    yes: "Yes (skip claim)",
    no: "No",
    resultLabel: "Result   :",
    already: "Already checked in today, nothing to do",
    todayGet: "today's credits",
    base: "base",
    extra: "extra",
    success: "Check-in success",
    earned: "credits earned",
    rewards: "Rewards  :",
    statusFail: "Status read failed",
    claimFail: "Check-in failed",
    rawResp: "Raw response:",
    error: "Error",
  },
};

async function main() {
  const lang = readLanguage();
  const t = TEXTS[lang];
  const client = await createClient();

  const status = await client.post("/trae/api/v2/ug/checkin_credits/status", {});
  if (!(status.json && status.json.code === 0)) {
    console.log(`[${t.statusFail}] ${(status.json && status.json.message) || "HTTP " + status.status}`);
    process.exit(2);
  }

  const s = status.json;
  const today = new Date().toLocaleDateString(lang === "en" ? "en-US" : "zh-CN");
  console.log(t.title);
  console.log(`${t.date} ${today}`);
  console.log(`${t.checkedLabel} ${s.checked_in ? t.yes : t.no}`);

  if (s.checked_in) {
    const base = s.credits != null ? `${t.base} ${s.credits}` : "";
    const extra = s.extra_credits != null ? ` + ${t.extra} ${s.extra_credits}` : "";
    console.log(`${t.resultLabel} ${t.already}${base || extra ? ` (${t.todayGet}: ${base}${extra})` : ""}`);
    return;
  }

  const claim = await client.post("/trae/api/v2/ug/checkin_credits/claim", {});
  if (claim.json && claim.json.code === 0) {
    const c = claim.json;
    const gained = c.gained_credits ?? c.credits_gained ?? c.reward ?? c.extra_credits ?? "";
    console.log(`${t.resultLabel} ${t.success}${gained !== "" ? `, ${t.earned} ${gained}` : ""}`);
    if (c.reward_info) console.log(`${t.rewards} ${JSON.stringify(c.reward_info)}`);
  } else {
    console.log(`[${t.claimFail}] ${(claim.json && claim.json.message) || "HTTP " + claim.status}`);
    if (claim.json) console.log(`${t.rawResp} ${JSON.stringify(claim.json).slice(0, 300)}`);
    process.exit(3);
  }
}

main().catch((e) => {
  const t = TEXTS[readLanguage()];
  console.error(`[${t.error}] ${e.message}`);
  process.exit(1);
});