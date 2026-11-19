/**
 * KeymasterMarketProtocol v1 目录读取与校验。
 *
 * 库负责目录传输层的完整校验流程：JSON 解析、每项渠道结构、逐渠道调用
 * 注入的验证器完成发布证明解码与验签、双渠道公钥与版本一致性、按验签
 * 公钥去重。发布签名、规范 URL 与展示字段的真值规则由产品侧注入的验证
 * 器复用现有实现；本库不重实现发布证明格式。
 *
 * 任一条目无效使整份响应无效；只有完整通过校验的响应才能作为当前清单。
 */

export interface VerifiedPublication {
  appPublicKeyHex: string;
  appVersion: string;
  /** 展示资料从证明读出；组合发布允许两个渠道的展示不同。 */
  name: string;
  description: string;
  iconUrl: string;
  /** 完整规范发布 JSON 的 SHA-256；验证器按其现有实现提供，空表示不提供。 */
  publicationId: string;
  /** URL 渠道证明的签署完整入口（含路径、查询和片段）；URL 验证器必填。 */
  urlAddress: string;
}

/** URL 渠道验证器：解码、验签，要求发布包含受签名 URL 渠道。 */
export type UrlVerifier = (proof: string) => VerifiedPublication;
/** Files 渠道验证器：解码、验签，要求发布包含受签名 Files 渠道。 */
export type FilesVerifier = (proof: string) => VerifiedPublication;

/** 目录提供的 URL 渠道；证明字符串原样保留供后续流程复用。 */
export interface UrlEntry {
  publication: string;
  /** 完整规范发布 JSON 的 SHA-256；空表示验证器未提供。 */
  publicationId: string;
  /** 签署完整入口。 */
  address: string;
  name: string;
  description: string;
  iconUrl: string;
}

/** 目录提供的 Files 渠道。indexseedhashhex 是完整入口的定位值。 */
export interface FilesEntry {
  publication: string;
  publicationId: string;
  indexseedhashhex: string;
  name: string;
  description: string;
  iconUrl: string;
}

/** 目录中一个 App 的已验证条目；展示资料从证明读出（URL 渠道优先）。 */
export interface AppEntry {
  appPublicKeyHex: string;
  appVersion: string;
  name: string;
  description: string;
  iconUrl: string;
  url?: UrlEntry;
  files?: FilesEntry;
}

const SEEDHEX_PATTERN = /^[0-9a-f]{64}$/;

/**
 * 校验一整份目录响应并返回按公钥排序的条目清单。apps 必填且为数组；
 * `{"apps":[]}` 是合法空目录。每项至少一个渠道、每渠道最多一项；字段
 * 缺席表示该发布没有由此目录提供的对应渠道。双渠道各自验签且公钥、版本
 * 必须一致；两个证明允许不同。按验签公钥去重；重复公钥、缺字段、类型
 * 错误、无效渠道、验签失败、截断或解析失败使整份响应无效。消费者不按
 * 条目数组顺序决定生效；返回清单已按公钥稳定排序。
 */
export function decodeDirectory(
  raw: string,
  verifyUrl: UrlVerifier,
  verifyFiles: FilesVerifier,
): AppEntry[] {
  if (typeof raw !== "string" || raw.trim() === "") throw new Error("directory response empty");
  let doc: unknown;
  try {
    doc = JSON.parse(raw);
  } catch (cause) {
    throw cause instanceof Error ? cause : new Error(String(cause));
  }
  if (doc === null || typeof doc !== "object" || Array.isArray(doc)) throw new Error("directory root must be an object");
  const record = doc as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  if (keys.length !== 1 || keys[0] !== "apps") throw new Error("directory fields invalid");
  if (!Array.isArray(record.apps)) throw new Error("directory apps must be an array");
  const seen = new Set<string>();
  const out: AppEntry[] = [];
  for (const item of record.apps) {
    const entry = decodeAppItem(item, verifyUrl, verifyFiles);
    if (seen.has(entry.appPublicKeyHex)) throw new Error(`duplicate App public key ${entry.appPublicKeyHex}`);
    seen.add(entry.appPublicKeyHex);
    out.push(entry);
  }
  out.sort((a, b) => (a.appPublicKeyHex < b.appPublicKeyHex ? -1 : a.appPublicKeyHex > b.appPublicKeyHex ? 1 : 0));
  return out;
}

function decodeAppItem(item: unknown, verifyUrl: UrlVerifier, verifyFiles: FilesVerifier): AppEntry {
  if (item === null || typeof item !== "object" || Array.isArray(item)) throw new Error("directory app must be an object");
  const record = item as Record<string, unknown>;
  const keys = Object.keys(record).sort().join(",");
  if (keys !== "" && keys !== "files" && keys !== "url" && keys !== "files,url") throw new Error("directory app fields invalid");
  const entry: AppEntry = { appPublicKeyHex: "", appVersion: "", name: "", description: "", iconUrl: "" };
  if (record.url !== undefined) {
    if (record.url === null || typeof record.url !== "object" || Array.isArray(record.url)) throw new Error("url channel invalid");
    const url = record.url as Record<string, unknown>;
    if (Object.keys(url).join(",") !== "publication" || typeof url.publication !== "string" || !url.publication) {
      throw new Error("url publication required");
    }
    const verified = wrapVerify(() => verifyUrl(url.publication as string), "url publication invalid");
    if (!verified.urlAddress) throw new Error("url publication has no signed URL channel");
    entry.appPublicKeyHex = verified.appPublicKeyHex;
    entry.appVersion = verified.appVersion;
    entry.name = verified.name;
    entry.description = verified.description;
    entry.iconUrl = verified.iconUrl;
    entry.url = {
      publication: url.publication as string,
      publicationId: verified.publicationId,
      address: verified.urlAddress,
      name: verified.name,
      description: verified.description,
      iconUrl: verified.iconUrl,
    };
  }
  if (record.files !== undefined) {
    if (record.files === null || typeof record.files !== "object" || Array.isArray(record.files)) throw new Error("files channel invalid");
    const files = record.files as Record<string, unknown>;
    if (Object.keys(files).sort().join(",") !== "indexseedhashhex,publication") {
      throw new Error("files channel fields invalid");
    }
    if (typeof files.publication !== "string" || !files.publication) throw new Error("files publication required");
    if (typeof files.indexseedhashhex !== "string" || !SEEDHEX_PATTERN.test(files.indexseedhashhex)) {
      throw new Error("files indexseedhashhex invalid");
    }
    const verified = wrapVerify(() => verifyFiles(files.publication as string), "files publication invalid");
    if (entry.url) {
      if (verified.appPublicKeyHex !== entry.appPublicKeyHex) throw new Error("channel App public key mismatch");
      if (verified.appVersion !== entry.appVersion) throw new Error("channel appVersion mismatch");
    } else {
      entry.appPublicKeyHex = verified.appPublicKeyHex;
      entry.appVersion = verified.appVersion;
      entry.name = verified.name;
      entry.description = verified.description;
      entry.iconUrl = verified.iconUrl;
    }
    entry.files = {
      publication: files.publication as string,
      publicationId: verified.publicationId,
      indexseedhashhex: files.indexseedhashhex as string,
      name: verified.name,
      description: verified.description,
      iconUrl: verified.iconUrl,
    };
  }
  if (!entry.url && !entry.files) throw new Error("at least one channel is required");
  return entry;
}

function wrapVerify(run: () => VerifiedPublication, context: string): VerifiedPublication {
  try {
    const verified = run();
    if (!verified || typeof verified !== "object" || !verified.appPublicKeyHex || !verified.appVersion) {
      throw new Error("verified publication fields invalid");
    }
    return verified;
  } catch (cause) {
    const message = cause instanceof Error ? cause.message : String(cause);
    throw new Error(`${context}: ${message}`);
  }
}
