// Package marketprotocol 实现 KeymasterMarketProtocol v1 的目录读取与校验。
//
// 库负责目录传输层的完整校验流程：JSON 解析、每项渠道结构、逐渠道调用
// 注入的验证器完成发布证明解码与验签、双渠道公钥与版本一致性、按验签
// 公钥去重。发布签名、规范 URL 与展示字段的真值规则由产品侧注入的验证
// 器复用现有实现；本库不重实现发布证明格式。
//
// 任一条目无效使整份响应无效；只有完整通过校验的响应才能作为当前清单。
package marketprotocol

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"unicode/utf8"
)

// VerifiedPublication 是注入验证器返回的已验证发布资料；库只消费目录
// 决策所需字段，完整发布对象归产品侧。展示资料从证明读出；组合发布允许
// 两个渠道的展示不同。PublicationID 为完整规范发布 JSON 的 SHA-256，
// 由验证器按其现有实现提供，空表示不提供。
type VerifiedPublication struct {
	AppPublicKeyHex string
	AppVersion      string
	Name            string
	Description     string
	IconURL         string
	PublicationID   string
	// URL 渠道证明的签署完整入口（含路径、查询和片段）；URL 验证器必填。
	URLAddress string
}

// URLVerifier 验证 URL 渠道证明：解码、验签，要求发布包含受签名 URL
// 渠道，返回已验证公钥、版本与签署完整入口。
type URLVerifier func(proof string) (VerifiedPublication, error)

// FilesVerifier 验证 Files 渠道证明：解码、验签，要求发布包含受签名
// Files 渠道，返回已验证公钥与版本。
type FilesVerifier func(proof string) (VerifiedPublication, error)

// URLEntry 是目录提供的 URL 渠道；证明字符串原样保留供后续流程复用，
// 展示资料从该渠道证明读出。
type URLEntry struct {
	Publication   string `json:"publication"`
	PublicationID string
	Address       string `json:"address"`
	Name          string
	Description   string
	IconURL       string
}

// FilesEntry 是目录提供的 Files 渠道。EntrySeedhashhex 是完整入口的
// 定位值，与证明内签署的、移除证明记录后的入口摘要不同；目录读取阶段
// 仅校验定位值格式与发布签名。展示资料从该渠道证明读出。
type FilesEntry struct {
	Publication      string `json:"publication"`
	PublicationID    string
	EntrySeedhashhex string `json:"indexseedhashhex"`
	Name             string
	Description      string
	IconURL          string
}

// AppEntry 是目录中一个 App 的已验证条目：公钥、版本与渠道；展示资料从
// 证明读出（URL 渠道优先，无 URL 渠道时取 Files 渠道），由产品侧继续消费。
type AppEntry struct {
	AppPublicKeyHex string
	AppVersion      string
	Name            string
	Description     string
	IconURL         string
	URL             *URLEntry
	Files           *FilesEntry
}

// DecodeDirectory 校验一整份目录响应并返回按公钥排序的条目清单。
// apps 必填且为数组；{"apps":[]} 是合法空目录。每项至少一个渠道、每渠道
// 最多一项；字段缺席表示该发布没有由此目录提供的对应渠道。双渠道各自
// 验签且公钥、版本必须一致；两个证明允许不同。按验签公钥去重，重复公钥、
// 缺字段、类型错误、无效渠道、验签失败、截断或解析失败使整份响应无效。
// 消费者不按条目数组顺序决定生效；返回清单已按公钥稳定排序。
func DecodeDirectory(raw []byte, verifyURL URLVerifier, verifyFiles FilesVerifier) ([]AppEntry, error) {
	if !utf8.Valid(raw) {
		return nil, fmt.Errorf("directory response must be UTF-8")
	}
	var doc struct {
		Apps []json.RawMessage `json:"apps"`
	}
	if err := strictUnmarshal(raw, &doc); err != nil {
		return nil, err
	}
	if doc.Apps == nil {
		return nil, fmt.Errorf("directory apps must be an array")
	}
	seen := map[string]bool{}
	out := make([]AppEntry, 0, len(doc.Apps))
	for i, item := range doc.Apps {
		entry, err := decodeAppItem(item, verifyURL, verifyFiles)
		if err != nil {
			return nil, fmt.Errorf("apps[%d]: %w", i, err)
		}
		if seen[entry.AppPublicKeyHex] {
			return nil, fmt.Errorf("duplicate App public key %s", entry.AppPublicKeyHex)
		}
		seen[entry.AppPublicKeyHex] = true
		out = append(out, entry)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].AppPublicKeyHex < out[b].AppPublicKeyHex })
	return out, nil
}

func decodeAppItem(raw json.RawMessage, verifyURL URLVerifier, verifyFiles FilesVerifier) (AppEntry, error) {
	var presence map[string]json.RawMessage
	if err := json.Unmarshal(raw, &presence); err != nil {
		return AppEntry{}, err
	}
	// 显式 null 与字段缺席不同：按协议省略渠道表示不提供该渠道，
	// 传入 null 属于错误类型，须与 TS 同样拒绝整份目录。
	if value, ok := presence["url"]; ok && len(bytes.TrimSpace(value)) != 0 && string(bytes.TrimSpace(value)) == "null" {
		return AppEntry{}, fmt.Errorf("url channel invalid")
	}
	if value, ok := presence["files"]; ok && len(bytes.TrimSpace(value)) != 0 && string(bytes.TrimSpace(value)) == "null" {
		return AppEntry{}, fmt.Errorf("files channel invalid")
	}
	var item struct {
		URL   *struct {
			Publication string `json:"publication"`
		} `json:"url"`
		Files *struct {
			Publication      string `json:"publication"`
			EntrySeedhashhex string `json:"indexseedhashhex"`
		} `json:"files"`
	}
	if err := strictUnmarshal(raw, &item); err != nil {
		return AppEntry{}, err
	}
	if item.URL == nil && item.Files == nil {
		return AppEntry{}, fmt.Errorf("at least one channel is required")
	}
	entry := AppEntry{}
	if item.URL != nil {
		if item.URL.Publication == "" {
			return AppEntry{}, fmt.Errorf("url publication required")
		}
		verified, err := verifyURL(item.URL.Publication)
		if err != nil {
			return AppEntry{}, fmt.Errorf("url publication invalid: %w", err)
		}
		if verified.URLAddress == "" {
			return AppEntry{}, fmt.Errorf("url publication has no signed URL channel")
		}
		entry.AppPublicKeyHex, entry.AppVersion = verified.AppPublicKeyHex, verified.AppVersion
		entry.Name, entry.Description, entry.IconURL = verified.Name, verified.Description, verified.IconURL
		entry.URL = &URLEntry{Publication: item.URL.Publication, PublicationID: verified.PublicationID, Address: verified.URLAddress,
			Name: verified.Name, Description: verified.Description, IconURL: verified.IconURL}
	}
	if item.Files != nil {
		if item.Files.Publication == "" {
			return AppEntry{}, fmt.Errorf("files publication required")
		}
		if !isSeedHex(item.Files.EntrySeedhashhex) {
			return AppEntry{}, fmt.Errorf("files indexseedhashhex invalid")
		}
		verified, err := verifyFiles(item.Files.Publication)
		if err != nil {
			return AppEntry{}, fmt.Errorf("files publication invalid: %w", err)
		}
		if entry.URL != nil {
			if verified.AppPublicKeyHex != entry.AppPublicKeyHex {
				return AppEntry{}, fmt.Errorf("channel App public key mismatch")
			}
			if verified.AppVersion != entry.AppVersion {
				return AppEntry{}, fmt.Errorf("channel appVersion mismatch")
			}
		} else {
			entry.AppPublicKeyHex, entry.AppVersion = verified.AppPublicKeyHex, verified.AppVersion
			entry.Name, entry.Description, entry.IconURL = verified.Name, verified.Description, verified.IconURL
		}
		entry.Files = &FilesEntry{Publication: item.Files.Publication, PublicationID: verified.PublicationID, EntrySeedhashhex: item.Files.EntrySeedhashhex,
			Name: verified.Name, Description: verified.Description, IconURL: verified.IconURL}
	}
	return entry, nil
}

// strictUnmarshal 拒绝未知字段与尾随内容；截断或解析失败整体失败。
func strictUnmarshal(raw []byte, target any) error {
	if len(bytes.TrimLeft(raw, " \t\r\n")) == 0 {
		return fmt.Errorf("directory response empty")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var tail any
	if err := decoder.Decode(&tail); err != io.EOF {
		return fmt.Errorf("trailing JSON content")
	}
	return nil
}

func isSeedHex(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
