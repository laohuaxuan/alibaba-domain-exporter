package model

import "time"

type DomainInfo struct {
	DomainName   string
	RegExpiry    time.Time // 域名注册到期
	CertExpiry   time.Time // TLS 证书到期
	RegDaysLeft  int
	CertDaysLeft int
	RegStatus    string
	CertStatus   string
	CertError    string
}

const (
	RegionID       = "cn-shanghai" //域名服务固定区域
	PageSize       = 100
	Timeout        = 8 * time.Second
	ScrapeInterval = 6 * time.Hour //每6小时刷新
)

// type DomainRecord struct {
// 	DomainName string
// 	Expiry     time.Time
// }
