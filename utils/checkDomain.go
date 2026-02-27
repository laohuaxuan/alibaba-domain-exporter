package utils

import (
	"alibaba-domain/model"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"
)

// 根据剩余天数生成状态
func GetStatus(daysLeft int) string {
	if daysLeft < 0 {
		return "已过期"
	} else if daysLeft < 30 {
		return "即将过期"
	}
	return "正常"
}

// 并发检查所有域名的TLS证书
func CheckAllCertificates(domains []model.DomainInfo) []model.DomainInfo {
	results := make([]model.DomainInfo, len(domains))
	var wg sync.WaitGroup
	wg.Add(len(domains))

	for i, domain := range domains {
		go func(idx int, d string) {
			defer wg.Done()
			info := CheckDomain(d)
			results[idx] = info
		}(i, domain.DomainName)
	}
	wg.Wait()
	return results
}

// 检查单个域名
func CheckDomain(domain string) model.DomainInfo {
	certExpiry, certErr := getCertExpiry(domain)
	var certDaysLeft int
	var certStatus string
	if certErr != "" {
		certStatus = "获取失败"
	} else {
		certDaysLeft = int(certExpiry.Sub(time.Now()).Hours() / 24)
		certStatus = GetStatus(certDaysLeft)
	}
	return model.DomainInfo{
		DomainName:   domain,
		CertExpiry:   certExpiry,
		CertDaysLeft: certDaysLeft,
		CertStatus:   certStatus,
		CertError:    certErr,
	}
}

// 检查 单个TLS 证书
func getCertExpiry(domain string) (time.Time, string) {
	netDialer := &net.Dialer{
		Timeout:   model.Timeout,
		KeepAlive: 30 * time.Second,
	}
	conn, err := tls.DialWithDialer(netDialer, "tcp", domain+":443", &tls.Config{
		ServerName:         domain,
		InsecureSkipVerify: false,
	})
	if err != nil {
		return time.Time{}, fmt.Sprintf("连接失败: %v", err)
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return time.Time{}, "无证书"
	}

	return certs[0].NotAfter, ""
}
