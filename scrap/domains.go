package scrap

import (
	"alibaba-domain/model"
	"alibaba-domain/utils"
	"fmt"
	"strconv"
	"time"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/domain"
)

// 扫描已注册的主域名
func ScanRegisterdDomains(client *domain.Client) ([]model.DomainInfo, error) {
	//fmt.Println("已注册域名（主域名）:")
	var allDomains []model.DomainInfo
	var domainInfo model.DomainInfo
	req := domain.CreateQueryDomainListRequest()
	req.PageSize = "100"
	req.PageNum = "1"
	for {
		domains, err := client.QueryDomainList(req)
		if err != nil {
			// fmt.Printf("获取注册域名失败：%v\n", err)
			return nil, fmt.Errorf("获取注册域名失败：%v\n", err)
		}
		for _, d := range domains.Data.Domain {
			regExpiry, _ := time.Parse("2006-01-02 15:04:05 MST", d.ExpirationDate+" CST")
			if regExpiry.IsZero() {
				regExpiry, _ = time.Parse("2006-01-02", d.ExpirationDate)
			}
			regDaysLeft := int(regExpiry.Sub(time.Now()).Hours() / 24)
			//证书检测
			domainInfo = utils.CheckDomain(d.DomainName)
			allDomains = append(allDomains, model.DomainInfo{
				DomainName:   d.DomainName,
				RegExpiry:    regExpiry,
				RegDaysLeft:  regDaysLeft,
				RegStatus:    utils.GetStatus(regDaysLeft),
				CertExpiry:   domainInfo.CertExpiry,
				CertDaysLeft: domainInfo.CertDaysLeft,
				CertStatus:   domainInfo.CertStatus,
				CertError:    domainInfo.CertError,
			})
		}
		if len(domains.Data.Domain) < 100 {
			break //最后一页
		}
		currentPage, _ := strconv.Atoi(string(req.PageNum))
		req.PageNum = requests.NewInteger(currentPage + 1)
	}
	//输出
	// utils.PrintResults(allDomains)
	return allDomains, nil
}
