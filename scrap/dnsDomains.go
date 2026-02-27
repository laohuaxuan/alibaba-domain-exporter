package scrap

import (
	"alibaba-domain/model"
	"alibaba-domain/utils"
	"fmt"
	"strconv"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/alidns"
)

// 扫描云解析 DNS 中的所有子域名
func ScanDNSRecord(client *alidns.Client) ([]model.DomainInfo, error) {
	//先获取所有主域名
	domainReq := alidns.CreateDescribeDomainsRequest()
	domainReq.PageSize = "50"
	domainReq.PageNumber = "1"
	var allSubDomains []model.DomainInfo
	for {
		domainResp, err := client.DescribeDomains(domainReq)
		if err != nil {
			// fmt.Printf("获取DNS主域名失败：%v\n", err)
			return nil, fmt.Errorf("获取DNS主域名失败：%v\n", err)
		}

		for _, d := range domainResp.Domains.Domain {
			// 获取该主域名下的所有记录
			recordReq := alidns.CreateDescribeDomainRecordsRequest()
			recordReq.DomainName = d.DomainName
			recordReq.PageSize = "500" //一次性拉取最多500条

			recordResp, err := client.DescribeDomainRecords(recordReq)
			if err != nil {
				fmt.Printf("跳过域名 %s: %v\n", d.DomainName, err)
				continue
			}

			for _, r := range recordResp.DomainRecords.Record {
				if r.Type == "A" || r.Type == "CNAME" || r.Type == "AAAA" {
					subdomain := r.RR
					if subdomain == "@" { //根域名
						continue
					}
					allSubDomains = append(allSubDomains, model.DomainInfo{
						DomainName: fmt.Sprintf("%s.%s", subdomain, d.DomainName),
					})
				}
			}
		}
		if len(domainResp.Domains.Domain) < 50 {
			break
		}
		currentPage, _ := strconv.Atoi(string(domainReq.PageNumber))
		domainReq.PageNumber = requests.NewInteger(currentPage + 1)
	}

	//检查证书
	all := utils.CheckAllCertificates(allSubDomains)
	return all, nil
	// utils.PrintResults(all)
}
