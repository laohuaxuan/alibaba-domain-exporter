package main

import (
	"alibaba-domain/model"
	prom "alibaba-domain/prometheus"
	"alibaba-domain/utils"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/auth/credentials"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/alidns"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/domain"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	//从环境变量读取AK/SK
	accessKeyID := os.Getenv("ALIBABA_CLOUD_ACCESS_KEY_ID")
	accessKeySecret := os.Getenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET")

	if accessKeyID == "" || accessKeySecret == "" {
		panic("请设置环境变量 ALIBABA_CLOUD_ACCESS_KEY_ID 和 ALIBABA_CLOUD_ACCESS_KEY_SECRET")
	}

	//创建客户端
	config := sdk.NewConfig()
	credential := credentials.NewAccessKeyCredential(accessKeyID, accessKeySecret)

	//1、扫描已注册域名（主域名）
	domainClient, _ := domain.NewClientWithOptions(model.RegionID, config, credential)
	//domainClient, err := domain.NewClientWithAccessKey(model.RegionID, accessKeyID, accessKeySecret)
	// if err != nil {
	// 	log.Fatalf("创建 Domain 客户端失败: %v", err)
	// }
	//scanRegisterdDomains(domainClient)

	//扫描云解析DNS记录（子域名）
	dnsClient, _ := alidns.NewClientWithOptions(model.RegionID, config, credential)
	scanDNSRecord(dnsClient)

	//后台抓取
	go scrapDomain(domainClient, dnsClient)

	r := gin.Default()
	r.LoadHTMLGlob("templates/*")
	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", gin.H{"title": "Domain Expiry Exporter"})
	})
	r.GET("/metrics", gin.WrapH(promhttp.Handler()))
	port := os.Getenv("PORT")
	if port == "" {
		port = "9100"
	}
	log.Printf("start prometheus exporter on :%s", port)

	r.Run(":" + port)
}

func scrapDomain(domainClient *domain.Client, dnsClient *alidns.Client) {
	ticker := time.NewTicker(model.ScrapeInterval)
	defer ticker.Stop()

	for {
		scraping(domainClient, dnsClient)
		<-ticker.C
	}
}

func scraping(domainClient *domain.Client, dnsClient *alidns.Client) {
	domains, err := scanRegisterdDomains(domainClient)
	if err != nil {
		log.Printf("get domains failed: %v", err)
	}
	dnsDomains, err := scanDNSRecord(dnsClient)
	if err != nil {
		log.Printf("get sub domains failed: %v", err)
	}

	//清理指标
	prom.DomainCertDaysLeft.Reset()
	prom.DomainRegDaysLeft.Reset()

	for _, domain := range domains {
		regDaysLeft := domain.RegDaysLeft
		prom.DomainRegDaysLeft.WithLabelValues(domain.DomainName, "registration").Set(float64(regDaysLeft))
		certDaysLeft := -1
		if !domain.CertExpiry.IsZero() {
			certDaysLeft = domain.CertDaysLeft
		}
		prom.DomainCertDaysLeft.WithLabelValues(domain.DomainName, "tls_cert").Set(float64(certDaysLeft))
	}

	for _, dnsDomain := range dnsDomains {
		certDaysLeft := -1
		if !dnsDomain.CertExpiry.IsZero() {
			certDaysLeft = dnsDomain.CertDaysLeft
		}
		prom.DomainCertDaysLeft.WithLabelValues(dnsDomain.DomainName, "tls_cert").Set(float64(certDaysLeft))
	}
}

// 主域名
func getAllDomainRecords(client *domain.Client) ([]model.DomainRecord, error) {
	var all []model.DomainRecord
	pageNum := 1
	for {
		req := domain.CreateQueryDomainListRequest()
		req.PageSize = requests.NewInteger(model.PageSize)
		req.PageNum = requests.NewInteger(pageNum)

		resp, err := client.QueryDomainList(req)
		if err != nil {
			return nil, fmt.Errorf("第%d页失败:%v", pageNum, err)
		}

		for _, d := range resp.Data.Domain {
			regExpiry, _ := time.Parse("2006-01-02 15:04:05 MST", d.ExpirationDate+" CST")
			if regExpiry.IsZero() {
				regExpiry, _ = time.Parse("2006-01-02", d.ExpirationDate)
			}
			all = append(all, model.DomainRecord{
				DomainName: d.DomainName,
				Expiry:     regExpiry,
			})
		}
		if len(resp.Data.Domain) < model.PageSize {
			break
		}
		pageNum++
	}
	return all, nil
}

// 子域名
func getSubDomainRecords(client *alidns.Client) ([]model.DomainRecord, error) {
	var all []model.DomainRecord
	pageNum := 1
	for {
		domainReq := alidns.CreateDescribeDomainsRequest()
		domainReq.PageSize = requests.NewInteger(model.PageSize)
		domainReq.PageNumber = requests.NewInteger(pageNum)

		domainResp, err := client.DescribeDomains(domainReq)
		if err != nil {
			fmt.Printf("获取DNS主域名失败：%v\n", err)
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
					all = append(all, model.DomainRecord{
						DomainName: fmt.Sprintf("%s.%s", subdomain, d.DomainName),
					})
					// allSubDomains = append(allSubDomains, model.DomainInfo{
					// 	DomainName: fmt.Sprintf("%s.%s", subdomain, d.DomainName),
					// })
				}
			}
		}
	}
}

// 扫描已注册的主域名
func scanRegisterdDomains(client *domain.Client) ([]model.DomainInfo, error) {
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

// 扫描云解析 DNS 中的所有子域名
func scanDNSRecord(client *alidns.Client) ([]model.DomainInfo, error) {
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
