package main

import (
	"alibaba-domain/model"
	prom "alibaba-domain/prometheus"
	"alibaba-domain/scrap"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/auth/credentials"
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

	//扫描云解析DNS记录（子域名）
	dnsClient, _ := alidns.NewClientWithOptions(model.RegionID, config, credential)

	//后台抓取
	go scrapDomain(domainClient, dnsClient)

	r := gin.Default()
	r.LoadHTMLGlob("templates/*")
	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", gin.H{"title": "Domain Expiry Exporter"})
	})
	//健康检查
	r.GET("/health", func(c *gin.Context) {

	})
	//指标抓取
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
	domains, err := scrap.ScanRegisterdDomains(domainClient)
	if err != nil {
		log.Printf("get domains failed: %v", err)
	}
	dnsDomains, err := scrap.ScanDNSRecord(dnsClient)
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
