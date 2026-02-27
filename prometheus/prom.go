package prometheus

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	//域名注册剩余时间
	DomainRegDaysLeft = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "domain_registration_days_left", //指标名
			Help: "主域名注册到期剩余时间(天)",
		},
		[]string{"domain", "type"}, //domain：域名，type：reg/tls
	)

	DomainCertDaysLeft = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "domain_tls_cert_days_left",
			Help: "子域名证书到期剩余时间(天)",
		},
		[]string{"domain", "type"},
	)
)

func init() {
	prometheus.MustRegister(DomainRegDaysLeft, DomainCertDaysLeft)
}
