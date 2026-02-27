package utils

import (
	"alibaba-domain/model"
	"fmt"
	"strconv"
)

// 打印结果
func PrintResults(results []model.DomainInfo) {
	fmt.Printf("%-40s %-12s %-12s %-12s %-12s %-12s %-12s %s\n",
		"域名", "注册到期", "注册状态", "注册剩余时间", "证书到期", "证书状态", "证书剩余时间", "备注")
	fmt.Println("------------------------------------------------------------------------------------------------------------------------")

	for _, r := range results {
		regDate := "N/A"
		regDaysLeft := "N/A"
		if !r.RegExpiry.IsZero() {
			regDate = r.RegExpiry.Format("2006-01-02")
			regDaysLeft = strconv.Itoa(r.RegDaysLeft)
		}
		certDate := "N/A"
		certDateLeft := "N/A"
		if !r.CertExpiry.IsZero() {
			certDate = r.CertExpiry.Format("2006-01-02")
			certDateLeft = strconv.Itoa(r.CertDaysLeft)
		}

		note := "None"
		if r.CertError != "" {
			note = r.CertError
		}
		fmt.Printf("%-40s %-12s %-12s %-12s %-12s %-12s %-12s %s\n",
			r.DomainName,
			regDate,
			r.RegStatus,
			regDaysLeft,
			certDate,
			r.CertStatus,
			certDateLeft,
			note)
	}
}
