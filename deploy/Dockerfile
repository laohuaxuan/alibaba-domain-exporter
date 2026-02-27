FROM acr-openxlab-prod-registry-vpc.cn-shanghai.cr.aliyuncs.com/public/golang:1.24-alpine as builder
#解决alpine环境的C动态库在ubuntu中没有的问题
ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

WORKDIR $GOPATH/src
COPY . .
COPY etc /app/etc

RUN go env -w GOPROXY=https://mirrors.aliyun.com/goproxy/,direct && go build -o /app/alibaba-domain-exporter

FROM acr-openxlab-prod-registry-vpc.cn-shanghai.cr.aliyuncs.com/public/ubuntu:24.04


RUN cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && \
    echo "Asia/Shanghai" > /etc/timezone

WORKDIR /app
COPY --from=builder /app .

#阿里云AKSK环境变量
ARG ALIBABA_CLOUD_ACCESS_KEY_ID
ARG ALIBABA_CLOUD_ACCESS_KEY_SECRET

ENV TZ=Asia/Shanghai

ENTRYPOINT ["./alibaba-domain-exporter"]