package common

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/mikelpsv/tuya_cloud_sdk_go/config"

	"github.com/mikelpsv/tuya_cloud_sdk_go/pkg/tylog"
)

func DoAPIRequest(a APIRequest, resp interface{}) error {
	body := []byte(``)

	var token, err = TokenLocalCache.GetToken()
	if err != nil {
		return ErrorGetTokenFailed
	}

	uri := strings.Join([]string{config.HOST, a.API()}, "")
	timestamp := GetTimestamp()

	var req *http.Request
	pr, ok := a.(RequestBody)
	if ok {
		body = pr.Body()
		req, err = http.NewRequest(a.Method(), uri, bytes.NewReader(pr.Body()))
	} else {
		req, err = http.NewRequest(a.Method(), uri, nil)
	}
	if err != nil {
		return err
	}

	sign := GetBizSign(req, body, token, timestamp)

	if a.Method() != "GET" {
		AddBodyBizHeader(req, token, sign, timestamp)
	} else {
		AddBizHeader(req, token, sign, timestamp)
	}

	err = DoRequest(req, resp)
	return err
}

func AddEasyHeader(req *http.Request, sign, timestamp string) {
	req.Header.Add("client_id", config.AccessID)
	req.Header.Add("sign", sign)
	req.Header.Add("sign_method", "HMAC-SHA256")
	req.Header.Add("t", timestamp)
}

func AddBizHeader(req *http.Request, token, sign, timestamp string) {
	req.Header.Add("client_id", config.AccessID)
	req.Header.Add("access_token", token)
	req.Header.Add("sign", sign)
	req.Header.Add("sign_method", "HMAC-SHA256")
	req.Header.Add("t", timestamp)
}

func AddBodyBizHeader(req *http.Request, token, sign, timestamp string) {
	req.Header.Add("client_id", config.AccessID)
	req.Header.Add("access_token", token)
	req.Header.Add("sign", sign)
	req.Header.Add("sign_method", "HMAC-SHA256")
	req.Header.Add("t", timestamp)
	req.Header.Add("Content-Type", "application/json")
}

func DoRequest(req *http.Request, resp interface{}) error {
	httpResp, err := http.DefaultClient.Do(req)
	if err != nil {
		tylog.SugarLog.Errorf("do request failed err:%v,req:%v\n", err, req)
		return err
	}
	defer httpResp.Body.Close()
	bs, err := ioutil.ReadAll(httpResp.Body)
	if err != nil {
		tylog.SugarLog.Errorf("do request failed err:%v,req:%v\n", err, req)
		return err
	}

	// resp := &GetFunctionsResponse{}
	err = json.Unmarshal(bs, &resp)
	if err != nil {
		tylog.SugarLog.Errorf("do request failed err:%v,req:%v,resp:%v\n", err, req, string(bs))
		return err
	}
	tylog.SugarLog.Infof("req:%v,resp:%+v\n", req, resp)
	return nil
}

func NewHTTPRequest(a APIRequest) (*http.Request, error) {
	url := strings.Join([]string{config.HOST, a.API()}, "")
	var req *http.Request
	var err error
	pr, ok := a.(RequestBody)
	if ok {
		req, err = http.NewRequest(a.Method(), url, bytes.NewReader(pr.Body()))
	} else {
		req, err = http.NewRequest(a.Method(), url, nil)
	}
	return req, err
}
