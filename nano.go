package main

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
)

func matcher(url string) {
	response := requester(url)
	if response != "" {
		Hach, _ := CreatHashSum(response)
		if contains(HashList, Hach) == false {
			HashList = append(HashList, Hach)
			for k, p := range regex {
				rgx := regexp.MustCompile(p)
				found := rgx.MatchString(response)
				if found {
					mt := rgx.FindStringSubmatch(response)
					a := mt[0]
					fmt.Printf("%s  \033[32m  %s : %s \033[00m\n", url, k, a)
				}

			}

		}

	}

}

func CreatHashSum(input string) (string, error) {
	hasher := md5.New()

	_, err := hasher.Write([]byte(input))
	if err != nil {
		return "", err
	}

	hashSum := hasher.Sum(nil)

	hashString := hex.EncodeToString(hashSum)

	return hashString, nil
}

func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}

func isUrl(url string) bool {
	s := false

	if strings.HasPrefix(url, "http://") == true || strings.HasPrefix(url, "https://") == true {
		if len(strings.Split(url, "/")) > 2 {
			s = true
		}

	}
	return s
}
func requester(url string) string {

	response := ""
	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err == nil {
		resp, err := client.Do(req)
		if err == nil {
			defer resp.Body.Close()

			body, _ := ioutil.ReadAll(resp.Body)
			response = string(body)

		}
	}
	return response
}

var regex = map[string]string{
	"Yopmail":                  "@yopmail.com",
	"Firebase":                 "[-a-zA-Z0-9@:%._~#=]{1,256}.firebaseio.com",
	"AWS Access Key ID Value":  "(A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
	"FCM Server Key":           "AAAA[a-zA-Z0-9_-]{7}:[a-zA-Z0-9_-]{140}",
	"slack_token":              "(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
	"slack_webhook":            "https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
	"facebook_oauth":           "[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].{0,30}['\"\\s][0-9a-f]{32}['\"\\s]",
	"twitter_oauth":            "[t|T][w|W][i|I][t|T][t|T][e|E][r|R].{0,30}['\"\\s][0-9a-zA-Z]{35,44}['\"\\s]",
	"heroku_api":               "[h|H][e|E][r|R][o|O][k|K][u|U].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
	"mailgun_api":              "key-[0-9a-zA-Z]{32}",
	"mailchamp_api":            "[0-9a-f]{32}-us[0-9]{1,2}",
	"picatic_api":              "sk_live_[0-9a-z]{32}",
	"google_oauth_id":          "[0-9(+-[0-9A-Za-z_]{32}.apps.googleusercontent.com",
	"ipinfo token":             "ipinfo.io?token=",
	"google_api":               "AIza[0-9A-Za-z-_]{35}",
	"google_captcha":           "^6[0-9a-zA-Z_-]{39}$",
	"google_oauth":             "ya29\\.[0-9A-Za-z\\-_]+",
	"amazon_aws_access_key_id": "AKIA[0-9A-Z]{16}",
	"amazon_mws_auth_token":    "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
	//"amazonaws_url":                 "s3\\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\\.s3\\.amazonaws.com",
	"facebook_access_token":         "EAACEdEose0cBA[0-9A-Za-z]+",
	"mailgun_api_key":               "key-[0-9a-zA-Z]{32}",
	"twilio_api_key":                "K[0-9a-fA-F]{32}$",
	"twilio_account_sid":            "C[a-zA-Z0-9_\\-]{32}$",
	"twilio_app_sid":                "P[a-zA-Z0-9_\\-]{32}$",
	"paypal_braintree_access_token": "access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}",
	"square_oauth_secret":           "sq0csp-[ 0-9A-Za-z\\-_]{43}",
	"square_access_token":           "sqOatp-[0-9A-Za-z\\-_]{22}",
	"stripe_standard_api":           "sk_live_[0-9a-zA-Z]{24}",
	"stripe_restricted_api":         "rk_live_[0-9a-zA-Z]{24}",
	"github_access_token":           "[a-zA-Z0-9_-]*:[a-zA-Z0-9_\\-]+@github\\.com*",
	"private_ssh_key":               "-----BEGIN PRIVATE KEY-----[a-zA-Z0-9\\S]{100,}-----END PRIVATE KEY-----",
	"private_rsa_key":               "-----BEGIN RSA PRIVATE KEY-----[a-zA-Z0-9\\S]{100,}-----END RSA PRIVATE KEY-----",
	"AMAZON_KEY":                    "([^A-Z0-9]|^)(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{12,}",
	"Authorization":                 "^Bearer[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$",
	"accessToken":                   "^acesstoken=[0-9]{13,17}",
	"vtex-key":                      "vtex-api-(appkey|apptoken)",
	"email":                         "(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+.[a-zA-Z0-9-.]+$)",
	"api.runtime.dev":               " https://api.runtime.dev/tlp?apikey",
	"app.sportdataapi.com":          "https://app.sportdataapi.com/api",
	"api.mediastack.com":            "https://api.mediastack.com/v1",
	"api.screenshotlayer.com":       "http://api.screenshotlayer.com/api/capture ",
	"api.languagelayer.com":         "http://api.languagelayer.com/detect?access_key=",
	"app.zenscrape.com":             "https://app.zenscrape.com/api/v1/get?apikey=",
	"Http usernamme password":       "(ftp|ftps|http|https)://[A-Za-z0-9-_:.~]+(@)",
	"credentials-disclosure[7]":     "zendesk[_-]?travis[_-]?github(=| =|:| :)",
	"credentials-disclosure[10]":    "yt[_-]?partner[_-]?client[_-]?secret(=| =|:| :)",
	"credentials-disclosure[11]":    "yt[_-]?client[_-]?secret(=| =|:| :)",
	"credentials-disclosure[14]":    "yt[_-]?account[_-]?client[_-]?secret(=| =|:| :)",
	"credentials-disclosure[17]":    "www[_-]?googleapis[_-]?com(=| =|:| :)",
	"credentials-disclosure[19]":    "wpt[_-]?ssh[_-]?connect(=| =|:| :)",
	"credentials-disclosure[21]":    "wpt[_-]?prepare[_-]?dir(=| =|:| :)",
	"credentials-disclosure[22]":    "wpt[_-]?db[_-]?user(=| =|:| :)",
	"credentials-disclosure[26]":    "wordpress[_-]?db[_-]?user(=| =|:| :)",
	"credentials-disclosure[29]":    "widget[_-]?test[_-]?server(=| =|:| :)",
	"credentials-disclosure[49]":    "v[_-]?sfdc[_-]?client[_-]?secret(=| =|:| :)",
	"credentials-disclosure[50]":    "usertravis(=| =|:| :)",
	"credentials-disclosure[53]":    "use[_-]?ssh(=| =|:| :)",
	"credentials-disclosure[54]":    "us[_-]?east[_-]?1[_-]?elb[_-]?amazonaws[_-]?com(=| =|:| :)",
	"credentials-disclosure[55]":    "urban[_-]?secret(=| =|:| :)",
	"credentials-disclosure[56]":    "urban[_-]?master[_-]?secret(=| =|:| :)",
	"credentials-disclosure[58]":    "unity[_-]?serial(=| =|:| :)",
	"credentials-disclosure[61]":    "twitteroauthaccesssecret(=| =|:| :)",
	"credentials-disclosure[62]":    "twitter[_-]?consumer[_-]?secret(=| =|:| :)",
	"credentials-disclosure[66]":    "twilio[_-]?sid(=| =|:| :)",
	"credentials-disclosure[67]":    "twilio[_-]?configuration[_-]?sid(=| =|:| :)",
	"credentials-disclosure[68]":    "twilio[_-]?chat[_-]?account[_-]?api[_-]?service(=| =|:| :)",
	"credentials-disclosure[69]":    "twilio[_-]?api[_-]?secret(=| =|:| :)",
	"credentials-disclosure[74]":    "travis[_-]?secure[_-]?env[_-]?vars(=| =|:| :)",
	"credentials-disclosure[75]":    "travis[_-]?pull[_-]?request(=| =|:| :)",
	"credentials-disclosure[79]":    "travis[_-]?branch(=| =|:| :)",
	"credentials-disclosure[85]":    "test[_-]?test(=| =|:| :)",
	"credentials-disclosure[90]":    "surge[_-]?login(=| =|:| :)",
	"credentials-disclosure[91]":    "stripe[_-]?public(=| =|:| :)",
	"credentials-disclosure[92]":    "stripe[_-]?private(=| =|:| :)",
	"credentials-disclosure[98]":    "starship[_-]?account[_-]?sid(=| =|:| :)",
	"credentials-disclosure[100]":   "star[_-]?test[_-]?location(=| =|:| :)",
	"credentials-disclosure[101]":   "star[_-]?test[_-]?bucket(=| =|:| :)",
	"credentials-disclosure[103]":   "staging[_-]?base[_-]?url[_-]?runscope(=| =|:| :)",
	"credentials-disclosure[104]":   "ssmtp[_-]?config(=| =|:| :)",
	"credentials-disclosure[111]":   "spotify[_-]?api[_-]?client[_-]?secret(=| =|:| :)",
	"credentials-disclosure[116]":   "soundcloud[_-]?client[_-]?secret(=| =|:| :)",
	"credentials-disclosure[134]":   "snoowrap[_-]?client[_-]?secret(=| =|:| :)",
	"credentials-disclosure[137]":   "slash[_-]?developer[_-]?space(=| =|:| :)",
	"credentials-disclosure[147]":   "service[_-]?account[_-]?secret(=| =|:| :)",
	"credentials-disclosure[149]":   "sentry[_-]?endpoint(=| =|:| :)",
	"credentials-disclosure[150]":   "sentry[_-]?default[_-]?org(=| =|:| :)",
	"credentials-disclosure[153]":   "sendgrid[_-]?username(=| =|:| :)",
	"credentials-disclosure[154]":   "sendgrid[_-]?user(=| =|:| :)",
	"credentials-disclosure[158]":   "sendgrid(=| =|:| :)",
	"credentials-disclosure[159]":   "selion[_-]?selenium[_-]?host(=| =|:| :)",
	"credentials-disclosure[160]":   "selion[_-]?log[_-]?level[_-]?dev(=| =|:| :)",
	"credentials-disclosure[165]":   "secret[_-]?9(=| =|:| :)",
	"credentials-disclosure[166]":   "secret[_-]?8(=| =|:| :)",
	"credentials-disclosure[167]":   "secret[_-]?7(=| =|:| :)",
	"credentials-disclosure[168]":   "secret[_-]?6(=| =|:| :)",
	"credentials-disclosure[169]":   "secret[_-]?5(=| =|:| :)",
	"credentials-disclosure[170]":   "secret[_-]?4(=| =|:| :)",
	"credentials-disclosure[171]":   "secret[_-]?3(=| =|:| :)",
	"credentials-disclosure[172]":   "secret[_-]?2(=| =|:| :)",
	"credentials-disclosure[173]":   "secret[_-]?11(=| =|:| :)",
	"credentials-disclosure[174]":   "secret[_-]?10(=| =|:| :)",
	"credentials-disclosure[175]":   "secret[_-]?1(=| =|:| :)",
	"credentials-disclosure[176]":   "secret[_-]?0(=| =|:| :)",
	"credentials-disclosure[185]":   "sacloud[_-]?api(=| =|:| :)",
	"credentials-disclosure[188]":   "s3[_-]?user[_-]?secret(=| =|:| :)",
	"credentials-disclosure[190]":   "s3[_-]?secret[_-]?assets(=| =|:| :)",
	"credentials-disclosure[191]":   "s3[_-]?secret[_-]?app[_-]?logs(=| =|:| :)",
	"credentials-disclosure[195]":   "s3[_-]?external[_-]?3[_-]?amazonaws[_-]?com(=| =|:| :)",
	"credentials-disclosure[196]":   "s3[_-]?bucket[_-]?name[_-]?assets(=| =|:| :)",
	"credentials-disclosure[197]":   "s3[_-]?bucket[_-]?name[_-]?app[_-]?logs(=| =|:| :)",
	"credentials-disclosure[208]":   "reporting[_-]?webdav[_-]?url(=| =|:| :)",
	"credentials-disclosure[209]":   "reporting[_-]?webdav[_-]?pwd(=| =|:| :)",
	"credentials-disclosure[212]":   "registry[_-]?secure(=| =|:| :)",
	"credentials-disclosure[215]":   "rediscloud[_-]?url(=| =|:| :)",
	"credentials-disclosure[216]":   "redis[_-]?stunnel[_-]?urls(=| =|:| :)",
	"credentials-disclosure[223]":   "publish[_-]?secret(=| =|:| :)",
	"credentials-disclosure[225]":   "publish[_-]?access(=| =|:| :)",
	"credentials-disclosure[226]":   "project[_-]?config(=| =|:| :)",
	"credentials-disclosure[231]":   "pring[_-]?mail[_-]?username(=| =|:| :)",
	"credentials-disclosure[232]":   "preferred[_-]?username(=| =|:| :)",
	"credentials-disclosure[233]":   "prebuild[_-]?auth(=| =|:| :)",
	"credentials-disclosure[235]":   "postgresql[_-]?db(=| =|:| :)",
	"credentials-disclosure[237]":   "postgres[_-]?env[_-]?postgres[_-]?db(=| =|:| :)",
	"credentials-disclosure[242]":   "pg[_-]?host(=| =|:| :)",
	"credentials-disclosure[243]":   "pg[_-]?database(=| =|:| :)",
	"credentials-disclosure[244]":   "personal[_-]?secret(=| =|:| :)",
	"credentials-disclosure[247]":   "percy[_-]?project(=| =|:| :)",
	"credentials-disclosure[248]":   "paypal[_-]?client[_-]?secret(=| =|:| :)",
	"credentials-disclosure[253]":   "ossrh[_-]?username(=| =|:| :)",
	"credentials-disclosure[254]":   "ossrh[_-]?secret(=| =|:| :)",
	"credentials-disclosure[259]":   "os[_-]?auth[_-]?url(=| =|:| :)",
	"credentials-disclosure[270]":   "okta[_-]?oauth2[_-]?clientsecret(=| =|:| :)",
	"credentials-disclosure[271]":   "okta[_-]?oauth2[_-]?client[_-]?secret(=| =|:| :)",
	"credentials-disclosure[273]":   "ofta[_-]?secret(=| =|:| :)",
	"credentials-disclosure[274]":   "ofta[_-]?region(=| =|:| :)",
	"credentials-disclosure[277]":   "octest[_-]?app[_-]?username(=| =|:| :)",
	"credentials-disclosure[280]":   "object[_-]?store[_-]?creds(=| =|:| :)",
	"credentials-disclosure[281]":   "object[_-]?store[_-]?bucket(=| =|:| :)",
	"credentials-disclosure[282]":   "object[_-]?storage[_-]?region[_-]?name(=| =|:| :)",
	"credentials-disclosure[301]":   "node[_-]?env(=| =|:| :)",
	"credentials-disclosure[308]":   "nativeevents(=| =|:| :)",
	"credentials-disclosure[309]":   "mysqlsecret(=| =|:| :)",
	"credentials-disclosure[310]":   "mysqlmasteruser(=| =|:| :)",
	"credentials-disclosure[311]":   "mysql[_-]?username(=| =|:| :)",
	"credentials-disclosure[312]":   "mysql[_-]?user(=| =|:| :)",
	"credentials-disclosure[315]":   "mysql[_-]?hostname(=| =|:| :)",
	"credentials-disclosure[316]":   "mysql[_-]?database(=| =|:| :)",
	"credentials-disclosure[317]":   "my[_-]?secret[_-]?env(=| =|:| :)",
	"credentials-disclosure[318]":   "multi[_-]?workspace[_-]?sid(=| =|:| :)",
	"credentials-disclosure[319]":   "multi[_-]?workflow[_-]?sid(=| =|:| :)",
	"credentials-disclosure[320]":   "multi[_-]?disconnect[_-]?sid(=| =|:| :)",
	"credentials-disclosure[321]":   "multi[_-]?connect[_-]?sid(=| =|:| :)",
	"credentials-disclosure[322]":   "multi[_-]?bob[_-]?sid(=| =|:| :)",
	"credentials-disclosure[335]":   "manifest[_-]?app[_-]?url(=| =|:| :)",
	"credentials-disclosure[340]":   "manage[_-]?secret(=| =|:| :)",
	"credentials-disclosure[354]":   "magento[_-]?auth[_-]?username (=| =|:| :)",
	"credentials-disclosure[361]":   "looker[_-]?test[_-]?runner[_-]?client[_-]?secret(=| =|:| :)",
	"credentials-disclosure[363]":   "ll[_-]?publish[_-]?url(=| =|:| :)",
	"credentials-disclosure[367]":   "lektor[_-]?deploy[_-]?username(=| =|:| :)",
	"credentials-disclosure[370]":   "kxoltsn3vogdop92m(=| =|:| :)",
	"credentials-disclosure[371]":   "kubeconfig(=| =|:| :)",
	"credentials-disclosure[372]":   "kubecfg[_-]?s3[_-]?path(=| =|:| :)",
	"credentials-disclosure[375]":   "kafka[_-]?rest[_-]?url(=| =|:| :)",
	"credentials-disclosure[376]":   "kafka[_-]?instance[_-]?name(=| =|:| :)",
	"credentials-disclosure[377]":   "kafka[_-]?admin[_-]?url(=| =|:| :)",
	"credentials-disclosure[378]":   "jwt[_-]?secret(=| =|:| :)",
	"credentials-disclosure[379]":   "jdbc:mysql(=| =|:| :)",
	"credentials-disclosure[380]":   "jdbc[_-]?host(=| =|:| :)",
	"credentials-disclosure[381]":   "jdbc[_-]?databaseurl(=| =|:| :)",
	"credentials-disclosure[384]":   "internal[_-]?secrets(=| =|:| :)",
	"credentials-disclosure[385]":   "integration[_-]?test[_-]?appid(=| =|:| :)",
	"credentials-disclosure[387]":   "index[_-]?name(=| =|:| :)",
	"credentials-disclosure[388]":   "ij[_-]?repo[_-]?username(=| =|:| :)",
	"credentials-disclosure[400]":   "grgit[_-]?user(=| =|:| :)",
	"credentials-disclosure[404]":   "gradle[_-]?publish[_-]?secret(=| =|:| :)",
	"credentials-disclosure[409]":   "gpg[_-]?ownertrust(=| =|:| :)",
	"credentials-disclosure[414]":   "google[_-]?client[_-]?secret(=| =|:| :)",
	"credentials-disclosure[415]":   "google[_-]?client[_-]?id(=| =|:| :)",
	"credentials-disclosure[417]":   "google[_-]?account[_-]?type(=| =|:| :)",
	"credentials-disclosure[422]":   "github[_-]?repo(=| =|:| :)",
	"credentials-disclosure[424]":   "github[_-]?pwd(=| =|:| :)",
	"credentials-disclosure[427]":   "github[_-]?oauth(=| =|:| :)",
	"credentials-disclosure[429]":   "github[_-]?hunter[_-]?username(=| =|:| :)",
	"credentials-disclosure[433]":   "github[_-]?client[_-]?secret(=| =|:| :)",
	"credentials-disclosure[435]":   "github[_-]?auth(=| =|:| :)",
	"credentials-disclosure[440]":   "git[_-]?name(=| =|:| :)",
	"credentials-disclosure[442]":   "git[_-]?committer[_-]?name(=| =|:| :)",
	"credentials-disclosure[444]":   "git[_-]?author[_-]?name(=| =|:| :)",
	"credentials-disclosure[448]":   "gh[_-]?unstable[_-]?oauth[_-]?client[_-]?secret(=| =|:| :)",
	"credentials-disclosure[452]":   "gh[_-]?oauth[_-]?client[_-]?secret(=| =|:| :)",
	"credentials-disclosure[453]":   "gh[_-]?next[_-]?unstable[_-]?oauth[_-]?client[_-]?secret(=| =|:| :)",
	"credentials-disclosure[454]":   "gh[_-]?next[_-]?unstable[_-]?oauth[_-]?client[_-]?id(=| =|:| :)",
	"credentials-disclosure[455]":   "gh[_-]?next[_-]?oauth[_-]?client[_-]?secret(=| =|:| :)",
	"credentials-disclosure[458]":   "gcs[_-]?bucket(=| =|:| :)",
	"credentials-disclosure[461]":   "gcloud[_-]?project(=| =|:| :)",
	"credentials-disclosure[462]":   "gcloud[_-]?bucket(=| =|:| :)",
	"credentials-disclosure[463]":   "ftp[_-]?username(=| =|:| :)",
	"credentials-disclosure[464]":   "ftp[_-]?user(=| =|:| :)",
	"credentials-disclosure[465]":   "ftp[_-]?pw(=| =|:| :)",
	"credentials-disclosure[467]":   "ftp[_-]?login(=| =|:| :)",
	"credentials-disclosure[468]":   "ftp[_-]?host(=| =|:| :)",
	"credentials-disclosure[470]":   "flickr[_-]?api[_-]?secret(=| =|:| :)",
	"credentials-disclosure[473]":   "firefox[_-]?secret(=| =|:| :)",
	"credentials-disclosure[475]":   "firebase[_-]?project[_-]?develop(=| =|:| :)",
	"credentials-disclosure[478]":   "firebase[_-]?api[_-]?json(=| =|:| :)",
	"credentials-disclosure[484]":   "env[_-]?secret(=| =|:| :)",
	"credentials-disclosure[491]":   "elastic[_-]?cloud[_-]?auth(=| =|:| :)",
	"credentials-disclosure[493]":   "dsonar[_-]?login(=| =|:| :)",
	"credentials-disclosure[495]":   "dropbox[_-]?oauth[_-]?bearer(=| =|:| :)",
	"credentials-disclosure[500]":   "docker[_-]?postgres[_-]?url(=| =|:| :)",
	"credentials-disclosure[510]":   "deploy[_-]?user(=| =|:| :)",
	"credentials-disclosure[512]":   "deploy[_-]?secure(=| =|:| :)",
	"credentials-disclosure[517]":   "db[_-]?username(=| =|:| :)",
	"credentials-disclosure[518]":   "db[_-]?user(=| =|:| :)",
	"credentials-disclosure[519]":   "db[_-]?pw(=| =|:| :)",
	"credentials-disclosure[521]":   "db[_-]?host(=| =|:| :)",
	"credentials-disclosure[522]":   "db[_-]?database(=| =|:| :)",
	"credentials-disclosure[523]":   "db[_-]?connection(=| =|:| :)",
	"credentials-disclosure[526]":   "database[_-]?username(=| =|:| :)",
	"credentials-disclosure[527]":   "database[_-]?user(=| =|:| :)",
	"credentials-disclosure[528]":   "database[_-]?port(=| =|:| :)",
	"credentials-disclosure[530]":   "database[_-]?name(=| =|:| :)",
	"credentials-disclosure[531]":   "database[_-]?host(=| =|:| :)",
	"credentials-disclosure[538]":   "cos[_-]?secrets(=| =|:| :)",
	"credentials-disclosure[539]":   "conversation[_-]?username(=| =|:| :)",
	"credentials-disclosure[561]":   "clu[_-]?repo[_-]?url(=| =|:| :)",
	"credentials-disclosure[562]":   "cloudinary[_-]?url[_-]?staging(=| =|:| :)",
	"credentials-disclosure[563]":   "cloudinary[_-]?url(=| =|:| :)",
	"credentials-disclosure[568]":   "cloudant[_-]?service[_-]?database(=| =|:| :)",
	"credentials-disclosure[569]":   "cloudant[_-]?processed[_-]?database(=| =|:| :)",
	"credentials-disclosure[571]":   "cloudant[_-]?parsed[_-]?database(=| =|:| :)",
	"credentials-disclosure[572]":   "cloudant[_-]?order[_-]?database(=| =|:| :)",
	"credentials-disclosure[573]":   "cloudant[_-]?instance(=| =|:| :)",
	"credentials-disclosure[574]":   "cloudant[_-]?database(=| =|:| :)",
	"credentials-disclosure[575]":   "cloudant[_-]?audited[_-]?database(=| =|:| :)",
	"credentials-disclosure[576]":   "cloudant[_-]?archived[_-]?database(=| =|:| :)",
	"credentials-disclosure[579]":   "client[_-]?secret(=| =|:| :)",
	"credentials-disclosure[582]":   "claimr[_-]?superuser(=| =|:| :)",
	"credentials-disclosure[583]":   "claimr[_-]?db(=| =|:| :)",
	"credentials-disclosure[584]":   "claimr[_-]?database(=| =|:| :)",
	"credentials-disclosure[586]":   "ci[_-]?server[_-]?name(=| =|:| :)",
	"credentials-disclosure[587]":   "ci[_-]?registry[_-]?user(=| =|:| :)",
	"credentials-disclosure[588]":   "ci[_-]?project[_-]?url(=| =|:| :)",
	"credentials-disclosure[594]":   "censys[_-]?secret(=| =|:| :)",
	"credentials-disclosure[596]":   "cattle[_-]?agent[_-]?instance[_-]?auth(=| =|:| :)",
	"credentials-disclosure[600]":   "bx[_-]?username(=| =|:| :)",
	"credentials-disclosure[609]":   "bluemix[_-]?username(=| =|:| :)",
	"credentials-disclosure[610]":   "bluemix[_-]?pwd(=| =|:| :)",
	"credentials-disclosure[614]":   "bluemix[_-]?auth(=| =|:| :)",
	"credentials-disclosure[622]":   "b2[_-]?bucket(=| =|:| :)",
	"credentials-disclosure[630]":   "aws[_-]?secrets(=| =|:| :)",
	"credentials-disclosure[633]":   "aws[_-]?secret(=| =|:| :)",
	"credentials-disclosure[639]":   "aws[_-]?access(=| =|:| :)",
	"credentials-disclosure[642]":   "auth0[_-]?client[_-]?secret(=| =|:| :)",
	"credentials-disclosure[643]":   "auth0[_-]?api[_-]?clientsecret(=| =|:| :)",
	"credentials-disclosure[647]":   "artifacts[_-]?secret(=| =|:| :)",
	"credentials-disclosure[649]":   "artifacts[_-]?bucket(=| =|:| :)",
	"credentials-disclosure[655]":   "appclientsecret(=| =|:| :)",
	"credentials-disclosure[657]":   "app[_-]?secrete(=| =|:| :)",
	"credentials-disclosure[659]":   "app[_-]?bucket[_-]?perm(=| =|:| :)",
	"credentials-disclosure[662]":   "api[_-]?secret(=| =|:| :)",
	"credentials-disclosure[666]":   "aos[_-]?sec(=| =|:| :)",
	"credentials-disclosure[672]":   "amazon[_-]?bucket[_-]?name(=| =|:| :)",

	"credentials-disclosure[690]": `\b\w*[sS][eE][cC][rR][eE][tT]\b(=| =|:| :)\s*([\w\d\-@+"']{8,})`,
	"credentials-disclosure[693]": `\b\w*[tT][oO][kK][eE][nN]\b(=| =|:| :)\s*([\w\d\-@+"']{8,})`,
	"credentials-disclosure[694]": `\b\w*[pP][aA][sS][sS]\b(=| =|:| :)\s*([\w\d\-@+"']{8,})`,
	"credentials-disclosure[695]": `\b\w*[kK][eE][yY]\b(=| =|:| :)\s*([\w\d\-@+"']{8,})`,
	"credentials-disclosure[696]": `\b\w*[pP][aA][sS][sS][wW][oO][rR][dD]\b(=| =|:| :)\s*([\w\d\-@+"']{8,})`,
	"credentials-disclosure[697]": `\b\w*[eE][mM][aA][iI][lL]\b(=| =|:| :)\s*([\w\d\-@+"']{8,})`,
}
