package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/infosecwatchman/eyeSegmentAPI/eyeSegmentAPI"
	"html/template"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

type Response struct {
	Srcgrp string //`json:"srcgrp"`
	Dstgrp string //`json:"dstgrp"`
	Srcip  string //`json:"srcip"`
	Dstip  string //`json:"dstip"`
	//Srcnet string //`json:"srcnet"`
	//Dstnet string //`json:"dstnet"`
	TimeFilter int
}

var templates *template.Template

func indexPage(w http.ResponseWriter, r *http.Request) {
	//splits out the port number
	addr := strings.Split(r.RemoteAddr, ":")[0]
	// basically checks for localhost which defaults to ipv6 and returns this bracket
	if addr == "[" {
		addr = "10.9.9.42"
	}
	varmap := map[string]interface{}{
		"SOURCE_IP": addr,
	}
	templates.ExecuteTemplate(w, "index.html", varmap)
}

func testDataPage(w http.ResponseWriter, r *http.Request) {
	file, _ := template.ParseGlob("./data.json")
	file.ExecuteTemplate(w, "data.json", nil)
}

func dataPage(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s accessing /data", r.RemoteAddr)
	fmt.Fprint(w, DataStream())
}

func FSAuth(host, username, password string) bool {
	eyeSegmentAPI.FSusername = username
	eyeSegmentAPI.FSApplianceFQDN = host
	eyeSegmentAPI.FSpassword = password
	eyeSegmentAPI.FSLogin()
	return eyeSegmentAPI.ConnectTest()
}

func basicAuth(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if ok {
			if !eyeSegmentAPI.ConnectTest() {
				if FSAuth(eyeSegmentAPI.FSApplianceFQDN, username, password) {
					//log.Printf("JSESSIONID: %s, XSRFTOKEN: %s", JSESSIONID, XSRFTOKEN)
					next.ServeHTTP(w, r)
					return
				}
			} else {
				next.ServeHTTP(w, r)
				return
			}
		}

		w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})
}

func Query(w http.ResponseWriter, r *http.Request) {
	var response Response

	payload := `{"srcZones":["1srcZone"],"dstZones":["1dstZone"],"services":[],"isExclude":false,"protocols":[],"srcIp":"1srcIp","dstIp":"1dstIp","hasFilters":true,"filterEnabled":true,"confidence":null}`

	body, _ := io.ReadAll(r.Body)
	err := json.Unmarshal(body, &response)
	if err != nil {
		log.Println(err)
	}
	//var source, destination bool
	log.Println(response)

	if len(response.Srcgrp) != 0 {
		payload = strings.ReplaceAll(payload, "1srcZone", eyeSegmentAPI.GetZoneID(response.Srcgrp)) // GetZoneID(response.Srcgrp))
	}
	if len(response.Srcip) != 0 {
		payload = strings.ReplaceAll(payload, "1srcIp", response.Srcip)
	}
	//if len(response.Srcnet) != 0 {}

	if len(response.Dstgrp) != 0 {
		payload = strings.ReplaceAll(payload, "1dstZone", eyeSegmentAPI.GetZoneID(response.Dstgrp))
	}
	if len(response.Dstip) != 0 {
		payload = strings.ReplaceAll(payload, "1dstIp", response.Dstip)
	}
	payload = strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(payload, "1dstIp", ""), `"1dstZone"`, ""), "1srcIp", ""), `"1srcZone"`, "")
	//if len(response.Dstnet) != 0 {}

	if response.TimeFilter != 3 {
		eyeSegmentAPI.TimeBasedFilter(response.TimeFilter)
	}
	log.Println(payload)
	eyeSegmentAPI.SetFilter(payload)
	fmt.Println(eyeSegmentAPI.GetFilter())
	/*
		dataContainer, err := gabs.ParseJSON(eyeSegmentAPI.GetMatrixData())
		if err != nil {
			log.Println(err)
		}
		for _, data := range dataContainer.S("data").Children() {
			log.Println(data.Data())
		}
	*/
	fmt.Fprint(w, eyeSegmentAPI.GetFilter())
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	//log.Println("hello")
	FSFQDN := flag.String("t", "", "FQDN of Forescout Appliance")
	test := flag.Bool("t1", false, "Test function")
	flag.Parse()
	if *test {
		return
	} else if *FSFQDN == "" {
		log.Println("No Forescout Appliance target given, please provide FQDN of the target server.")
		flag.PrintDefaults()
		return
	}
	eyeSegmentAPI.FSApplianceFQDN = *FSFQDN
	templates = template.Must(templates.ParseGlob("templates/*.html"))
	r := mux.NewRouter()
	//r.HandleFunc("/", basicAuth(indexPage)).Methods("GET")
	r.HandleFunc("/", indexPage).Methods("GET")
	r.HandleFunc("/data", basicAuth(dataPage)).Methods("GET")
	r.HandleFunc("/data.json", testDataPage).Methods("GET")
	r.HandleFunc("/query", basicAuth(Query)).Methods("POST")
	http.Handle("/query", r)
	http.Handle("/data.json", r)
	http.Handle("/data", r)
	http.Handle("/", r)
	srv := &http.Server{
		Addr:         ":8000",
		Handler:      r,
		IdleTimeout:  time.Minute,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	log.Printf("starting server on %s", srv.Addr)
	err := srv.ListenAndServeTLS("./certs/localhost.pem", "./certs/localhost-key.pem")
	log.Fatal(err)

}
