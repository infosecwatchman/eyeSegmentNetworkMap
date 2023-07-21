package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"github.com/Jeffail/gabs/v2"
	"github.com/cheggaaa/pb/v3"
	"github.com/infosecwatchman/eyeSegmentAPI/eyeSegmentAPI"
	"golang.org/x/exp/slices"
	"io"
	"log"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type edge struct {
	num         int
	From        string        `json:"from"`
	To          string        `json:"to"`
	ID          string        `json:"id"`
	Connections []connectData `json:"connections"`
}

type connectData struct {
	NumOfConnections int    `json:"#Connections"`
	First_Seen       string `json:"First_Seen"`
	Last_Seen        string `json:"Last_Seen"`
	Port             int    `json:"Port"`
	Protocol         string `json:"Protocol"`
	Service_Name     string `json:"Service_Name"`
}

func DataStream() string {
	log.Println("Running DataStream")
	MatrixData := gabs.New()
	dataContainer, err := gabs.ParseJSON(eyeSegmentAPI.GetMatrixData())
	if err != nil {
		log.Println(err)
	}
	var columnNamesMaster []string
	var concatenatedData [][]string
	if dataContainer.ExistsP("data.0.srcZone") {
		waitgroup := sync.WaitGroup{}
		for count, data := range dataContainer.S("data").Children() {
			waitgroup.Add(1)
			go func(data *gabs.Container, count int) {
				defer waitgroup.Done()
				CSVData := eyeSegmentAPI.GetCSVData(trimQuote(data.S("srcZone").String()), trimQuote(data.S("dstZone").String()))
				csvdata := csv.NewReader(CSVData)
				records, err := csvdata.ReadAll()
				if err != nil {
					log.Fatalln(err)
				}

				for rownum, row := range records {
					if rownum == 0 {
						if len(columnNamesMaster) == 0 {
							columnNamesMaster = row
						} else {
							for columnNum, cell := range row {
								if !slices.Contains(columnNamesMaster, cell) {
									if strings.Contains(cell, "Level") {
										level, _ := strconv.Atoi(strings.Split(cell, "Level_")[1])
										index := slices.Index(columnNamesMaster, fmt.Sprintf("%sLevel_%d", strings.Split(cell, "Level_")[0], level-1))
										columnNamesMaster = slices.Insert(columnNamesMaster, index+1, cell)
									} else {
										columnNamesMaster[columnNum] = cell
									}
								}
							}
						}
						break
					}
				}
			}(data, count)
		}
		waitgroup.Wait()
		fmt.Println(columnNamesMaster)
		bar := pb.StartNew(len(dataContainer.S("data").Children())).SetTemplate(pb.Simple).SetRefreshRate(100 * time.Millisecond)
		for count, data := range dataContainer.S("data").Children() {
			waitgroup.Add(1)
			go func(data *gabs.Container, count int) {
				defer waitgroup.Done()
				CSVData := eyeSegmentAPI.GetCSVData(trimQuote(data.S("srcZone").String()), trimQuote(data.S("dstZone").String()))
				csvdata := csv.NewReader(CSVData)
				records, err := csvdata.ReadAll()
				if err != nil {
					log.Fatalln(err)
				}
				columnNamesTemp := make([]string, len(columnNamesMaster))
				for rownum, row := range records {
					if rownum == 0 {
						columnNamesTemp = row
					} else {
						temprow := make([]string, len(columnNamesMaster))
						for cellColumnNum, cell := range row {
							temprow = slices.Insert(temprow, slices.Index(columnNamesMaster, columnNamesTemp[cellColumnNum]), cell)
						}
						concatenatedData = append(concatenatedData, temprow)
					}
				}
				//tracker++
				//fmt.Printf("Added %s to %s ||| %d out of %d complete.\n", trimQuote(data.S("srcZone").String()), trimQuote(data.S("dstZone").String()), tracker, len(dataContainer.S("data").Children()))
				bar.Increment()
			}(data, count)
		}
		waitgroup.Wait()
		for i := 0; i <= 50; i++ {
			if bar.Current() == int64(len(dataContainer.S("data").Children())) {
				bar.Finish()
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		var buffer bytes.Buffer
		/*
			fmt.Println("Creating file.")
			file, err := os.Create("result.csv")
			if err != nil {
				log.Fatal(err)
			}
			defer file.Close()
		*/
		csvData := csv.NewWriter(&buffer)
		//defer csvData.Flush()
		fmt.Println("writing headers")
		err = csvData.Write(columnNamesMaster)
		if err != nil {
			fmt.Println(err)
		}
		for _, rows := range concatenatedData {
			if len(columnNamesMaster) > len(rows) {
				runtimes := 0
				for runtimes == (len(columnNamesMaster) - len(rows)) {
					fmt.Printf("looping %d", runtimes)
					rows = append(rows, "")
					runtimes++
				}
			}
			//fmt.Println("writing line")
			err = csvData.Write(rows)
			if err != nil {
				fmt.Println(err)
			}
		}
		csvData.Flush()
		if err := csvData.Error(); err != nil {
			panic(err)
		}
		start := time.Now()
		MatrixData = CSVtoJSON(strings.NewReader(buffer.String()))
		fmt.Printf("Converting JSON: %s\n", time.Since(start))
	}
	fmt.Println("exiting Datastream function.")
	//fmt.Println(MatrixData.String())

	return strings.ReplaceAll(MatrixData.String(), `\"`, "")
}

func trimQuote(s string) string {
	if len(s) > 0 && s[0] == '"' {
		s = s[1:]
	}
	if len(s) > 0 && s[len(s)-1] == '"' {
		s = s[:len(s)-1]
	}
	return s
}

func CSVtoJSON(importcsvdata io.Reader) *gabs.Container {
	csvdata := csv.NewReader(importcsvdata)
	csvdata.FieldsPerRecord = -1
	records, err := csvdata.ReadAll()
	if err != nil {
		log.Fatalln(err)
	}
	fulljson := gabs.New()
	fulljson.Array("edges")
	fulljson.Array("nodes")
	var edges []edge
	var headers []string
	waitgroup := sync.WaitGroup{}
	for rownum, row := range records {
		//fmt.Printf("%d: %s\n", row, record)
		if rownum == 0 {
			headers = row
		} else {
			jsonSRCNodePart := gabs.New()
			jsonDSTNodePart := gabs.New()
			jsonEdgePart := gabs.New()
			connectionData := gabs.New()
			connectionData.Array("connectionData")
			for fieldnum, field := range row {
				tempsrcjson := gabs.New()
				tempdstjson := gabs.New()
				for columnnum, column := range headers {
					waitgroup.Add(1)
					go func(columnnum int, column string, headers []string) {
						var m sync.Mutex
						defer waitgroup.Done()
						if columnnum == fieldnum {
							if strings.Contains(column, "Source") {
								if !strings.Contains(column, "IP") || !strings.Contains(column, "DNS") {
									m.Lock()
									tempsrcjson.Set(field, strings.ReplaceAll(column, "Source_", ""))
									m.Unlock()
								}
							}
							if strings.Contains(column, "Destination") {
								if !strings.Contains(column, "IP") || !strings.Contains(column, "DNS") {
									m.Lock()
									tempdstjson.Set(field, strings.ReplaceAll(column, "Destination_", ""))
									m.Unlock()
								}
							}
						}
					}(columnnum, column, headers)
				}
				for columnnum, column := range headers {
					waitgroup.Add(1)
					go func(columnnum int, column string, headers []string) {
						var m sync.Mutex
						defer waitgroup.Done()
						if columnnum == fieldnum {
							if column == "Source_IP" {
								regex, _ := regexp.Compile(fmt.Sprintf(`"id":"%s"`, field))
								m.Lock()
								if !regex.MatchString(fulljson.Search("nodes").String()) {
									jsonDSTNodePart.Set(field, "id")
								}
								m.Unlock()
							}
							if column == "Destination_IP" {
								regex, _ := regexp.Compile(fmt.Sprintf(`"id":"%s"`, field))
								m.Lock()
								if !regex.MatchString(fulljson.Search("nodes").String()) {
									jsonSRCNodePart.Set(field, "id")
								}
								m.Unlock()
							}
							if column == "Source_IP" {
								m.Lock()
								jsonEdgePart.Set(field, "from")
								m.Unlock()
							}
							if column == "Destination_IP" {
								m.Lock()
								jsonEdgePart.Set(field, "to")
								m.Unlock()
							}
							if !strings.Contains(column, "Destination") && !strings.Contains(column, "Source") {
								m.Lock()
								jsonEdgePart.Set(field, column)
								m.Unlock()
							}

						}
					}(columnnum, column, headers)
				}
				waitgroup.Wait()
				jsonDSTNodePart.Merge(tempsrcjson)
				jsonSRCNodePart.Merge(tempdstjson)
			}
			from := jsonEdgePart.S("from").Data()
			to := jsonEdgePart.S("to").Data()
			id := fmt.Sprintf("%s%s", jsonEdgePart.S("to").Data(), jsonEdgePart.S("from").Data())

			connectionData.Set(from, "from")
			connectionData.Set(to, "to")
			connectionData.Set(id, "id")
			jsonEdgePart.Delete("from")
			jsonEdgePart.Delete("to")
			connectionData.ArrayAppend(jsonEdgePart, "connectionData")

			regex, _ := regexp.Compile(`"id"`)
			if regex.MatchString(jsonSRCNodePart.String()) {
				fulljson.ArrayAppend(jsonSRCNodePart, "nodes")
			}
			if regex.MatchString(jsonDSTNodePart.String()) {
				fulljson.ArrayAppend(jsonDSTNodePart, "nodes")
			}

			IdRegex, _ := regexp.Compile(fmt.Sprintf(`"id":"%s"`, id))
			compiledJson, _ := json.Marshal(edges)
			if !IdRegex.MatchString(string(compiledJson)) {
				var newedge edge
				newedge.ID = trimQuote(connectionData.S("id").String())
				newedge.From = trimQuote(connectionData.S("from").String())
				newedge.To = trimQuote(connectionData.S("to").String())
				NumofConnections, _ := strconv.Atoi(trimQuote(jsonEdgePart.S("#Connections").String()))
				port, _ := strconv.Atoi(trimQuote(jsonEdgePart.S("Port").String()))
				newedge.Connections = append(newedge.Connections, connectData{
					NumOfConnections: NumofConnections,
					First_Seen:       trimQuote(jsonEdgePart.S("First_Seen").String()),
					Last_Seen:        trimQuote(jsonEdgePart.S("Last_Seen").String()),
					Port:             port,
					Protocol:         trimQuote(jsonEdgePart.S("Protocol").String()),
					Service_Name:     trimQuote(jsonEdgePart.S("Service_Name").String()),
				})
				edges = append(edges, newedge)
			} else {
				for edgeID, edge := range edges {
					if edge.ID == id {
						var newConnection connectData
						NumofConnections, _ := strconv.Atoi(trimQuote(jsonEdgePart.S("#Connections").String()))
						port, _ := strconv.Atoi(trimQuote(jsonEdgePart.S("Port").String()))
						newConnection = connectData{
							NumOfConnections: NumofConnections,
							First_Seen:       trimQuote(jsonEdgePart.S("First_Seen").String()),
							Last_Seen:        trimQuote(jsonEdgePart.S("Last_Seen").String()),
							Port:             port,
							Protocol:         trimQuote(jsonEdgePart.S("Protocol").String()),
							Service_Name:     trimQuote(jsonEdgePart.S("Service_Name").String()),
						}
						edges[edgeID].Connections = append(edges[edgeID].Connections, newConnection)
					}
				}
			}
		}
	}
	jsonByte, _ := json.Marshal(edges)
	compiledJson, _ := gabs.ParseJSON(jsonByte)
	fulljson.Set(compiledJson, "edges")
	return fulljson
}
