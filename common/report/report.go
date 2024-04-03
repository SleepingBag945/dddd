package report

import (
	"dddd/ddout"
	"dddd/structs"
	"encoding/json"
	"fmt"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"os"
	"strconv"
	"strings"
	"time"
)

func getSeverity(s severity.Severity) string {
	if s == severity.Info {
		return "Info"
	} else if s == severity.Low {
		return "Low"
	} else if s == severity.Medium {
		return "Medium"
	} else if s == severity.High {
		return "High"
	} else if s == severity.Critical {
		return "Critical"
	} else if s == severity.Unknown {
		return "Unknown"
	}
	return "Unknown"
}

func writeFile(result string, filename string) {
	var text = []byte(result)
	fl, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		fmt.Printf("Open %s error, %v\n", filename, err)
		return
	}
	_, err = fl.Write(text)
	fl.Close()
	if err != nil {
		fmt.Printf("Write %s error, %v\n", filename, err)
	}
}

var ReportIndex = 1

func GenerateHTMLReportHeader() {
	if structs.GlobalConfig.ReportName == "" {
		structs.GlobalConfig.ReportName = strconv.Itoa(int(time.Now().Unix())) + ".html"
	}
	showData := defaultHeader()
	writeFile(showData, structs.GlobalConfig.ReportName)
}

func AddResultByResultEvent(result output.ResultEvent) {
	if structs.GlobalConfig.ReportName == "" {
		return
	}

	b, e := json.Marshal(result)
	if e == nil {
		show := fmt.Sprintf("[%s] [%s] %v", result.TemplateID,
			result.Info.SeverityHolder.Severity.String(),
			result.Matched)
		ddout.FormatOutput(ddout.OutputMessage{
			Type:   "Nuclei",
			Nuclei: string(b),
			Show:   show,
		})
	}

	severityString := getSeverity(result.Info.SeverityHolder.Severity)

	title := fmt.Sprintf(`<table>
	<thead onclick="$(this).next('tbody').toggle()" style="background:#000000">
		<td class="vuln">%v&nbsp;&nbsp;%s</td>
		<td class="security %s">%s</td>
		<td class="url">%s</td>
	</thead>`, ReportIndex, result.TemplateID, strings.ToLower(severityString), strings.ToUpper(severityString), result.Host)

	info := fmt.Sprintf("<b>name:</b> %s&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<b>author:</b> %s&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<b>security:</b> %s",
		result.Info.Name, result.Info.Authors.String(), severityString,
	)
	if len(result.Info.Description) > 0 {
		info += "<br/><b>description:</b> " + result.Info.Description
	}

	if result.Info.Reference != nil && len(result.Info.Reference.ToSlice()) > 0 {
		info += "<br/><b>reference:</b> "
		for _, rv := range result.Info.Reference.ToSlice() {
			info += "<br/>&nbsp;&nbsp;- <a href='" + rv + "' target='_blank'>" + rv + "</a>"
		}
	}

	header := "<tbody>"

	bodyinfo := fmt.Sprintf(`<tr>
			<td colspan="3">%s</td>
		</tr>`, info)

	fullurl := xssfilter(result.Matched)

	footer := "</tbody></table>"
	d := title + header + bodyinfo

	urlShow := `<tr>
		<td colspan="3"  style="border-top:1px solid #60786F"><a href="` + fullurl + `" target="_blank">` + fullurl + `</a></td>
	</tr><tr>`

	bodyHeader := `
			<td colspan="3" style="background: #1c1b19; color: #048d18;">
				<div class="clr">
				<div class="request w50">
				<div class="toggleR" onclick="$(this).parent().next('.response').toggle();if($(this).text()=='→'){$(this).text('←');$(this).css('background','red');$(this).parent().removeClass('w50').addClass('w100')}else{$(this).text('→');$(this).css('background','black');$(this).parent().removeClass('w100').addClass('w50')}">→</div>
<xmp>%s</xmp>
				</div>
				<div class="response w50">
				<div class="toggleL" onclick="$(this).parent().prev('.request').toggle();if($(this).text()=='←'){$(this).text('→');$(this).css('background','red');$(this).parent().removeClass('w50').addClass('w100')}else{$(this).text('←');$(this).css('background','black');$(this).parent().removeClass('w100').addClass('w50')}">←</div>
<xmp>%s</xmp>
				</div>
			</div>
			</td>
		</tr>
	`

	if len(result.Packet) == 0 {
		body := urlShow + fmt.Sprintf(bodyHeader, result.Request, result.Response)
		d += body
	} else {
		for index, v := range result.Packet {
			if index == 1 {
				d += urlShow
			} else {
				d += "<tr><td colspan=\"3\"  style=\"border-top:1px solid #60786F\"></td></tr>"
			}
			body := fmt.Sprintf(bodyHeader, v.Request, v.Response)
			d += body
		}
	}

	d += footer

	writeFile(d, structs.GlobalConfig.ReportName)

	ReportIndex += 1
}

func AddResultByGoPocResult(result structs.GoPocsResultType) {
	severityString := result.Security

	title := fmt.Sprintf(`<table>
	<thead onclick="$(this).next('tbody').toggle()" style="background:#000000">
		<td class="vuln">%v&nbsp;&nbsp;%s</td>
		<td class="security %s">%s</td>
		<td class="url">%s</td>
	</thead>`, ReportIndex, result.PocName, strings.ToLower(severityString), strings.ToUpper(severityString), result.Target)

	info := ""
	if result.Description != "" {
		info = "<br/><b>description:</b> " + result.Description
	}

	header := "<tbody>"

	bodyinfo := fmt.Sprintf(`<tr>
			<td colspan="3">%s</td>
		</tr>`, info)

	body := fmt.Sprintf(`<tr>
		<td colspan="3"  style="border-top:1px solid #60786F"><a href="%s" target="_blank">%s</a></td>
	</tr><tr>
			<td colspan="3" style="background: #1c1b19; color: #048d18;">
				<div class="clr">
				<div class="request w50">
				<div class="toggleR" onclick="$(this).parent().next('.response').toggle();if($(this).text()=='→'){$(this).text('←');$(this).css('background','red');$(this).parent().removeClass('w50').addClass('w100')}else{$(this).text('→');$(this).css('background','black');$(this).parent().removeClass('w100').addClass('w50')}">→</div>
<xmp>%s</xmp>
				</div>
				<div class="response w50">
				<div class="toggleL" onclick="$(this).parent().prev('.request').toggle();if($(this).text()=='←'){$(this).text('→');$(this).css('background','red');$(this).parent().removeClass('w50').addClass('w100')}else{$(this).text('←');$(this).css('background','black');$(this).parent().removeClass('w100').addClass('w50')}">←</div>
<xmp>%s</xmp>
				</div>
			</div>
			</td>
		</tr>
	`, result.Target, result.Target, xssfilter(result.InfoLeft), xssfilter(result.InfoRight))

	footer := "</tbody></table>"
	d := title + header + bodyinfo + body + footer
	writeFile(d, structs.GlobalConfig.ReportName)

	ReportIndex += 1
}
