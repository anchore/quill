package extract

import (
	"encoding/json"
	"strings"
)

type MachoDetails struct {
	Magic            string   `json:"magic"`
	Type             string   `json:"type"`
	CPU              string   `json:"cpu"`
	SubCPU           string   `json:"subcpu"`
	Flags            []string `json:"flags"`
	Libs             []string `json:"libs"`
	LoadCommandCount uint32   `json:"loadCommandsCount"`
	LoadCommandSize  uint32   `json:"loadCommandSize"`
	UUID             string   `json:"uuid"`
}

func getMachoDetails(m File) MachoDetails {
	var uuidStr string
	uuidVal := m.blacktopFile.UUID()
	if uuidVal != nil {
		uuidStr = uuidVal.String()
	}
	return MachoDetails{
		Magic:            m.blacktopFile.Magic.String(),
		Type:             m.blacktopFile.Type.String(),
		CPU:              m.blacktopFile.CPU.String(),
		SubCPU:           m.blacktopFile.SubCPU.String(m.blacktopFile.CPU),
		Flags:            m.blacktopFile.Flags.Flags(),
		Libs:             m.blacktopFile.ImportedLibraries(),
		LoadCommandCount: m.blacktopFile.NCommands,
		LoadCommandSize:  m.blacktopFile.SizeCommands,
		UUID:             uuidStr,
	}
}

func (m MachoDetails) String() (r string) {
	libBytes, err := json.MarshalIndent(m.Libs, "  ", "  ")
	if err != nil {
		// TODO: no
		panic(err)
	}
	return tprintf(
		`Magic:        {{.Magic}}
Type:         {{.Type}}
CPU:          {{.CPU}} ({{.SubCPU}})
Flags:        {{.FormattedFlags}}
Libraries:    {{.FormattedLibs}}
LoadCommands: {{.LoadCommandCount}}
UUID:         {{.UUID}}
`,
		struct {
			MachoDetails
			FormattedFlags string
			FormattedLibs  string
			Indent         string
		}{
			MachoDetails:   m,
			FormattedFlags: strings.Join(m.Flags, ", "),
			FormattedLibs:  string(libBytes),
		},
	)
}
