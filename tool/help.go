package main

var (
	usageHelpMsg = `Command line interface for JinYu(jy).

Usage:
    jy [commands] [options]
    
Commands:
    -g, --get [get-type] [parameters]        get different type of infomations

Get-type:
	port_mask				 Port/Mask of input
	hex						 Hex
	dec					     Decimal


Parameters and options:
    -h, --help                 Help messages of cnatcli
	-r, --right				   Right of []
	-l, --left				   Left  of []
	-num,--number			   Number
	-ip						   IP

Use 'jy command --help' for information about that command.
`
	errHelpMsg = `Invalid command or args. Run 'jy --help' for usage.`

	infoHelper = `
	示例:
		1: 生成端口掩码形式
		jy -g port_mask -l 100 -r 200 
`

	portMaskHelp = `-g port_mask 生成-l和-r 端口掩码列表
	示例:
		jy -g port_mask -l 100 -r 200 
	`
	hexHelp = `-g hex 获取十六进制显示信息
	示例:
		jy -g hex -ip 192.168.1.2	

		jy -g hex -num 1000
	`
	decHelp = `-g dec 获取十进制显示信息
	示例:
		jy -g dec -ip 192.168.1.2

		jy -g dec -num 0x10101010
	`
)
