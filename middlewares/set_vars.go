package middlewares

var (
	appName          string
	accessManagerUrl string
)

func SetAppName(name string) {
	appName = name
}

func SetAccessManagerUrl(url string) {
	accessManagerUrl = url
}
