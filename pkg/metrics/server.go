package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"
)

func RunServer() {
	log.Info().Msg("metrics on ':9090/metrics'")
	http.Handle("/metrics", promhttp.Handler())
	http.ListenAndServe(":9090", nil)
}
