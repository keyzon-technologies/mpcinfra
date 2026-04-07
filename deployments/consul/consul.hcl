server           = true
ui               = true
node_name        = "server-1"
bootstrap_expect = 1
client_addr      = "0.0.0.0"
data_dir         = "/consul/data"

ports {
  http  = 8500
  https = 8501
}

tls {
  defaults {
    cert_file        = "/tmp/certs/consul-server.pem"
    key_file         = "/tmp/certs/consul-server.key"
    ca_file          = "/tmp/certs/rootCA.pem"
    verify_outgoing  = true
    verify_incoming  = false
  }
}
