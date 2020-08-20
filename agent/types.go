package agent

type ErrorResponse struct {
	Code  int    `json:"code"`
	Error string `json:"error"`
}

type InterfaceUpRequest struct {
	Name     string `json:"name"`
	Network  string `json:"network"`
	Endpoint string `json:"endpoint,omitempty"`
}

func (r *InterfaceUpRequest) Valid() error {
	return nil
}

type InterfaceUpResponse struct {
}
