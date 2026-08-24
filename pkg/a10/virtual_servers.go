package a10

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
)

// VirtualServer is the secret-free TLS attachment subset of an ACOS SLB
// virtual server.
type VirtualServer struct {
	Name        VirtualServerName `json:"name"`
	IPAddress   string            `json:"ip-address,omitempty"`
	IPv6Address string            `json:"ipv6-address,omitempty"`
	Ports       []VirtualPort     `json:"port-list,omitempty"`
}

// VirtualPort describes the client-SSL templates attached to one ACOS virtual
// port. ACOS represents local and shared-partition references separately.
type VirtualPort struct {
	Number                  uint16                `json:"port-number"`
	Protocol                string                `json:"protocol"`
	ClientSSLTemplate       ClientSSLTemplateName `json:"template-client-ssl,omitempty"`
	SharedClientSSLTemplate ClientSSLTemplateName `json:"template-client-ssl-shared,omitempty"`
}

// VirtualServerTLSBinding identifies where a client-SSL template is served.
type VirtualServerTLSBinding struct {
	VirtualServer           VirtualServerName     `json:"virtualServer"`
	Address                 string                `json:"address"`
	Port                    uint16                `json:"port"`
	Protocol                string                `json:"protocol"`
	ClientSSLTemplate       ClientSSLTemplateName `json:"clientSSLTemplate"`
	SharedPartitionTemplate bool                  `json:"sharedPartitionTemplate"`
}

// ListVirtualServers returns the typed TLS attachment inventory without
// exposing unrelated virtual-server configuration.
func (s *Session) ListVirtualServers(ctx context.Context) ([]VirtualServer, error) {
	var document struct {
		VirtualServers []VirtualServer `json:"virtual-server-list"`
	}
	if err := s.doJSON(ctx, http.MethodGet, "/slb/virtual-server", nil, &document, http.StatusOK); err != nil {
		return nil, err
	}
	return document.VirtualServers, nil
}

// FindClientSSLTemplatesByVIP resolves every local or shared client-SSL
// template attached to an exact IPv4 or IPv6 virtual address.
func (s *Session) FindClientSSLTemplatesByVIP(ctx context.Context, address string) ([]VirtualServerTLSBinding, error) {
	wanted, err := netip.ParseAddr(address)
	if err != nil {
		return nil, fmt.Errorf("invalid VIP address %q: %w", address, err)
	}
	virtualServers, err := s.ListVirtualServers(ctx)
	if err != nil {
		return nil, err
	}
	var result []VirtualServerTLSBinding
	for _, virtualServer := range virtualServers {
		configuredAddress := virtualServer.IPAddress
		if configuredAddress == "" {
			configuredAddress = virtualServer.IPv6Address
		}
		parsed, parseErr := netip.ParseAddr(configuredAddress)
		if parseErr != nil || parsed != wanted {
			continue
		}
		for _, port := range virtualServer.Ports {
			template := port.ClientSSLTemplate
			shared := false
			if template == "" {
				template = port.SharedClientSSLTemplate
				shared = template != ""
			}
			if template == "" {
				continue
			}
			result = append(result, VirtualServerTLSBinding{
				VirtualServer: virtualServer.Name, Address: configuredAddress,
				Port: port.Number, Protocol: port.Protocol,
				ClientSSLTemplate: template, SharedPartitionTemplate: shared,
			})
		}
	}
	return result, nil
}
