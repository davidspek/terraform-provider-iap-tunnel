// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

// Ensure ScaffoldingProvider satisfies various provider interfaces.
var _ provider.Provider = &IapTunnelProvider{}
var _ provider.ProviderWithEphemeralResources = &IapTunnelProvider{}

// var _ provider.ProviderWithFunctions = &IapTunnelProvider{}

// IapTunnelProvider defines the provider implementation.
type IapTunnelProvider struct {
	// version is set to the provider version on release, "dev" when the
	// provider is built and ran locally, and "test" when running acceptance
	// testing.
	version string
}

type ProviderConfigData struct {
	Tracker *TunnelTracker
}

// IapTunnelProviderModel describes the provider data model.
type IapTunnelProviderModel struct{}

func (p *IapTunnelProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "iap"
	resp.Version = p.version
}

func (p *IapTunnelProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		// Attributes: map[string]schema.Attribute{
		// 	"endpoint": schema.StringAttribute{
		// 		MarkdownDescription: "Example provider attribute",
		// 		Optional:            true,
		// 	},
		// },
	}
}

func (p *IapTunnelProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data IapTunnelProviderModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	config := &ProviderConfigData{
		Tracker: NewTunnelTracker(),
	}

	resp.EphemeralResourceData = config
}

func (p *IapTunnelProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{}
}

func (p *IapTunnelProvider) EphemeralResources(ctx context.Context) []func() ephemeral.EphemeralResource {
	return []func() ephemeral.EphemeralResource{
		NewIapTunnelEphemeralResource,
	}
}

func (p *IapTunnelProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{}
}

// func (p *IapTunnelProvider) Functions(ctx context.Context) []func() function.Function {
// 	return []func() function.Function{}
// }

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &IapTunnelProvider{
			version: version,
		}
	}
}
