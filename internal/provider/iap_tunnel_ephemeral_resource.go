// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"

	iap_tunnel "github.com/davidspek/terraform-provider-iap-tunnel/internal/iap-tunnel"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ ephemeral.EphemeralResource = &IapTunnelEphemeralResource{}
var _ ephemeral.EphemeralResourceWithConfigure = &IapTunnelEphemeralResource{}
var _ ephemeral.EphemeralResourceWithClose = &IapTunnelEphemeralResource{}
var _ ephemeral.EphemeralResourceWithValidateConfig = &IapTunnelEphemeralResource{}

func NewIapTunnelEphemeralResource() ephemeral.EphemeralResource {
	return &IapTunnelEphemeralResource{}
}

// IapTunnelEphemeralResource defines the ephemeral resource implementation.
type IapTunnelEphemeralResource struct {
	tunnelTracker *TunnelTracker
}

// IapTunnelEphemeralResourceModel describes the ephemeral resource data model.
type IapTunnelEphemeralResourceModel struct {
	Project    types.String `tfsdk:"project"`
	Zone       types.String `tfsdk:"zone"`
	Instance   types.String `tfsdk:"instance"`
	RemotePort types.Int32  `tfsdk:"remote_port"`
	Interface  types.String `tfsdk:"interface"`
	LocalPort  types.Int32  `tfsdk:"local_port"`
}

const (
	iapTunnelPrivateDataKey = "iapTunnel"
)

type IapTunnelPrivateData struct {
	ID string
}

func (r *IapTunnelEphemeralResource) Metadata(_ context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_tunnel"
}

func (r *IapTunnelEphemeralResource) Schema(ctx context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		// This description is used by the documentation generator and the language server.
		MarkdownDescription: "The IAP Tunnel ephemeral resource allows for the creation of tunnels to Google Cloud instances using Identity-Aware Proxy (IAP).",

		Attributes: map[string]schema.Attribute{
			"project": schema.StringAttribute{
				MarkdownDescription: "The Google Cloud project ID of the target instance.",
				Required:            true, // Ephemeral resources expect their dependencies to already exist.
			},
			"zone": schema.StringAttribute{
				Computed: false,
				// Sensitive:           true, // If applicable, mark the attribute as sensitive.
				Required:            true,
				MarkdownDescription: "The Google Cloud zone of the target instance.",
			},
			"instance": schema.StringAttribute{
				Computed: false,
				// Sensitive:           true, // If applicable, mark the attribute as sensitive.
				MarkdownDescription: "The name of the target instance.",
				Required:            true,
			},
			"remote_port": schema.Int32Attribute{
				Computed: false,
				// Sensitive:           true, // If applicable, mark the attribute as sensitive.
				MarkdownDescription: "The port on the target instance to tunnel to.",
				Required:            true,
			},
			"interface": schema.StringAttribute{
				Computed: false,
				// Sensitive:           true, // If applicable, mark the attribute as sensitive.
				MarkdownDescription: "The network interface to use for the tunnel.",
				Required:            false,
				Optional:            true,
			},
			"local_port": schema.Int32Attribute{
				Computed: false,
				// Sensitive:           true, // If applicable, mark the attribute as sensitive.
				MarkdownDescription: "The local port to bind the tunnel to.",
				Required:            true,
			},
		},
	}
}

func (r *IapTunnelEphemeralResource) Configure(ctx context.Context, req ephemeral.ConfigureRequest, resp *ephemeral.ConfigureResponse) {
	// Always perform a nil check when handling ProviderData because Terraform
	// sets that data after it calls the ConfigureProvider RPC.
	if req.ProviderData == nil {
		return
	}

	configData, ok := req.ProviderData.(*ProviderConfigData)

	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Ephemeral Resource Configure Type",
			fmt.Sprintf("Expected *ProviderConfigData, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)

		return
	}

	r.tunnelTracker = configData.Tracker
}

func (r *IapTunnelEphemeralResource) ValidateConfig(ctx context.Context, req ephemeral.ValidateConfigRequest, resp *ephemeral.ValidateConfigResponse) {
	var data IapTunnelEphemeralResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// for _, localPortForwarding := range data.LocalPortForwardings {
	// 	if !localPortForwarding.RetryDelay.IsNull() {
	// 		if _, err := time.ParseDuration(localPortForwarding.RetryDelay.ValueString()); err != nil {
	// 			resp.Diagnostics.AddError("Local Port Forwarding Error", fmt.Sprintf("Invalid retry delay: %s", err))
	// 		}
	// 	}
	// }
}

func (r *IapTunnelEphemeralResource) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var data IapTunnelEphemeralResourceModel

	// Read Terraform config data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	id := randSeq(8)
	tunnelInfo := &TunnelInfo{}

	b, err := json.Marshal(&IapTunnelPrivateData{ID: id})
	if err != nil {
		resp.Diagnostics.AddError("Private Data Error", fmt.Sprintf("Unable to marshal private data, got error: %s", err))
		return
	}
	resp.Private.SetKey(ctx, iapTunnelPrivateDataKey, b)

	// Start the tunnel
	m := &iap_tunnel.TunnelManager{
		Target: iap_tunnel.IapTunnelTarget{
			Project:   data.Project.String(),
			Zone:      data.Zone.String(),
			Instance:  data.Instance.String(),
			Interface: data.Interface.String(),
			Port:      int(data.RemotePort.ValueInt32()),
		},
		LocalPort: int(data.LocalPort.ValueInt32()),
	}
	tunnelInfo.manager = m

	err = m.StartProxy(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Tunnel Error", fmt.Sprintf("Failed to start tunnel: %s", err))
		return
	}
	tunnelInfo.listener = nil
	tunnelInfo.conn = nil

	r.tunnelTracker.Add(id, tunnelInfo)

	// Save data into ephemeral result data
	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)
}

func (r *IapTunnelEphemeralResource) closeByConnectionID(id string) diag.Diagnostics {
	diags := diag.Diagnostics{}

	tunnelInfo := r.tunnelTracker.Get(id)
	if tunnelInfo == nil {
		return diags
	}

	// if err := tunnelInfo.conn.Close(websocket.StatusNormalClosure, ""); err != nil {
	// 	diags.AddError("Failed to close connection", fmt.Sprintf("Failed to close connection: %v", err))
	// }

	// if err := tunnelInfo.listener.Close(); err != nil {
	// 	diags.AddError("Failed to close listener", fmt.Sprintf("Failed to close listener: %v", err))
	// }

	r.tunnelTracker.Remove(id)

	return diags
}

func (r *IapTunnelEphemeralResource) Close(ctx context.Context, req ephemeral.CloseRequest, resp *ephemeral.CloseResponse) {
	b, diags := req.Private.GetKey(ctx, iapTunnelPrivateDataKey)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	var privateData IapTunnelPrivateData
	if err := json.Unmarshal(b, &privateData); err != nil {
		resp.Diagnostics.AddError("Private Data Error", fmt.Sprintf("Unable to unmarshal private data, got error: %s", err))
		return
	}

	resp.Diagnostics.Append(r.closeByConnectionID(privateData.ID)...)
}

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.IntN(len(letters))]
	}
	return string(b)
}
