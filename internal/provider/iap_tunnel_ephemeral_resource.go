package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net"
	"time"

	iap_tunnel "github.com/davidspek/terraform-provider-iap-tunnel/internal/iap-tunnel"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
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
		MarkdownDescription: "The IAP Tunnel ephemeral resource allows for the creation of tunnels to Google Cloud instances using Identity-Aware Proxy (IAP).",
		Attributes: map[string]schema.Attribute{
			"project": schema.StringAttribute{
				MarkdownDescription: "The Google Cloud project ID of the target instance.",
				Required:            true,
			},
			"zone": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The Google Cloud zone of the target instance.",
			},
			"instance": schema.StringAttribute{
				MarkdownDescription: "The name of the target instance.",
				Required:            true,
			},
			"remote_port": schema.Int32Attribute{
				MarkdownDescription: "The port on the target instance to tunnel to.",
				Required:            true,
			},
			"interface": schema.StringAttribute{
				MarkdownDescription: "The network interface to use for the tunnel.",
				Optional:            true,
			},
			"local_port": schema.Int32Attribute{
				MarkdownDescription: "The local port to bind the tunnel to.",
				Required:            true,
			},
		},
	}
}

func (r *IapTunnelEphemeralResource) Configure(ctx context.Context, req ephemeral.ConfigureRequest, resp *ephemeral.ConfigureResponse) {
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
}

func (r *IapTunnelEphemeralResource) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var data IapTunnelEphemeralResourceModel
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

	// target := iap_tunnel.TunnelTarget{
	// 	Project:   data.Project.String(),
	// 	Zone:      data.Zone.String(),
	// 	Instance:  data.Instance.String(),
	// 	Interface: data.Interface.String(),
	// 	Port:      int(data.RemotePort.ValueInt32()),
	// }
	target := iap_tunnel.TunnelTarget{
		Project:   "prj-dl-dev-ooms-dev-2037",
		Zone:      "us-central1-a",
		Instance:  "bastion-vm",
		Interface: "nic0",
		Port:      6432,
	}
	manager := iap_tunnel.NewTunnelManager(target, nil)

	localPort := int(data.LocalPort.ValueInt32())
	listenAddr := fmt.Sprintf("127.0.0.1:%d", localPort)
	lis, err := net.Listen("tcp", listenAddr)
	if err != nil {
		resp.Diagnostics.AddError("Tunnel Error", fmt.Sprintf("Failed to listen on %s: %v", listenAddr, err))
		return
	}
	tflog.Info(ctx, "Tunnel listening", map[string]interface{}{"listen_addr": listenAddr})

	tunnelInfo.listener = lis
	tunnelCtx, cancel := context.WithCancel(context.Background())
	tunnelInfo.cancel = cancel

	tunnelInfo.manager = manager

	// Start Serve in a goroutine
	go func() {
		fmt.Printf("[IAP Tunnel] Starting tunnel on %s\n", listenAddr)
		tflog.Info(ctx, "Starting tunnel", map[string]interface{}{"listen_addr": listenAddr})
		err := manager.Serve(tunnelCtx, lis)
		if err != nil {
			tflog.Error(ctx, "Tunnel serve error", map[string]interface{}{"err": err})
			resp.Diagnostics.AddError("Failed to serve tunnel", fmt.Sprintf("[IAP Tunnel] Serve error: %v", err))
		}
	}()

	// Forward tunnel errors to diagnostics
	go func() {
		for err := range manager.Errors() {
			tflog.Error(ctx, "Tunnel error", map[string]interface{}{"err": err})
			resp.Diagnostics.AddError("Tunnel error", err.Error())
		}
	}()

	// Wait for the tunnel to be ready (CONNECT_SUCCESS received)
	select {
	case <-tunnelInfo.manager.Ready():
		tflog.Info(ctx, "Tunnel is ready for connections", map[string]interface{}{"listen_addr": listenAddr})
	case <-time.After(30 * time.Second):
		resp.Diagnostics.AddError("Tunnel Error", "Timed out waiting for tunnel to become ready")
		return
	}

	r.tunnelTracker.Add(id, tunnelInfo)

	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)
}

func (r *IapTunnelEphemeralResource) closeByConnectionID(id string) diag.Diagnostics {
	diags := diag.Diagnostics{}

	tunnelInfo := r.tunnelTracker.Get(id)
	if tunnelInfo == nil {
		return diags
	}

	if tunnelInfo.cancel != nil {
		diags.AddWarning("", "[IAP Tunnel] Cancelling tunnel context...")
		tunnelInfo.cancel()
	}

	if tunnelInfo.listener != nil {
		fmt.Println("[IAP Tunnel] Closing listener...")
		if err := tunnelInfo.listener.Close(); err != nil {
			diags.AddError("Failed to close listener", fmt.Sprintf("Failed to close listener: %v", err))
		}
	}
	fmt.Println("[IAP Tunnel] Tunnel listener closed.")

	r.tunnelTracker.Remove(id)
	fmt.Println("[IAP Tunnel] Tunnel resource cleanup complete.")

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
