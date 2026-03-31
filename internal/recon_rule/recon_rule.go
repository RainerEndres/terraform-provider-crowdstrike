package reconrule

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/recon"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource                   = &reconRuleResource{}
	_ resource.ResourceWithConfigure      = &reconRuleResource{}
	_ resource.ResourceWithImportState    = &reconRuleResource{}
	_ resource.ResourceWithValidateConfig = &reconRuleResource{}
)

var (
	documentationSection        string         = "Falcon Intelligence Recon"
	resourceMarkdownDescription string         = "This resource allows you to manage Falcon Intelligence Recon monitoring rules in the CrowdStrike Falcon Platform.\n\nRecon rules define the monitoring criteria used to discover threats across the dark web, criminal forums, and other online sources."
	requiredScopes              []scopes.Scope = []scopes.Scope{
		{
			Name:  "Monitoring rules (Falcon Intelligence Recon)",
			Read:  true,
			Write: true,
		},
	}
)

func NewReconRuleResource() resource.Resource {
	return &reconRuleResource{}
}

type reconRuleResource struct {
	client *client.CrowdStrikeAPISpecification
}

type reconRuleResourceModel struct {
	ID                       types.String `tfsdk:"id"`
	Name                     types.String `tfsdk:"name"`
	Topic                    types.String `tfsdk:"topic"`
	Filter                   types.String `tfsdk:"filter"`
	Priority                 types.String `tfsdk:"priority"`
	Permissions              types.String `tfsdk:"permissions"`
	BreachMonitoringEnabled  types.Bool   `tfsdk:"breach_monitoring_enabled"`
	BreachMonitorOnly        types.Bool   `tfsdk:"breach_monitor_only"`
	SubstringMatchingEnabled types.Bool   `tfsdk:"substring_matching_enabled"`
	LookbackPeriod           types.Int64  `tfsdk:"lookback_period"`
	Status                   types.String `tfsdk:"status"`
	StatusMessage            types.String `tfsdk:"status_message"`
	CreatedTimestamp         types.String `tfsdk:"created_timestamp"`
	UpdatedTimestamp         types.String `tfsdk:"updated_timestamp"`
	LastUpdated              types.String `tfsdk:"last_updated"`
}

func (m *reconRuleResourceModel) wrap(rule models.SadomainRule) {
	m.ID = types.StringPointerValue(rule.ID)
	m.Name = types.StringPointerValue(rule.Name)
	m.Topic = types.StringPointerValue(rule.Topic)
	m.Filter = types.StringPointerValue(rule.Filter)
	m.Priority = types.StringPointerValue(rule.Priority)
	m.Permissions = types.StringPointerValue(rule.Permissions)
	m.BreachMonitoringEnabled = types.BoolPointerValue(rule.BreachMonitoringEnabled)
	m.BreachMonitorOnly = types.BoolPointerValue(rule.BreachMonitorOnly)
	m.SubstringMatchingEnabled = types.BoolPointerValue(rule.SubstringMatchingEnabled)
	m.LookbackPeriod = types.Int64Value(rule.LookbackPeriod)
	m.Status = types.StringPointerValue(rule.Status)
	m.StatusMessage = types.StringValue(rule.StatusMessage)

	if rule.CreatedTimestamp != nil {
		m.CreatedTimestamp = types.StringValue(rule.CreatedTimestamp.String())
	}
	if rule.UpdatedTimestamp != nil {
		m.UpdatedTimestamp = types.StringValue(rule.UpdatedTimestamp.String())
	}
}

func (r *reconRuleResource) Configure(
	ctx context.Context,
	req resource.ConfigureRequest,
	resp *resource.ConfigureResponse,
) {
	if req.ProviderData == nil {
		return
	}

	providerConfig, ok := req.ProviderData.(config.ProviderConfig)

	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf(
				"Expected config.ProviderConfig, got: %T. Please report this issue to the provider developers.",
				req.ProviderData,
			),
		)
		return
	}

	r.client = providerConfig.Client
}

func (r *reconRuleResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_recon_rule"
}

func (r *reconRuleResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			documentationSection,
			resourceMarkdownDescription,
			requiredScopes,
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The unique identifier of the recon rule.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"last_updated": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Timestamp of the last Terraform update of the resource.",
			},
			"name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The name of the recon rule.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			// Allowed values from SadomainCreateRuleRequestV1.Topic in gofalcon.
			"topic": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The topic of the recon rule. Determines what type of threat intelligence is monitored.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.OneOf(
						"SA_BRAND_PRODUCT",
						"SA_VIP",
						"SA_THIRD_PARTY",
						"SA_IP",
						"SA_CVE",
						"SA_BIN",
						"SA_DOMAIN",
						"SA_EMAIL",
						"SA_ALIAS",
						"SA_AUTHOR",
						"SA_CUSTOM",
						"SA_TYPOSQUATTING",
					),
				},
			},
			"filter": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The FQL filter used for searching.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			// Allowed values from SadomainCreateRuleRequestV1.Priority in gofalcon.
			"priority": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The priority of the recon rule.",
				Validators: []validator.String{
					stringvalidator.OneOf("low", "medium", "high"),
				},
			},
			// Allowed values from SadomainCreateRuleRequestV1.Permissions in gofalcon.
			"permissions": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The access permissions for the recon rule.",
				Validators: []validator.String{
					stringvalidator.OneOf("public", "private"),
				},
			},
			"breach_monitoring_enabled": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Whether to monitor for breach data. Only available for `SA_DOMAIN` and `SA_EMAIL` rule topics.",
			},
			"breach_monitor_only": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Whether to monitor only for breach data. Must be used with `breach_monitoring_enabled` set to `true`.",
			},
			"substring_matching_enabled": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Whether to monitor for substring matches. Only available for the `SA_TYPOSQUATTING` rule topic.",
			},
			"lookback_period": schema.Int64Attribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "The duration (in days) for which the rule looks back in the past at first run.",
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			"status": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The current status of the recon rule.",
			},
			"status_message": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The detailed status message of the recon rule.",
			},
			"created_timestamp": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The timestamp when the recon rule was created.",
			},
			"updated_timestamp": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The timestamp when the recon rule was last updated.",
			},
		},
	}
}

func (r *reconRuleResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var cfg reconRuleResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if cfg.BreachMonitorOnly.IsUnknown() || cfg.BreachMonitoringEnabled.IsUnknown() || cfg.Topic.IsUnknown() {
		return
	}

	if cfg.BreachMonitorOnly.ValueBool() && !cfg.BreachMonitoringEnabled.ValueBool() {
		resp.Diagnostics.AddAttributeError(
			path.Root("breach_monitor_only"),
			"Invalid Configuration",
			"breach_monitor_only can only be set to true when breach_monitoring_enabled is also true.",
		)
	}
}

func (r *reconRuleResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan reconRuleResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Creating recon rule", map[string]any{
		"name":  plan.Name.ValueString(),
		"topic": plan.Topic.ValueString(),
	})

	name := plan.Name.ValueString()
	topic := plan.Topic.ValueString()
	filter := plan.Filter.ValueString()
	priority := plan.Priority.ValueString()
	permissions := plan.Permissions.ValueString()
	breachMonitoringEnabled := plan.BreachMonitoringEnabled.ValueBool()
	breachMonitorOnly := plan.BreachMonitorOnly.ValueBool()
	substringMatchingEnabled := plan.SubstringMatchingEnabled.ValueBool()
	originatingTemplateID := ""

	createReq := &models.SadomainCreateRuleRequestV1{
		Name:                     &name,
		Topic:                    &topic,
		Filter:                   &filter,
		Priority:                 &priority,
		Permissions:              &permissions,
		BreachMonitoringEnabled:  &breachMonitoringEnabled,
		BreachMonitorOnly:        &breachMonitorOnly,
		SubstringMatchingEnabled: &substringMatchingEnabled,
		LookbackPeriod:           plan.LookbackPeriod.ValueInt64(),
		OriginatingTemplateID:    &originatingTemplateID,
	}

	params := recon.NewCreateRulesV1ParamsWithContext(ctx)
	params.SetBody([]*models.SadomainCreateRuleRequestV1{createReq})

	createResp, err := r.client.Recon.CreateRulesV1(params)
	if err != nil {
		resp.Diagnostics.Append(
			tferrors.NewDiagnosticFromAPIError(tferrors.Create, err, requiredScopes),
		)
		return
	}

	if createResp == nil || createResp.Payload == nil || len(createResp.Payload.Resources) == 0 {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Create))
		return
	}

	createdRule := createResp.Payload.Resources[0]

	tflog.Info(ctx, "Successfully created recon rule", map[string]any{
		"id":   *createdRule.ID,
		"name": *createdRule.Name,
	})

	plan.wrap(*createdRule)
	plan.LastUpdated = utils.GenerateUpdateTimestamp()
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *reconRuleResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state reconRuleResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ruleID := state.ID.ValueString()
	tflog.Info(ctx, "Reading recon rule", map[string]any{
		"id": ruleID,
	})

	rule, diags := getReconRule(ctx, r.client, ruleID)
	if tferrors.HasNotFoundError(diags) {
		tflog.Warn(ctx, "Recon rule not found, removing from state", map[string]any{
			"id": ruleID,
		})
		resp.Diagnostics.Append(tferrors.NewResourceNotFoundWarningDiagnostic())
		resp.State.RemoveResource(ctx)
		return
	}
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	state.wrap(*rule)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *reconRuleResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan reconRuleResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ruleID := plan.ID.ValueString()
	tflog.Info(ctx, "Updating recon rule", map[string]any{
		"id":   ruleID,
		"name": plan.Name.ValueString(),
	})

	name := plan.Name.ValueString()
	filter := plan.Filter.ValueString()
	priority := plan.Priority.ValueString()
	permissions := plan.Permissions.ValueString()
	breachMonitoringEnabled := plan.BreachMonitoringEnabled.ValueBool()
	breachMonitorOnly := plan.BreachMonitorOnly.ValueBool()
	substringMatchingEnabled := plan.SubstringMatchingEnabled.ValueBool()

	updateReq := &models.DomainUpdateRuleRequestV1{
		ID:                       &ruleID,
		Name:                     &name,
		Filter:                   &filter,
		Priority:                 &priority,
		Permissions:              &permissions,
		BreachMonitoringEnabled:  &breachMonitoringEnabled,
		BreachMonitorOnly:        &breachMonitorOnly,
		SubstringMatchingEnabled: &substringMatchingEnabled,
	}

	params := recon.NewUpdateRulesV1ParamsWithContext(ctx)
	params.SetBody([]*models.DomainUpdateRuleRequestV1{updateReq})

	updateResp, err := r.client.Recon.UpdateRulesV1(params)
	if err != nil {
		resp.Diagnostics.Append(
			tferrors.NewDiagnosticFromAPIError(tferrors.Update, err, requiredScopes),
		)
		return
	}

	if updateResp == nil || updateResp.Payload == nil || len(updateResp.Payload.Resources) == 0 {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Update))
		return
	}

	updatedRule := updateResp.Payload.Resources[0]

	tflog.Info(ctx, "Successfully updated recon rule", map[string]any{
		"id":   *updatedRule.ID,
		"name": *updatedRule.Name,
	})

	plan.wrap(*updatedRule)
	plan.LastUpdated = utils.GenerateUpdateTimestamp()
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *reconRuleResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state reconRuleResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ruleID := state.ID.ValueString()
	tflog.Info(ctx, "Deleting recon rule", map[string]any{
		"id": ruleID,
	})

	params := recon.NewDeleteRulesV1ParamsWithContext(ctx)
	params.SetIds([]string{ruleID})

	_, err := r.client.Recon.DeleteRulesV1(params)
	if err != nil {
		resp.Diagnostics.Append(
			tferrors.NewDiagnosticFromAPIError(tferrors.Delete, err, requiredScopes),
		)
		return
	}

	tflog.Info(ctx, "Successfully deleted recon rule", map[string]any{
		"id": ruleID,
	})
}

func (r *reconRuleResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// getReconRule retrieves a single recon rule by ID.
func getReconRule(
	ctx context.Context,
	apiClient *client.CrowdStrikeAPISpecification,
	ruleID string,
) (*models.SadomainRule, diag.Diagnostics) {
	var diags diag.Diagnostics

	params := recon.NewGetRulesV1ParamsWithContext(ctx)
	params.SetIds([]string{ruleID})

	resp, err := apiClient.Recon.GetRulesV1(params)
	if err != nil {
		diags.Append(
			tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, requiredScopes),
		)
		return nil, diags
	}

	if resp == nil || resp.Payload == nil || len(resp.Payload.Resources) == 0 {
		diags.Append(
			tferrors.NewNotFoundError(
				fmt.Sprintf("Recon rule with ID %s not found.", ruleID),
			),
		)
		return nil, diags
	}

	return resp.Payload.Resources[0], diags
}
