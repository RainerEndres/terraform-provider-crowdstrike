package correlationrules

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// useStateUnlessMitreChanged preserves the state value for computed attributes
// that are derived from mitre_attack (tactic, technique).  When mitre_attack
// hasn't changed the value is stable and we avoid "(known after apply)" noise.
// When it has changed the value must be recomputed from the API response.
type useStateUnlessMitreChanged struct{}

func (m useStateUnlessMitreChanged) Description(_ context.Context) string {
	return "Uses the state value unless mitre_attack has changed."
}

func (m useStateUnlessMitreChanged) MarkdownDescription(_ context.Context) string {
	return "Uses the state value unless mitre_attack has changed."
}

func (m useStateUnlessMitreChanged) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	// Only act when the planned value is unknown (i.e. Computed, not set by user).
	if !req.PlanValue.IsUnknown() {
		return
	}
	// On create there is no state to preserve.
	if req.StateValue.IsNull() {
		return
	}

	var planMitre, stateMitre types.List
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("mitre_attack"), &planMitre)...)
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("mitre_attack"), &stateMitre)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if planMitre.Equal(stateMitre) {
		resp.PlanValue = req.StateValue
	}
}
