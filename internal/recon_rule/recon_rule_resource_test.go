package reconrule_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccReconRuleResource_basic(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_recon_rule.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccReconRuleConfig_basic(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("topic"), knownvalue.StringExact("SA_ALIAS")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("filter"), knownvalue.StringExact("test-filter")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("priority"), knownvalue.StringExact("high")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("permissions"), knownvalue.StringExact("private")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("breach_monitoring_enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("breach_monitor_only"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("substring_matching_enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("status"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("created_timestamp"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("updated_timestamp"), knownvalue.NotNull()),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
		},
	})
}

func TestAccReconRuleResource_update(t *testing.T) {
	rName := acctest.RandomResourceName()
	rNameUpdated := fmt.Sprintf("%s-updated", rName)
	resourceName := "crowdstrike_recon_rule.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccReconRuleConfig_basic(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("priority"), knownvalue.StringExact("high")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("permissions"), knownvalue.StringExact("private")),
				},
			},
			{
				Config: testAccReconRuleConfig_updated(rNameUpdated),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rNameUpdated)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("topic"), knownvalue.StringExact("SA_ALIAS")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("filter"), knownvalue.StringExact("updated-filter")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("priority"), knownvalue.StringExact("low")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("permissions"), knownvalue.StringExact("public")),
				},
			},
			{
				Config: testAccReconRuleConfig_basic(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("priority"), knownvalue.StringExact("high")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("permissions"), knownvalue.StringExact("private")),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
		},
	})
}

func TestAccReconRuleResource_topicRequiresReplace(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_recon_rule.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccReconRuleConfig_basic(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("topic"), knownvalue.StringExact("SA_ALIAS")),
				},
			},
			{
				Config: testAccReconRuleConfig_differentTopic(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("topic"), knownvalue.StringExact("SA_CUSTOM")),
				},
			},
		},
	})
}

func TestAccReconRuleResource_validation(t *testing.T) {
	validationTests := []struct {
		name        string
		config      string
		expectError *regexp.Regexp
	}{
		{
			name: "invalid_topic",
			config: `
resource "crowdstrike_recon_rule" "test" {
  name        = "test"
  topic       = "INVALID_TOPIC"
  filter      = "test"
  priority    = "high"
  permissions = "private"
}`,
			expectError: regexp.MustCompile(`Attribute topic value must be one of`),
		},
		{
			name: "invalid_priority",
			config: `
resource "crowdstrike_recon_rule" "test" {
  name        = "test"
  topic       = "SA_ALIAS"
  filter      = "test"
  priority    = "critical"
  permissions = "private"
}`,
			expectError: regexp.MustCompile(`Attribute priority value must be one of`),
		},
		{
			name: "invalid_permissions",
			config: `
resource "crowdstrike_recon_rule" "test" {
  name        = "test"
  topic       = "SA_ALIAS"
  filter      = "test"
  priority    = "high"
  permissions = "restricted"
}`,
			expectError: regexp.MustCompile(`Attribute permissions value must be one of`),
		},
		{
			name: "breach_monitor_only_without_breach_monitoring",
			config: `
resource "crowdstrike_recon_rule" "test" {
  name                     = "test"
  topic                    = "SA_ALIAS"
  filter                   = "test"
  priority                 = "high"
  permissions              = "private"
  breach_monitor_only      = true
  breach_monitoring_enabled = false
}`,
			expectError: regexp.MustCompile(`breach_monitor_only can only be set to true when breach_monitoring_enabled is also true`),
		},
		{
			name: "empty_name",
			config: `
resource "crowdstrike_recon_rule" "test" {
  name        = ""
  topic       = "SA_ALIAS"
  filter      = "test"
  priority    = "high"
  permissions = "private"
}`,
			expectError: regexp.MustCompile(`Attribute name string length must be at least 1`),
		},
		{
			name: "empty_filter",
			config: `
resource "crowdstrike_recon_rule" "test" {
  name        = "test"
  topic       = "SA_ALIAS"
  filter      = ""
  priority    = "high"
  permissions = "private"
}`,
			expectError: regexp.MustCompile(`Attribute filter string length must be at least 1`),
		},
	}

	for _, tc := range validationTests {
		t.Run(tc.name, func(t *testing.T) {
			resource.ParallelTest(t, resource.TestCase{
				PreCheck:                 func() { acctest.PreCheck(t) },
				ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
				Steps: []resource.TestStep{
					{
						Config:      tc.config,
						ExpectError: tc.expectError,
						PlanOnly:    true,
					},
				},
			})
		})
	}
}

func testAccReconRuleConfig_basic(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_recon_rule" "test" {
  name        = %[1]q
  topic       = "SA_ALIAS"
  filter      = "test-filter"
  priority    = "high"
  permissions = "private"
}`, name)
}

func testAccReconRuleConfig_updated(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_recon_rule" "test" {
  name        = %[1]q
  topic       = "SA_ALIAS"
  filter      = "updated-filter"
  priority    = "low"
  permissions = "public"
}`, name)
}

func testAccReconRuleConfig_differentTopic(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_recon_rule" "test" {
  name        = %[1]q
  topic       = "SA_CUSTOM"
  filter      = "test-filter"
  priority    = "high"
  permissions = "private"
}`, name)
}
