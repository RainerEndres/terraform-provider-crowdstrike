package correlationrules_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccCorrelationRuleResource_Basic(t *testing.T) {
	rName := acctest.RandomResourceName()
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t, acctest.RequireCustomerID) },
		Steps: []resource.TestStep{
			// Create and verify
			{
				Config: testAccCorrelationRuleConfig(rName, 50, "inactive"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_correlation_rule.test",
						"name",
						rName,
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_correlation_rule.test",
						"severity",
						"50",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_correlation_rule.test",
						"status",
						"inactive",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_correlation_rule.test",
						"id",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_correlation_rule.test",
						"customer_id",
					),
					// Verify execution_mode defaults to "scheduled"
					resource.TestCheckResourceAttr(
						"crowdstrike_correlation_rule.test",
						"search.execution_mode",
						"scheduled",
					),
				),
			},
			// ImportState testing
			{
				ResourceName:            "crowdstrike_correlation_rule.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"trigger_on_create"},
			},
			// Update with new severity
			{
				Config: testAccCorrelationRuleConfig(rName+"-updated", 70, "inactive"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_correlation_rule.test",
						"name",
						rName+"-updated",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_correlation_rule.test",
						"severity",
						"70",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_correlation_rule.test",
						"status",
						"inactive",
					),
				),
			},
		},
	})
}

func TestAccCorrelationRuleResource_WithDescription(t *testing.T) {
	rName := acctest.RandomResourceName()
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t, acctest.RequireCustomerID) },
		Steps: []resource.TestStep{
			{
				Config: testAccCorrelationRuleConfigWithDescription(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_correlation_rule.test",
						"name",
						rName,
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_correlation_rule.test",
						"description",
						"Test correlation rule created by Terraform acceptance tests",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_correlation_rule.test",
						"severity",
						"30",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_correlation_rule.test",
						"status",
						"inactive",
					),
				),
			},
		},
	})
}

func TestAccCorrelationRuleResource_WithMitreAttack(t *testing.T) {
	rName := acctest.RandomResourceName()
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t, acctest.RequireCustomerID) },
		Steps: []resource.TestStep{
			{
				Config: testAccCorrelationRuleConfigWithMitreAttack(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_correlation_rule.test",
						"name",
						rName,
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_correlation_rule.test",
						"severity",
						"70",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_correlation_rule.test",
						"mitre_attack.#",
						"1",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_correlation_rule.test",
						"mitre_attack.0.tactic_id",
						"TA0001",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_correlation_rule.test",
						"mitre_attack.0.technique_id",
						"T1078",
					),
				),
			},
		},
	})
}

func TestAccCorrelationRuleResource_MultipleMitreAttack(t *testing.T) {
	rName := acctest.RandomResourceName()
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t, acctest.RequireCustomerID) },
		Steps: []resource.TestStep{
			{
				Config: testAccCorrelationRuleConfigWithMultipleMitreAttack(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_correlation_rule.test",
						"name",
						rName,
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_correlation_rule.test",
						"mitre_attack.#",
						"3",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_correlation_rule.test",
						"mitre_attack.0.tactic_id",
						"TA0001",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_correlation_rule.test",
						"mitre_attack.0.technique_id",
						"T1078",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_correlation_rule.test",
						"mitre_attack.1.tactic_id",
						"TA0003",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_correlation_rule.test",
						"mitre_attack.1.technique_id",
						"T1053",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_correlation_rule.test",
						"mitre_attack.2.tactic_id",
						"TA0004",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_correlation_rule.test",
						"mitre_attack.2.technique_id",
						"T1548",
					),
					// Verify tactic/technique are derived from first entry
					resource.TestCheckResourceAttr(
						"crowdstrike_correlation_rule.test",
						"tactic",
						"TA0001",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_correlation_rule.test",
						"technique",
						"T1078",
					),
				),
			},
		},
	})
}

func TestAccCorrelationRuleResource_UpdateFields(t *testing.T) {
	rName := acctest.RandomResourceName()
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t, acctest.RequireCustomerID) },
		Steps: []resource.TestStep{
			// Create initial rule
			{
				Config: testAccCorrelationRuleConfigUpdatable(rName, "Initial description", 30, "1h0m", "verbose"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_correlation_rule.test",
						"name",
						rName,
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_correlation_rule.test",
						"description",
						"Initial description",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_correlation_rule.test",
						"severity",
						"30",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_correlation_rule.test",
						"search.lookback",
						"1h0m",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_correlation_rule.test",
						"search.trigger_mode",
						"verbose",
					),
				),
			},
			// Update description
			{
				Config: testAccCorrelationRuleConfigUpdatable(rName, "Updated description", 30, "1h0m", "verbose"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_correlation_rule.test",
						"description",
						"Updated description",
					),
				),
			},
			// Update severity
			{
				Config: testAccCorrelationRuleConfigUpdatable(rName, "Updated description", 70, "1h0m", "verbose"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_correlation_rule.test",
						"severity",
						"70",
					),
				),
			},
			// Update search lookback
			{
				Config: testAccCorrelationRuleConfigUpdatable(rName, "Updated description", 70, "2h30m", "verbose"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_correlation_rule.test",
						"search.lookback",
						"2h30m",
					),
				),
			},
			// Update trigger_mode
			{
				Config: testAccCorrelationRuleConfigUpdatable(rName, "Updated description", 70, "2h30m", "summary"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_correlation_rule.test",
						"search.trigger_mode",
						"summary",
					),
				),
			},
		},
	})
}

func TestAccCorrelationRuleResource_WithStartOn(t *testing.T) {
	rName := acctest.RandomResourceName()
	// start_on must be at least 15 minutes in the future
	startOn := time.Now().Add(20 * time.Minute).UTC().Format(time.RFC3339)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t, acctest.RequireCustomerID) },
		Steps: []resource.TestStep{
			{
				Config: testAccCorrelationRuleConfigWithStartOn(rName, startOn),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_correlation_rule.test",
						"name",
						rName,
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_correlation_rule.test",
						"operation.start_on",
					),
				),
			},
		},
	})
}

func testAccCorrelationRuleConfig(rName string, severity int, status string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_correlation_rule" "test" {
  name        = %[1]q
  customer_id = %[4]q
  severity    = %[2]d
  status      = %[3]q

  search {
    filter       = "#repo=\"base_sensor\" #event_simpleName=ProcessRollup2"
    lookback     = "1h0m"
    outcome      = "detection"
    trigger_mode = "verbose"
  }

  operation {
    schedule {
      definition = "@every 1h0m"
    }
  }
}
`, rName, severity, status, acctest.CustomerID())
}

func testAccCorrelationRuleConfigWithDescription(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_correlation_rule" "test" {
  name        = %[1]q
  customer_id = %[2]q
  description = "Test correlation rule created by Terraform acceptance tests"
  severity    = 30
  status      = "inactive"

  search {
    filter          = "#Vendor=\"aws\" #event.module=\"cloudtrail\" event.action=\"AttachUserPolicy\""
    lookback        = "1h15m"
    outcome         = "detection"
    trigger_mode    = "summary"
    use_ingest_time = true
  }

  operation {
    schedule {
      definition = "@every 1h0m"
    }
  }
}
`, rName, acctest.CustomerID())
}

func testAccCorrelationRuleConfigWithMitreAttack(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_correlation_rule" "test" {
  name        = %[1]q
  customer_id = %[2]q
  severity    = 70
  status      = "inactive"

  search {
    filter       = "#event.kind=\"alert\" #event.module=\"falcon\""
    lookback     = "1h0m"
    outcome      = "detection"
    trigger_mode = "verbose"
  }

  operation {
    schedule {
      definition = "@every 1h0m"
    }
  }

  mitre_attack {
    tactic_id    = "TA0001"
    technique_id = "T1078"
  }
}
`, rName, acctest.CustomerID())
}

func testAccCorrelationRuleConfigWithMultipleMitreAttack(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_correlation_rule" "test" {
  name        = %[1]q
  customer_id = %[2]q
  severity    = 70
  status      = "inactive"

  search {
    filter       = "#event.kind=\"alert\" #event.module=\"falcon\""
    lookback     = "1h0m"
    outcome      = "detection"
    trigger_mode = "verbose"
  }

  operation {
    schedule {
      definition = "@every 1h0m"
    }
  }

  mitre_attack {
    tactic_id    = "TA0001"
    technique_id = "T1078"
  }

  mitre_attack {
    tactic_id    = "TA0003"
    technique_id = "T1053"
  }

  mitre_attack {
    tactic_id    = "TA0004"
    technique_id = "T1548"
  }
}
`, rName, acctest.CustomerID())
}

func testAccCorrelationRuleConfigUpdatable(rName, description string, severity int, lookback, triggerMode string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_correlation_rule" "test" {
  name        = %[1]q
  customer_id = %[6]q
  description = %[2]q
  severity    = %[3]d
  status      = "inactive"

  search {
    filter       = "#repo=\"base_sensor\" #event_simpleName=ProcessRollup2"
    lookback     = %[4]q
    outcome      = "detection"
    trigger_mode = %[5]q
  }

  operation {
    schedule {
      definition = "@every 1h0m"
    }
  }
}
`, rName, description, severity, lookback, triggerMode, acctest.CustomerID())
}

func testAccCorrelationRuleConfigWithStartOn(rName, startOn string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_correlation_rule" "test" {
  name        = %[1]q
  customer_id = %[3]q
  severity    = 50
  status      = "inactive"

  search {
    filter       = "#repo=\"base_sensor\" #event_simpleName=ProcessRollup2"
    lookback     = "1h0m"
    outcome      = "detection"
    trigger_mode = "verbose"
  }

  operation {
    start_on = %[2]q
    schedule {
      definition = "@every 1h0m"
    }
  }
}
`, rName, startOn, acctest.CustomerID())
}

func TestAccCorrelationRuleResource_WithComment(t *testing.T) {
	rName := acctest.RandomResourceName()
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t, acctest.RequireCustomerID) },
		Steps: []resource.TestStep{
			{
				Config: testAccCorrelationRuleConfigWithComment(rName, "initial comment"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_correlation_rule.test",
						"comment",
						"initial comment",
					),
				),
			},
			// Update comment
			{
				Config: testAccCorrelationRuleConfigWithComment(rName, "updated comment"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_correlation_rule.test",
						"comment",
						"updated comment",
					),
				),
			},
		},
	})
}

func TestAccCorrelationRuleResource_WithStopOn(t *testing.T) {
	rName := acctest.RandomResourceName()
	// stop_on must be in the future
	stopOn := time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t, acctest.RequireCustomerID) },
		Steps: []resource.TestStep{
			{
				Config: testAccCorrelationRuleConfigWithStopOn(rName, stopOn),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_correlation_rule.test",
						"name",
						rName,
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_correlation_rule.test",
						"operation.stop_on",
					),
				),
			},
			{
				ResourceName:            "crowdstrike_correlation_rule.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"trigger_on_create"},
			},
		},
	})
}

func TestAccCorrelationRuleResource_WithUseIngestTime(t *testing.T) {
	rName := acctest.RandomResourceName()
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t, acctest.RequireCustomerID) },
		Steps: []resource.TestStep{
			// Create with use_ingest_time = true
			{
				Config: testAccCorrelationRuleConfigWithUseIngestTime(rName, true),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_correlation_rule.test",
						"search.use_ingest_time",
						"true",
					),
				),
			},
			{
				ResourceName:            "crowdstrike_correlation_rule.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"trigger_on_create"},
			},
		},
	})
}

func TestAccCorrelationRuleResource_UpdateMitreAttack(t *testing.T) {
	rName := acctest.RandomResourceName()
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t, acctest.RequireCustomerID) },
		Steps: []resource.TestStep{
			// Create with no MITRE ATT&CK
			{
				Config: testAccCorrelationRuleConfig(rName, 50, "inactive"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_correlation_rule.test",
						"mitre_attack.#",
						"0",
					),
				),
			},
			// Add one MITRE ATT&CK entry
			{
				Config: testAccCorrelationRuleConfigWithMitreAttackUpdatable(rName, []mitreEntry{
					{tacticID: "TA0001", techniqueID: "T1078"},
				}),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_correlation_rule.test",
						"mitre_attack.#",
						"1",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_correlation_rule.test",
						"mitre_attack.0.tactic_id",
						"TA0001",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_correlation_rule.test",
						"mitre_attack.0.technique_id",
						"T1078",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_correlation_rule.test",
						"tactic",
						"TA0001",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_correlation_rule.test",
						"technique",
						"T1078",
					),
				),
			},
			// Add a second MITRE ATT&CK entry
			{
				Config: testAccCorrelationRuleConfigWithMitreAttackUpdatable(rName, []mitreEntry{
					{tacticID: "TA0001", techniqueID: "T1078"},
					{tacticID: "TA0004", techniqueID: "T1548"},
				}),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_correlation_rule.test",
						"mitre_attack.#",
						"2",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_correlation_rule.test",
						"mitre_attack.1.tactic_id",
						"TA0004",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_correlation_rule.test",
						"mitre_attack.1.technique_id",
						"T1548",
					),
				),
			},
			// Remove all MITRE ATT&CK entries
			{
				Config: testAccCorrelationRuleConfig(rName, 50, "inactive"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_correlation_rule.test",
						"mitre_attack.#",
						"0",
					),
				),
			},
		},
	})
}

func TestAccCorrelationRuleResource_StatusTransition(t *testing.T) {
	rName := acctest.RandomResourceName()
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t, acctest.RequireCustomerID) },
		Steps: []resource.TestStep{
			// Create as inactive
			{
				Config: testAccCorrelationRuleConfig(rName, 50, "inactive"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_correlation_rule.test",
						"status",
						"inactive",
					),
				),
			},
			// Transition to active
			{
				Config: testAccCorrelationRuleConfig(rName, 50, "active"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_correlation_rule.test",
						"status",
						"active",
					),
				),
			},
			// Transition back to inactive
			{
				Config: testAccCorrelationRuleConfig(rName, 50, "inactive"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_correlation_rule.test",
						"status",
						"inactive",
					),
				),
			},
		},
	})
}

type mitreEntry struct {
	tacticID    string
	techniqueID string
}

func testAccCorrelationRuleConfigWithComment(rName, comment string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_correlation_rule" "test" {
  name        = %[1]q
  customer_id = %[3]q
  comment     = %[2]q
  severity    = 50
  status      = "inactive"

  search {
    filter       = "#repo=\"base_sensor\" #event_simpleName=ProcessRollup2"
    lookback     = "1h0m"
    outcome      = "detection"
    trigger_mode = "verbose"
  }

  operation {
    schedule {
      definition = "@every 1h0m"
    }
  }
}
`, rName, comment, acctest.CustomerID())
}

func testAccCorrelationRuleConfigWithStopOn(rName, stopOn string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_correlation_rule" "test" {
  name        = %[1]q
  customer_id = %[3]q
  severity    = 50
  status      = "inactive"

  search {
    filter       = "#repo=\"base_sensor\" #event_simpleName=ProcessRollup2"
    lookback     = "1h0m"
    outcome      = "detection"
    trigger_mode = "verbose"
  }

  operation {
    stop_on = %[2]q
    schedule {
      definition = "@every 1h0m"
    }
  }
}
`, rName, stopOn, acctest.CustomerID())
}

func testAccCorrelationRuleConfigWithUseIngestTime(rName string, useIngestTime bool) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_correlation_rule" "test" {
  name        = %[1]q
  customer_id = %[3]q
  severity    = 50
  status      = "inactive"

  search {
    filter          = "#Vendor=\"aws\" #event.module=\"cloudtrail\" event.action=\"AttachUserPolicy\""
    lookback        = "1h0m"
    outcome         = "detection"
    trigger_mode    = "verbose"
    use_ingest_time = %[2]t
  }

  operation {
    schedule {
      definition = "@every 1h0m"
    }
  }
}
`, rName, useIngestTime, acctest.CustomerID())
}

func testAccCorrelationRuleConfigWithMitreAttackUpdatable(rName string, entries []mitreEntry) string {
	mitreBlocks := ""
	for _, e := range entries {
		mitreBlocks += fmt.Sprintf(`
  mitre_attack {
    tactic_id    = %q
    technique_id = %q
  }
`, e.tacticID, e.techniqueID)
	}
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_correlation_rule" "test" {
  name        = %[1]q
  customer_id = %[3]q
  severity    = 50
  status      = "inactive"

  search {
    filter       = "#repo=\"base_sensor\" #event_simpleName=ProcessRollup2"
    lookback     = "1h0m"
    outcome      = "detection"
    trigger_mode = "verbose"
  }

  operation {
    schedule {
      definition = "@every 1h0m"
    }
  }
%[2]s}
`, rName, mitreBlocks, acctest.CustomerID())
}
