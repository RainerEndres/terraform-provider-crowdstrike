package ngsiemookup_test

import (
	"fmt"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccNGSIEMLookupFileResource_basic(t *testing.T) {
	rName := acctest.RandomResourceName()
	filename := rName + ".csv"
	resourceName := "crowdstrike_ngsiem_lookup_file.test"

	csvContent := "user_id,name,region\n1,alice,US\n2,bob,EU\n"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccNGSIEMLookupConfig_basic(filename, csvContent),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("filename"), knownvalue.StringExact(filename)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("repository"), knownvalue.StringExact("all")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("last_updated"), knownvalue.NotNull()),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"content", "content_sha256", "last_updated"},
			},
		},
	})
}

func TestAccNGSIEMLookupFileResource_update(t *testing.T) {
	rName := acctest.RandomResourceName()
	filename := rName + ".csv"
	resourceName := "crowdstrike_ngsiem_lookup_file.test"

	csvContent1 := "user_id,name,region\n1,alice,US\n2,bob,EU\n"
	csvContent2 := "user_id,name,region\n1,alice,US\n2,bob,EU\n3,charlie,AU\n"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccNGSIEMLookupConfig_basic(filename, csvContent1),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("filename"), knownvalue.StringExact(filename)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("repository"), knownvalue.StringExact("all")),
				},
			},
			{
				Config: testAccNGSIEMLookupConfig_basic(filename, csvContent2),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("filename"), knownvalue.StringExact(filename)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("content"), knownvalue.StringExact(csvContent2)),
				},
			},
		},
	})
}

func testAccNGSIEMLookupConfig_basic(filename, content string) string {
	return fmt.Sprintf(`
resource "crowdstrike_ngsiem_lookup_file" "test" {
  filename   = %[1]q
  repository = "all"
  content    = %[2]q
}
`, filename, content)
}
