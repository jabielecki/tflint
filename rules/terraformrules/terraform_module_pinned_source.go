package terraformrules

import (
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform/configs"
	"github.com/terraform-linters/tflint/tflint"
)

// TerraformModulePinnedSourceRule checks unpinned or default version module source
type TerraformModulePinnedSourceRule struct {
	attributeName string
}

type terraformModulePinnedSourceRuleConfig struct {
	Style            string         `hcl:"style,optional"`
	DefaultRefRegexp string         `hcl:"default_ref_regexp,optional"`
	defaultRefRegexp *regexp.Regexp `hcl:"-"`
}

// NewTerraformModulePinnedSourceRule returns new rule with default attributes
func NewTerraformModulePinnedSourceRule() *TerraformModulePinnedSourceRule {
	return &TerraformModulePinnedSourceRule{
		attributeName: "source",
	}
}

// Name returns the rule name
func (r *TerraformModulePinnedSourceRule) Name() string {
	return "terraform_module_pinned_source"
}

// Enabled returns whether the rule is enabled by default
func (r *TerraformModulePinnedSourceRule) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *TerraformModulePinnedSourceRule) Severity() string {
	return tflint.WARNING
}

// Link returns the rule reference link
func (r *TerraformModulePinnedSourceRule) Link() string {
	return tflint.ReferenceLink(r.Name())
}

// ReGitHub matches a module source which is a GitHub repository
// See https://www.terraform.io/docs/modules/sources.html#github
var ReGitHub = regexp.MustCompile("(^github.com/(.+)/(.+)$)|(^git@github.com:(.+)/(.+)$)")

// ReBitbucket matches a module source which is a Bitbucket repository
// See https://www.terraform.io/docs/modules/sources.html#bitbucket
var ReBitbucket = regexp.MustCompile("^bitbucket.org/(.+)/(.+)$")

// ReGenericGit matches a module source which is a Git repository
// See https://www.terraform.io/docs/modules/sources.html#generic-git-repository
var ReGenericGit = regexp.MustCompile("(git://(.+)/(.+))|(git::https://(.+)/(.+))|(git::ssh://((.+)@)??(.+)/(.+)/(.+))")

var reSemverReference = regexp.MustCompile("\\?ref=v?\\d+\\.\\d+\\.\\d+$")
var reSemverRevision = regexp.MustCompile("\\?rev=v?\\d+\\.\\d+\\.\\d+$")

var subReHost = "([^.:/\\\\]{1,63})(\\.[^.:/\\\\]{1,63})+"
var subReName = "[0-9a-z](?:[0-9a-z_-]{0,62}[0-9a-z])?"
var subReProvider = "[0-9a-z]{1,64}"

// ReRegistry is a regular expression that matches the lowercased tf registry source
// (for example "azure/vnet/azurerm" or "example.com/my/module/aws").
var ReRegistry = regexp.MustCompile(
	fmt.Sprintf("^(%s(:\\d+)?)?(%s)\\/(%s)\\/(%s)(\\/\\/.*)?$",
		subReHost, subReName, subReName, subReProvider))

// Check checks if module source version is pinned
// Note that this rule is valid only for Git or Mercurial source
func (r *TerraformModulePinnedSourceRule) Check(runner *tflint.Runner) error {
	if !runner.TFConfig.Path.IsRoot() {
		// This rule does not evaluate child modules.
		return nil
	}

	log.Printf("[TRACE] Check `%s` rule for `%s` runner", r.Name(), runner.TFConfigPath())

	config := terraformModulePinnedSourceRuleConfig{}
	config.Style = "flexible"
	config.DefaultRefRegexp = "master"
	if err := runner.DecodeRuleConfig(r.Name(), &config); err != nil {
		return err
	}

	re := fmt.Sprintf("ref=(%s)($|\\&)", config.DefaultRefRegexp)
	log.Printf("[TRACE] Source that matches `%s` is considered a Default Ref", re)
	config.defaultRefRegexp = regexp.MustCompile(re)

	var err error
	for _, module := range runner.TFConfig.Module.ModuleCalls {
		log.Printf("[DEBUG] Walk `%s` attribute", module.Name+".source")

		lower := strings.ToLower(module.SourceAddr)

		if ReGitHub.MatchString(lower) || ReGenericGit.MatchString(lower) {
			err = r.checkGitSource(runner, module, config)
		} else if ReBitbucket.MatchString(lower) {
			err = r.checkBitbucketSource(runner, module, config)
		} else if strings.HasPrefix(lower, "hg::") {
			err = r.checkMercurialSource(runner, module, config)
		} else if ReRegistry.MatchString(lower) {
			err = r.checkRegistrySource(runner, module, config)
		}

		if err != nil {
			return err
		}
	}

	return nil
}

func (r *TerraformModulePinnedSourceRule) checkGitSource(runner *tflint.Runner, module *configs.ModuleCall, config terraformModulePinnedSourceRuleConfig) error {
	lower := strings.ToLower(module.SourceAddr)

	if strings.Contains(lower, "ref=") {
		return r.checkRefSource(runner, module, config)
	}

	runner.EmitIssue(
		r,
		fmt.Sprintf("Module source \"%s\" is not pinned", module.SourceAddr),
		module.SourceAddrRange,
	)
	return nil
}

func (r *TerraformModulePinnedSourceRule) checkMercurialSource(runner *tflint.Runner, module *configs.ModuleCall, config terraformModulePinnedSourceRuleConfig) error {
	lower := strings.ToLower(module.SourceAddr)

	if strings.Contains(lower, "rev=") {
		return r.checkRevSource(runner, module, config)
	}

	runner.EmitIssue(
		r,
		fmt.Sprintf("Module source \"%s\" is not pinned", module.SourceAddr),
		module.SourceAddrRange,
	)
	return nil
}

// Terraform can use a Bitbucket repo as Git or Mercurial.
//
// Note: Bitbucket is dropping Mercurial support in 2020, so this can be rolled into
// checkGitSource after that happens.
func (r *TerraformModulePinnedSourceRule) checkBitbucketSource(runner *tflint.Runner, module *configs.ModuleCall, config terraformModulePinnedSourceRuleConfig) error {
	lower := strings.ToLower(module.SourceAddr)

	if strings.Contains(lower, "ref=") {
		return r.checkRefSource(runner, module, config)
	} else if strings.Contains(lower, "rev=") {
		return r.checkRevSource(runner, module, config)
	} else {
		runner.EmitIssue(
			r,
			fmt.Sprintf("Module source \"%s\" is not pinned", module.SourceAddr),
			module.SourceAddrRange,
		)
	}

	return nil
}

func (r *TerraformModulePinnedSourceRule) checkRefSource(runner *tflint.Runner, module *configs.ModuleCall, config terraformModulePinnedSourceRuleConfig) error {
	lower := strings.ToLower(module.SourceAddr)

	switch config.Style {
	// The "flexible" style enforces to pin source, except for the default branch
	case "flexible":
		matches := config.defaultRefRegexp.FindStringSubmatch(lower)
		if len(matches) > 1 {
			runner.EmitIssue(
				r,
				fmt.Sprintf("Module source \"%s\" uses default ref \"%s\"", module.SourceAddr, matches[1]),
				module.SourceAddrRange,
			)
		}
	// The "semver" style enforces to pin source like semantic versioning
	case "semver":
		if !reSemverReference.MatchString(lower) {
			runner.EmitIssue(
				r,
				fmt.Sprintf("Module source \"%s\" uses a ref which is not a version string", module.SourceAddr),
				module.SourceAddrRange,
			)
		}
	default:
		return fmt.Errorf("`%s` is invalid style", config.Style)
	}

	return nil
}

func (r *TerraformModulePinnedSourceRule) checkRevSource(runner *tflint.Runner, module *configs.ModuleCall, config terraformModulePinnedSourceRuleConfig) error {
	lower := strings.ToLower(module.SourceAddr)

	switch config.Style {
	// The "flexible" style enforces to pin source, except for the default reference
	case "flexible":
		if strings.Contains(lower, "rev=default") {
			runner.EmitIssue(
				r,
				fmt.Sprintf("Module source \"%s\" uses default rev \"default\"", module.SourceAddr),
				module.SourceAddrRange,
			)
		}
	// The "semver" style enforces to pin source like semantic versioning
	case "semver":
		if !reSemverRevision.MatchString(lower) {
			runner.EmitIssue(
				r,
				fmt.Sprintf("Module source \"%s\" uses a rev which is not a version string", module.SourceAddr),
				module.SourceAddrRange,
			)
		}
	default:
		return fmt.Errorf("`%s` is invalid style", config.Style)
	}

	return nil
}

func (r *TerraformModulePinnedSourceRule) checkRegistrySource(runner *tflint.Runner, module *configs.ModuleCall, config terraformModulePinnedSourceRuleConfig) error {
	lower := strings.ToLower(module.Version.Required.String())

	if len(lower) == 0 {
		runner.EmitIssue(
			r,
			fmt.Sprintf("Module source \"%s\" version \"%s\" is not pinned", module.SourceAddr, module.Version.Required.String()),
			module.SourceAddrRange,
		)
	}

	return nil
}
