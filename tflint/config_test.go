package tflint

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	hcl "github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	tfplugin "github.com/terraform-linters/tflint-plugin-sdk/tflint"
)

func Test_LoadConfig(t *testing.T) {
	currentDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		Name     string
		File     string
		Fallback string
		Expected *Config
	}{
		{
			Name: "load file",
			File: filepath.Join(currentDir, "test-fixtures", "config", "config.hcl"),
			Expected: &Config{
				Module: true,
				Force:  true,
				IgnoreModules: map[string]bool{
					"github.com/terraform-linters/example-module": true,
				},
				Varfiles:          []string{"example1.tfvars", "example2.tfvars"},
				Variables:         []string{"foo=bar", "bar=['foo']"},
				DisabledByDefault: false,
				Rules: map[string]*RuleConfig{
					"aws_instance_invalid_type": {
						Name:    "aws_instance_invalid_type",
						Enabled: false,
					},
					"aws_instance_previous_type": {
						Name:    "aws_instance_previous_type",
						Enabled: false,
					},
				},
				Plugins: map[string]*PluginConfig{
					"foo": {
						Name:    "foo",
						Enabled: true,
					},
					"bar": {
						Name:    "bar",
						Enabled: false,
					},
				},
			},
		},
		{
			Name:     "empty file",
			File:     filepath.Join(currentDir, "test-fixtures", "config", "empty.hcl"),
			Expected: EmptyConfig(),
		},
		{
			Name:     "fallback",
			File:     filepath.Join(currentDir, "test-fixtures", "config", "not_found.hcl"),
			Fallback: filepath.Join(currentDir, "test-fixtures", "config", "fallback.hcl"),
			Expected: &Config{
				Module:            false,
				Force:             true,
				IgnoreModules:     map[string]bool{},
				Varfiles:          []string{},
				Variables:         []string{},
				DisabledByDefault: true,
				Rules:             map[string]*RuleConfig{},
				Plugins:           map[string]*PluginConfig{},
			},
		},
		{
			Name:     "fallback file not found",
			File:     filepath.Join(currentDir, "test-fixtures", "config", "not_found.hcl"),
			Fallback: filepath.Join(currentDir, "test-fixtures", "config", "fallback_not_found.hcl"),
			Expected: EmptyConfig(),
		},
	}

	for _, tc := range cases {
		originalDefault := defaultConfigFile
		defaultConfigFile = filepath.Join(currentDir, "test-fixtures", "config", "not_found.hcl")
		originalFallback := fallbackConfigFile
		fallbackConfigFile = tc.Fallback

		ret, err := LoadConfig(tc.File)
		if err != nil {
			t.Fatalf("Failed `%s` test: Unexpected error occurred: %s", tc.Name, err)
		}

		opts := []cmp.Option{
			cmpopts.IgnoreUnexported(RuleConfig{}),
			cmpopts.IgnoreUnexported(PluginConfig{}),
			cmpopts.IgnoreFields(PluginConfig{}, "Body"),
			cmpopts.IgnoreFields(RuleConfig{}, "Body"),
		}
		if !cmp.Equal(tc.Expected, ret, opts...) {
			t.Fatalf("Failed `%s` test: diff=%s", tc.Name, cmp.Diff(tc.Expected, ret, opts...))
		}

		defaultConfigFile = originalDefault
		fallbackConfigFile = originalFallback
	}
}

func Test_LoadConfig_error(t *testing.T) {
	currentDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		Name     string
		File     string
		Expected string
	}{
		{
			Name: "file not found",
			File: filepath.Join(currentDir, "test-fixtures", "config", "not_found.hcl"),
			Expected: fmt.Sprintf(
				"`%s` is not found",
				filepath.Join(currentDir, "test-fixtures", "config", "not_found.hcl"),
			),
		},
		{
			Name: "syntax error",
			File: filepath.Join(currentDir, "test-fixtures", "config", "syntax_error.hcl"),
			Expected: fmt.Sprintf(
				"%s:1,1-2: Invalid character; The \"`\" character is not valid. To create a multi-line string, use the \"heredoc\" syntax, like \"<<EOT\"., and 1 other diagnostic(s)",
				filepath.Join(currentDir, "test-fixtures", "config", "syntax_error.hcl"),
			),
		},
		{
			Name: "invalid config",
			File: filepath.Join(currentDir, "test-fixtures", "config", "invalid.hcl"),
			Expected: fmt.Sprintf(
				"%s:1,34-42: Extraneous label for rule; Only 1 labels (name) are expected for rule blocks.",
				filepath.Join(currentDir, "test-fixtures", "config", "invalid.hcl"),
			),
		},
		{
			Name:     "terraform_version",
			File:     filepath.Join(currentDir, "test-fixtures", "config", "terraform_version.hcl"),
			Expected: "`terraform_version` was removed in v0.9.0 because the option is no longer used",
		},
		{
			Name:     "ignore_rule",
			File:     filepath.Join(currentDir, "test-fixtures", "config", "ignore_rule.hcl"),
			Expected: "`ignore_rule` was removed in v0.12.0. Please define `rule` block with `enabled = false` instead",
		},
		{
			Name: "deep_check",
			File: filepath.Join(currentDir, "test-fixtures", "config", "deep_check.hcl"),
			Expected: `global "deep_check" option was removed in v0.23.0. Please declare "plugin" block like the following:

plugin "aws" {
  enabled = true
  deep_check = true
}`,
		},
		{
			Name: "aws_credentials",
			File: filepath.Join(currentDir, "test-fixtures", "config", "aws_credentials.hcl"),
			Expected: `"aws_credentials" was removed in v0.23.0. Please declare "plugin" block like the following:

plugin "aws" {
  enabled = true
  deep_check = true
  access_key = ...
}`,
		},
	}

	for _, tc := range cases {
		_, err := LoadConfig(tc.File)
		if err == nil {
			t.Fatalf("Failed `%s` test: Expected error does not occurred", tc.Name)
		}

		if err.Error() != tc.Expected {
			t.Fatalf("Failed `%s` test: expected error is `%s`, but get `%s`", tc.Name, tc.Expected, err.Error())
		}
	}
}

func Test_Merge(t *testing.T) {
	file1, diags := hclsyntax.ParseConfig([]byte(`foo = "bar"`), "test.hcl", hcl.Pos{})
	if diags.HasErrors() {
		t.Fatalf("Failed to parse test config: %s", diags)
	}
	file2, diags := hclsyntax.ParseConfig([]byte(`bar = "baz"`), "test2.hcl", hcl.Pos{})
	if diags.HasErrors() {
		t.Fatalf("Failed to parse test config: %s", diags)
	}

	cfg := &Config{
		Module: true,
		Force:  true,
		IgnoreModules: map[string]bool{
			"github.com/terraform-linters/example-1": true,
			"github.com/terraform-linters/example-2": false,
		},
		Varfiles:          []string{"example1.tfvars", "example2.tfvars"},
		Variables:         []string{"foo=bar"},
		DisabledByDefault: false,
		Rules: map[string]*RuleConfig{
			"aws_instance_invalid_type": {
				Name:    "aws_instance_invalid_type",
				Enabled: false,
				Body:    file1.Body,
			},
			"aws_instance_invalid_ami": {
				Name:    "aws_instance_invalid_ami",
				Enabled: true,
				Body:    file2.Body,
			},
		},
		Plugins: map[string]*PluginConfig{},
	}

	cases := []struct {
		Name     string
		Base     *Config
		Other    *Config
		Expected *Config
	}{
		{
			Name:     "empty",
			Base:     EmptyConfig(),
			Other:    EmptyConfig(),
			Expected: EmptyConfig(),
		},
		{
			Name:     "prefer base",
			Base:     cfg,
			Other:    EmptyConfig(),
			Expected: cfg,
		},
		{
			Name:     "prefer other",
			Base:     EmptyConfig(),
			Other:    cfg,
			Expected: cfg,
		},
		{
			Name: "override and merge",
			Base: &Config{
				Module: true,
				Force:  false,
				IgnoreModules: map[string]bool{
					"github.com/terraform-linters/example-1": true,
					"github.com/terraform-linters/example-2": false,
				},
				Varfiles:          []string{"example1.tfvars", "example2.tfvars"},
				Variables:         []string{"foo=bar"},
				DisabledByDefault: false,
				Rules: map[string]*RuleConfig{
					"aws_instance_invalid_type": {
						Name:    "aws_instance_invalid_type",
						Enabled: false,
						Body:    file1.Body,
					},
					"aws_instance_invalid_ami": {
						Name:    "aws_instance_invalid_ami",
						Enabled: true,
						Body:    file1.Body,
					},
				},
				Plugins: map[string]*PluginConfig{
					"foo": {
						Name:    "foo",
						Enabled: true,
					},
					"bar": {
						Name:    "bar",
						Enabled: false,
					},
				},
			},
			Other: &Config{
				Module: false,
				Force:  true,
				IgnoreModules: map[string]bool{
					"github.com/terraform-linters/example-2": true,
					"github.com/terraform-linters/example-3": false,
				},
				Varfiles:          []string{"example3.tfvars"},
				Variables:         []string{"bar=baz"},
				DisabledByDefault: false,
				Rules: map[string]*RuleConfig{
					"aws_instance_invalid_ami": {
						Name:    "aws_instance_invalid_ami",
						Enabled: false,
						Body:    file2.Body,
					},
					"aws_instance_previous_type": {
						Name:    "aws_instance_previous_type",
						Enabled: false,
						Body:    file2.Body,
					},
				},
				Plugins: map[string]*PluginConfig{
					"baz": {
						Name:    "baz",
						Enabled: true,
					},
					"bar": {
						Name:    "bar",
						Enabled: true,
					},
				},
			},
			Expected: &Config{
				Module: true,
				Force:  true,
				IgnoreModules: map[string]bool{
					"github.com/terraform-linters/example-1": true,
					"github.com/terraform-linters/example-2": true,
					"github.com/terraform-linters/example-3": false,
				},
				Varfiles:          []string{"example1.tfvars", "example2.tfvars", "example3.tfvars"},
				Variables:         []string{"foo=bar", "bar=baz"},
				DisabledByDefault: false,
				Rules: map[string]*RuleConfig{
					"aws_instance_invalid_type": {
						Name:    "aws_instance_invalid_type",
						Enabled: false,
						Body:    file1.Body,
					},
					"aws_instance_invalid_ami": {
						Name:    "aws_instance_invalid_ami",
						Enabled: false,
						Body:    file2.Body,
					},
					"aws_instance_previous_type": {
						Name:    "aws_instance_previous_type",
						Enabled: false,
						Body:    file2.Body,
					},
				},
				Plugins: map[string]*PluginConfig{
					"foo": {
						Name:    "foo",
						Enabled: true,
					},
					"bar": {
						Name:    "bar",
						Enabled: true,
					},
					"baz": {
						Name:    "baz",
						Enabled: true,
					},
				},
			},
		},
		{
			Name: "CLI --only argument and merge",
			Base: &Config{
				Module: true,
				Force:  false,
				IgnoreModules: map[string]bool{
					"github.com/terraform-linters/example-1": true,
					"github.com/terraform-linters/example-2": false,
				},
				Varfiles:          []string{"example1.tfvars", "example2.tfvars"},
				Variables:         []string{"foo=bar"},
				DisabledByDefault: false,
				Rules: map[string]*RuleConfig{
					"aws_instance_invalid_type": {
						Name:    "aws_instance_invalid_type",
						Enabled: false,
						Body:    file1.Body,
					},
					"aws_instance_invalid_ami": {
						Name:    "aws_instance_invalid_ami",
						Enabled: false,
						Body:    file1.Body,
					},
				},
				Plugins: map[string]*PluginConfig{
					"foo": {
						Name:    "foo",
						Enabled: true,
					},
					"bar": {
						Name:    "bar",
						Enabled: false,
					},
				},
			},
			Other: &Config{
				Module: false,
				Force:  true,
				IgnoreModules: map[string]bool{
					"github.com/terraform-linters/example-2": true,
					"github.com/terraform-linters/example-3": false,
				},
				Varfiles:          []string{"example3.tfvars"},
				Variables:         []string{"bar=baz"},
				DisabledByDefault: true,
				Rules: map[string]*RuleConfig{
					"aws_instance_invalid_type": {
						Name:    "aws_instance_invalid_type",
						Enabled: true,
						Body:    hcl.EmptyBody(),
					},
					"aws_instance_previous_type": {
						Name:    "aws_instance_previous_type",
						Enabled: true,
						Body:    hcl.EmptyBody(), // Will not attach, missing config
					},
				},
				Plugins: map[string]*PluginConfig{
					"baz": {
						Name:    "baz",
						Enabled: true,
					},
					"bar": {
						Name:    "bar",
						Enabled: true,
					},
				},
			},
			Expected: &Config{
				Module: true,
				Force:  true,
				IgnoreModules: map[string]bool{
					"github.com/terraform-linters/example-1": true,
					"github.com/terraform-linters/example-2": true,
					"github.com/terraform-linters/example-3": false,
				},
				Varfiles:          []string{"example1.tfvars", "example2.tfvars", "example3.tfvars"},
				Variables:         []string{"foo=bar", "bar=baz"},
				DisabledByDefault: true,
				Rules: map[string]*RuleConfig{
					"aws_instance_invalid_type": {
						Name:    "aws_instance_invalid_type",
						Enabled: true, // Passing an --only rule from CLI will always enable
						Body:    file1.Body,
					},
					"aws_instance_previous_type": {
						Name:    "aws_instance_previous_type",
						Enabled: true,
						Body:    hcl.EmptyBody(),
					},
					"aws_instance_invalid_ami": {
						Name:    "aws_instance_invalid_ami",
						Enabled: false,
						Body:    file1.Body,
					},
				},
				Plugins: map[string]*PluginConfig{
					"foo": {
						Name:    "foo",
						Enabled: true,
					},
					"bar": {
						Name:    "bar",
						Enabled: true,
					},
					"baz": {
						Name:    "baz",
						Enabled: true,
					},
				},
			},
		},
		{
			Name: "merge rule config with CLI-based config",
			Base: &Config{
				Module:            false,
				Force:             false,
				IgnoreModules:     map[string]bool{},
				Varfiles:          []string{},
				Variables:         []string{},
				DisabledByDefault: false,
				Rules: map[string]*RuleConfig{
					"aws_instance_invalid_type": {
						Name:    "aws_instance_invalid_type",
						Enabled: false,
						Body:    file1.Body,
					},
				},
				Plugins: map[string]*PluginConfig{},
			},
			Other: &Config{
				Module:            false,
				Force:             false,
				IgnoreModules:     map[string]bool{},
				Varfiles:          []string{},
				Variables:         []string{},
				DisabledByDefault: false,
				Rules: map[string]*RuleConfig{
					"aws_instance_invalid_type": {
						Name:    "aws_instance_invalid_type",
						Enabled: true,
						Body:    hcl.EmptyBody(),
					},
				},
				Plugins: map[string]*PluginConfig{},
			},
			Expected: &Config{
				Module:            false,
				Force:             false,
				IgnoreModules:     map[string]bool{},
				Varfiles:          []string{},
				Variables:         []string{},
				DisabledByDefault: false,
				Rules: map[string]*RuleConfig{
					"aws_instance_invalid_type": {
						Name:    "aws_instance_invalid_type",
						Enabled: true,       // overridden
						Body:    file1.Body, // keep
					},
				},
				Plugins: map[string]*PluginConfig{},
			},
		},
	}

	for _, tc := range cases {
		ret := tc.Base.Merge(tc.Other)

		opts := []cmp.Option{
			cmpopts.IgnoreUnexported(RuleConfig{}),
			cmpopts.IgnoreUnexported(PluginConfig{}),
			cmpopts.IgnoreUnexported(hclsyntax.Body{}),
			cmpopts.IgnoreFields(hclsyntax.Body{}, "Attributes", "Blocks"),
		}
		if !cmp.Equal(tc.Expected, ret, opts...) {
			t.Fatalf("Failed `%s` test: diff=%s", tc.Name, cmp.Diff(tc.Expected, ret, opts...))
		}
	}
}

func Test_ToPluginConfig(t *testing.T) {
	currentDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	config, err := LoadConfig(filepath.Join(currentDir, "test-fixtures", "config", "plugin.hcl"))
	if err != nil {
		t.Fatalf("Failed: Unexpected error occurred: %s", err)
	}

	ret := config.ToPluginConfig("foo")
	expected := &tfplugin.MarshalledConfig{
		Rules: map[string]*tfplugin.RuleConfig{
			"aws_instance_invalid_type": {
				Name:    "aws_instance_invalid_type",
				Enabled: false,
			},
			"aws_instance_invalid_ami": {
				Name:    "aws_instance_invalid_ami",
				Enabled: true,
			},
		},
		DisabledByDefault: true,
		BodyRange:         hcl.Range{Start: hcl.Pos{Line: 14, Column: 3}, End: hcl.Pos{Line: 16, Column: 17}},
	}
	opts := cmp.Options{
		cmpopts.IgnoreUnexported(PluginConfig{}),
		cmpopts.IgnoreFields(hcl.Range{}, "Filename"),
		cmpopts.IgnoreFields(hcl.Pos{}, "Byte"),
		cmpopts.IgnoreFields(tfplugin.MarshalledConfig{}, "BodyBytes"),
	}
	if !cmp.Equal(expected, ret, opts...) {
		t.Fatalf("Failed to match: %s", cmp.Diff(expected, ret, opts...))
	}
}

func Test_ToPluginConfig_noPluginConfig(t *testing.T) {
	config := EmptyConfig()
	config.Plugins["foo"] = &PluginConfig{Name: "foo", Enabled: true}

	ret := config.ToPluginConfig("foo")
	expected := &tfplugin.MarshalledConfig{
		Rules: map[string]*tfplugin.RuleConfig{},
	}

	opts := cmp.Options{
		cmpopts.IgnoreUnexported(PluginConfig{}),
	}
	if !cmp.Equal(expected, ret, opts...) {
		t.Fatalf("Failed to match: %s", cmp.Diff(expected, ret, opts...))
	}
}

type ruleSetA struct{}

func (*ruleSetA) RuleSetName() (string, error) {
	return "ruleSetA", nil
}
func (*ruleSetA) RuleSetVersion() (string, error) {
	return "0.1.0", nil
}
func (*ruleSetA) RuleNames() ([]string, error) {
	return []string{"aws_instance_invalid_type"}, nil
}

type ruleSetB struct{}

func (*ruleSetB) RuleSetName() (string, error) {
	return "ruleSetB", nil
}
func (*ruleSetB) RuleSetVersion() (string, error) {
	return "0.1.0", nil
}
func (*ruleSetB) RuleNames() ([]string, error) {
	return []string{"aws_instance_invalid_ami"}, nil
}

func Test_ValidateRules(t *testing.T) {
	config := &Config{
		Rules: map[string]*RuleConfig{
			"aws_instance_invalid_type": {
				Name:    "aws_instance_invalid_type",
				Enabled: false,
			},
			"aws_instance_invalid_ami": {
				Name:    "aws_instance_invalid_ami",
				Enabled: true,
			},
		},
	}

	cases := []struct {
		Name     string
		Config   *Config
		RuleSets []RuleSet
		Err      error
	}{
		{
			Name:     "valid",
			Config:   config,
			RuleSets: []RuleSet{&ruleSetA{}, &ruleSetB{}},
			Err:      nil,
		},
		{
			Name:     "duplicate",
			Config:   config,
			RuleSets: []RuleSet{&ruleSetA{}, &ruleSetB{}, &ruleSetB{}},
			Err:      errors.New("`aws_instance_invalid_ami` is duplicated in ruleSetB and ruleSetB"),
		},
		{
			Name:     "not found",
			Config:   config,
			RuleSets: []RuleSet{&ruleSetB{}},
			Err:      errors.New("Rule not found: aws_instance_invalid_type"),
		},
		{
			Name: "removed rule",
			Config: &Config{
				Rules: map[string]*RuleConfig{
					"terraform_dash_in_resource_name": {
						Name:    "terraform_dash_in_resource_name",
						Enabled: true,
					},
				},
			},
			RuleSets: []RuleSet{&ruleSetA{}, &ruleSetB{}},
			Err:      errors.New("`terraform_dash_in_resource_name` rule was removed in v0.16.0. Please use `terraform_naming_convention` rule instead"),
		},
	}

	for _, tc := range cases {
		err := tc.Config.ValidateRules(tc.RuleSets...)

		if tc.Err == nil {
			if err != nil {
				t.Fatalf("Failed %s: Unexpected error occurred: %s", tc.Name, err)
			}
		} else {
			if err == nil {
				t.Fatalf("Failed %s: Error should have occurred, but didn't", tc.Name)
			}
			if err.Error() != tc.Err.Error() {
				t.Fatalf("Failed %s: error message is not matched: want=%s got=%s", tc.Name, tc.Err, err)
			}
		}
	}
}

func Test_copy(t *testing.T) {
	cfg := &Config{
		Module: true,
		Force:  true,
		IgnoreModules: map[string]bool{
			"github.com/terraform-linters/example-1": true,
			"github.com/terraform-linters/example-2": false,
		},
		Varfiles:          []string{"example1.tfvars", "example2.tfvars"},
		Variables:         []string{},
		DisabledByDefault: true,
		Rules: map[string]*RuleConfig{
			"aws_instance_invalid_type": {
				Name:    "aws_instance_invalid_type",
				Enabled: false,
			},
			"aws_instance_invalid_ami": {
				Name:    "aws_instance_invalid_ami",
				Enabled: true,
			},
		},
		Plugins: map[string]*PluginConfig{
			"foo": {
				Name:    "foo",
				Enabled: true,
			},
			"bar": {
				Name:    "bar",
				Enabled: false,
			},
		},
	}

	cases := []struct {
		Name       string
		SideEffect func(*Config)
	}{
		{
			Name: "Module",
			SideEffect: func(c *Config) {
				c.Module = false
			},
		},
		{
			Name: "Force",
			SideEffect: func(c *Config) {
				c.Force = false
			},
		},
		{
			Name: "DisabledByDefault",
			SideEffect: func(c *Config) {
				c.DisabledByDefault = false
			},
		},
		{
			Name: "IgnoreModules",
			SideEffect: func(c *Config) {
				c.IgnoreModules["github.com/terraform-linters/example-1"] = false
			},
		},
		{
			Name: "Varfiles",
			SideEffect: func(c *Config) {
				c.Varfiles = append(c.Varfiles, "new.tfvars")
			},
		},
		{
			Name: "Variables",
			SideEffect: func(c *Config) {
				c.Variables = append(c.Variables, "baz=foo")
			},
		},
		{
			Name: "Rules",
			SideEffect: func(c *Config) {
				c.Rules["aws_instance_invalid_type"].Enabled = true
			},
		},
		{
			Name: "Plugins",
			SideEffect: func(c *Config) {
				c.Plugins["foo"].Enabled = false
			},
		},
	}

	opts := []cmp.Option{
		cmpopts.IgnoreUnexported(RuleConfig{}),
		cmpopts.IgnoreUnexported(PluginConfig{}),
	}
	for _, tc := range cases {
		ret := cfg.copy()
		if !cmp.Equal(cfg, ret, opts...) {
			t.Fatalf("The copied config doesn't match original: Diff=%s", cmp.Diff(cfg, ret, opts...))
		}

		tc.SideEffect(ret)
		if cmp.Equal(cfg, ret, opts...) {
			t.Fatalf("The original was changed when updating `%s`", tc.Name)
		}
	}
}
