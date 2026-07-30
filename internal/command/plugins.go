// Copyright IBM Corp. 2014, 2026
// SPDX-License-Identifier: BUSL-1.1

package command

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	plugin "github.com/hashicorp/go-plugin"
	"github.com/kardianos/osext"

	fileprovisioner "github.com/hashicorp/terraform/internal/builtin/provisioners/file"
	localexec "github.com/hashicorp/terraform/internal/builtin/provisioners/local-exec"
	remoteexec "github.com/hashicorp/terraform/internal/builtin/provisioners/remote-exec"
	"github.com/hashicorp/terraform/internal/logging"
	tfplugin "github.com/hashicorp/terraform/internal/plugin"
	"github.com/hashicorp/terraform/internal/plugin/discovery"
	"github.com/hashicorp/terraform/internal/provisioners"
)

// NOTE WELL: The logic in this file is primarily about plugin types OTHER THAN
// providers, which use an older set of approaches implemented here.
//
// The provider-related functions live primarily in meta_providers.go, and
// lean on some different underlying mechanisms in order to support automatic
// installation and a hierarchical addressing namespace, neither of which
// are supported for other plugin types.

// store the user-supplied path for plugin discovery
func (m *Meta) storePluginPath(pluginPath []string) error {
	if len(pluginPath) == 0 {
		return nil
	}

	m.fixupMissingWorkingDir()

	// remove the plugin dir record if the path was set to an empty string
	if len(pluginPath) == 1 && (pluginPath[0] == "") {
		return m.WorkingDir.SetForcedPluginDirs(nil)
	}

	return m.WorkingDir.SetForcedPluginDirs(pluginPath)
}

// Load the user-defined plugin search path into Meta.pluginPath if the file
// exists.
func (m *Meta) loadPluginPath() ([]string, error) {
	m.fixupMissingWorkingDir()
	return m.WorkingDir.ForcedPluginDirs()
}

// the default location for automatically installed plugins
func (m *Meta) pluginDir() string {
	return filepath.Join(m.DataDir(), "plugins", fmt.Sprintf("%s_%s", runtime.GOOS, runtime.GOARCH))
}

// pluginDirs return a list of directories to search for plugins.
//
// Earlier entries in this slice get priority over later when multiple copies
// of the same plugin version are found, but newer versions always override
// older versions where both satisfy the provider version constraints.
func (m *Meta) pluginDirs(includeAutoInstalled bool) []string {
	// user defined paths take precedence
	if len(m.pluginPath) > 0 {
		return m.pluginPath
	}

	// When searching the following directories, earlier entries get precedence
	// if the same plugin version is found twice, but newer versions will
	// always get preference below regardless of where they are coming from.
	// TODO: Add auto-install dir, default vendor dir and optional override
	// vendor dir(s).
	dirs := []string{"."}

	// Look in the same directory as the Terraform executable.
	// If found, this replaces what we found in the config path.
	exePath, err := osext.Executable()
	if err != nil {
		log.Printf("[ERROR] Error discovering exe directory: %s", err)
	} else {
		dirs = append(dirs, filepath.Dir(exePath))
	}

	// add the user vendor directory
	dirs = append(dirs, DefaultPluginVendorDir)

	if includeAutoInstalled {
		dirs = append(dirs, m.pluginDir())
	}
	dirs = append(dirs, m.GlobalPluginDirs...)

	return dirs
}

func (m *Meta) provisionerFactories() map[string]provisioners.Factory {
	dirs := m.pluginDirs(true)
	plugins := discovery.FindPlugins("provisioner", dirs)
	plugins, _ = plugins.ValidateVersions()

	// For now our goal is to just find the latest version of each plugin
	// we have on the system. All provisioners should be at version 0.0.0
	// currently, so there should actually only be one instance of each plugin
	// name here, even though the discovery interface forces us to pretend
	// that might not be true.

	factories := make(map[string]provisioners.Factory)

	// Wire up the internal provisioners first. These might be overridden
	// by discovered provisioners below.
	for name, factory := range internalProvisionerFactories() {
		factories[name] = factory
	}

	byName := plugins.ByName()
	for name, metas := range byName {
		// Since we validated versions above and we partitioned the sets
		// by name, we're guaranteed that the metas in our set all have
		// valid versions and that there's at least one meta.
		newest := metas.Newest()

		factories[name] = provisionerFactory(newest)
	}

	return factories
}

// validatePluginPath checks that the given path is a clean absolute path
// pointing to a regular executable file, preventing path traversal and
// injection of unexpected binaries into exec.Command.
func validatePluginPath(path string) error {
	// Require an absolute path to prevent relative-path traversal attacks.
	if !filepath.IsAbs(path) {
		return fmt.Errorf("plugin path must be absolute, got: %q", path)
	}

	// Ensure the path is clean (no ".." segments or redundant separators).
	if filepath.Clean(path) != path {
		return fmt.Errorf("plugin path is not clean (possible path traversal): %q", path)
	}

	// Verify the path resolves to a regular file (not a directory or device).
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("plugin path is not accessible %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("plugin path is not a regular file: %q", path)
	}

	// Verify the file has execute permission for at least one user class.
	if info.Mode()&0111 == 0 {
		return fmt.Errorf("plugin path is not executable: %q", path)
	}

	return nil
}

func provisionerFactory(meta discovery.PluginMeta) provisioners.Factory {
	return func() (provisioners.Interface, error) {
		// Resolve the executable path to an absolute, clean path to prevent
		// path traversal attacks before passing it to exec.Command.
		execPath, err := filepath.Abs(meta.Path)
		if err != nil {
			return nil, fmt.Errorf("could not resolve provisioner executable path: %w", err)
		}
		execPath = filepath.Clean(execPath)

		// Confirm the resolved executable path is within the expected plugin
		// directory, preventing execution of binaries outside that directory.
		pluginDir := filepath.Clean(filepath.Dir(execPath))
		if !strings.HasPrefix(execPath, pluginDir+string(filepath.Separator)) && execPath != pluginDir {
			return nil, fmt.Errorf("provisioner executable %q is not within the expected plugin directory %q", execPath, pluginDir)
		}

		if err := validatePluginPath(execPath); err != nil {
			return nil, fmt.Errorf("invalid provisioner plugin path: %w", err)
		}
		cfg := &plugin.ClientConfig{
			Cmd:              exec.Command(execPath),
			HandshakeConfig:  tfplugin.Handshake,
			VersionedPlugins: tfplugin.VersionedPlugins,
			Managed:          true,
			Logger:           logging.NewLogger("provisioner"),
			AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},
			AutoMTLS:         enableProviderAutoMTLS,
			SyncStdout:       logging.PluginOutputMonitor(fmt.Sprintf("%s:stdout", meta.Name)),
			SyncStderr:       logging.PluginOutputMonitor(fmt.Sprintf("%s:stderr", meta.Name)),
		}
		client := plugin.NewClient(cfg)
		return newProvisionerClient(client)
	}
}

func internalProvisionerFactories() map[string]provisioners.Factory {
	return map[string]provisioners.Factory{
		"file":        provisioners.FactoryFixed(fileprovisioner.New()),
		"local-exec":  provisioners.FactoryFixed(localexec.New()),
		"remote-exec": provisioners.FactoryFixed(remoteexec.New()),
	}
}

func newProvisionerClient(client *plugin.Client) (provisioners.Interface, error) {
	// Request the RPC client so we can get the provisioner
	// so we can build the actual RPC-implemented provisioner.
	rpcClient, err := client.Client()
	if err != nil {
		return nil, err
	}

	raw, err := rpcClient.Dispense(tfplugin.ProvisionerPluginName)
	if err != nil {
		return nil, err
	}

	// store the client so that the plugin can kill the child process
	p := raw.(*tfplugin.GRPCProvisioner)
	p.PluginClient = client
	return p, nil
}
