# Release Process

Our release process is automated by several [Prow jobs](https://github.com/falcosecurity/test-infra/blob/master/config/jobs/build-plugins/build-plugins.yaml). 

The process publishes two types of artifacts:
- **dev** builds: the process is fully automated, and it is triggered when changes are merged into `master` branch
- **stable** builds: the process is automated, but it needs to be manually triggered by tagging a plugin with a release version (see the [section](#Stable-builds) below)

Artifacts will be published at https://download.falco.org/?prefix=plugins/.


## Stable build

Since the *plugins* repository is a [monorepo](https://en.wikipedia.org/wiki/Monorepo), we introduced a special convention for tagging release versions, so that we can differentiate among plugins. Git tag MUST respect the following format:

*name*-*version*

Where *name* is the plugin name (must match a folder under [./plugins](./plugins)) and *version* is the plugin version to be released (must match the version string declared by the plugin).


## Initiating a plugin release (stable build)

When we release, we do the following process:

1. When changes are introduced to a plugin (i.e. a PR gets merged) and its version has been bumped, we choose the git tag based on the above convention
2. A person with repository rights [creates a new release](https://github.com/falcosecurity/plugins/releases) from the GitHub UI
3. Once the CI has done its job, the tag is live on [Github](https://github.com/falcosecurity/plugins/releases), and the plugin package is published at [download.falco.org](https://download.falco.org/?prefix=plugins/stable)
