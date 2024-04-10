# Release Process

Our release process is automated by a couple of GitHub Actions ([`Update Plugins-dev`](https://github.com/falcosecurity/plugins/blob/main/.github/workflows/main.yml) and [`Release Plugins`](https://github.com/falcosecurity/plugins/blob/main/.github/workflows/release.yml)). 

The process publishes two types of releases:
- **dev** builds: the process is fully automated, and it is triggered when changes are merged into `main` branch
- **stable** builds: the process is automated, but it needs to be manually triggered by tagging a plugin with a release version (see the [section](#Stable-builds) below)

Regardless of the type, if a plugin provides a ruleset, the ruleset is released, too, with the same version number. This may change in the future. Also, see [Versioning a rulset](https://github.com/falcosecurity/rules/blob/main/RELEASE.md#versioning-a-ruleset) guidelines before deciding the release version number.

Artifacts will be published at https://download.falco.org/?prefix=plugins/. For *stable* builds, [OCI artifacts](https://github.com/orgs/falcosecurity/packages?repo_name=plugins) are published too. They can be consumed with [falcoctl](https://github.com/falcosecurity/falcoctl).


## Tag format (stable build only)

Since the *plugins* repository is a [monorepo](https://en.wikipedia.org/wiki/Monorepo), we introduced a special convention for tagging release versions, so that we can differentiate among plugins. Git tag MUST respect the following format:

*plugins*/**name**/*v***version** e.x: plugins/cloudtrail/v1.2.3

Where **name** is the plugin name (must match a folder under [./plugins](./plugins)) and **version** is the plugin version to be released (must match the version string declared by the plugin).


## Release a plugin (stable build only)

When we release, we do the following process:

1. When changes are introduced to a plugin (i.e. a PR gets merged) and its version has been bumped, we choose the git tag based on the above convention
2. A person with repository rights [creates a new release](https://github.com/falcosecurity/plugins/releases) from the GitHub UI
3. Once the CI has done its job:
   1. the tag is live on [Github](https://github.com/falcosecurity/plugins/releases);
   2. the plugin package is published at [download.falco.org](https://download.falco.org/?prefix=plugins/stable);
   3. the OCI artifact is published at [ghcr.io](https://github.com/orgs/falcosecurity/packages).
