# CloudVision Packages

## Overview

This repository contains a number of example packages available to install directly into CloudVision and to serve as reference to those designing their own.
**Ready-to-install package artifacts are available on the [releases page](https://github.com/aristanetworks/cloudvision-packages/releases)**
**Please note that packages in the trunk branch may not be compatible with your installation of CloudVision. Please refer to the branch/[release](https://github.com/aristanetworks/cloudvision-packages/releases) corresponding to your CloudVision version for compatible packages.**
Packages are forwards compatible within a CloudVision release, with new releases in a maintenance train only being made if bugs are addressed. If a release does not exist for the your latest running maintenance version of CloudVision, then the latest release of that train has the most up-to-date packages and will work on your installation, e.g. 2025.1.0 artifacts work for CloudVision version 2025.1.1, 2025.1.2, etc.
CVaaS users are directed to install the latest release artifacts on their systems.

Once uploaded onto a CloudVision cluster, these packages may be duplicated and further customised for specific use cases.
Packages listed in `bundled.txt` are **_bundled by default_** with CloudVision on-premises installations.

## How to Upload Packages to a CloudVision cluster

The Packaging tab under general settings in CloudVision can be used to install or remove packages downloaded from the [releases page](https://github.com/aristanetworks/cloudvision-packages/releases).

## Creating artifacts from source

It is also possible to create the artifacts by hand from the source code and upload them via the packaging UI. The following steps outline this approach.

### Pre-requisites

* `git`
* `tar`
* `make` (optional, used for tarring up multiple packs at once)

### Steps

#### Prepare the package

* Clone the github repo into a folder using `git clone`
* (Optional) Check out the branch/tag associated with the wanted release e.g. `git checkout 2025.2`
* Run `make packages` to create artifacts for all packages in the `src` directly. These will be added to a `gen` folder in the root of the repository
  * This can alternatively be manually done by using `tar` on a package while you are in the `src` directory. The name of the tar is not important as the config file is referenced for naming purposes, but it is good practice to use the same name as the as the directory you are tarring, and include the version string.

##### Manual workflow example

**Note**: This example is using the `network-infra-health-package` package, which is bundled by default, for a CloudVision `2025.1.*` installation.

###### Creating the package tar

* Clone the repo, enter it, and `checkout` the version of CloudVision that is being run

``` Shell
> git clone git@github.com:aristanetworks/cloudvision-packages.git
...
> cd cloudvision-packages
> git checkout 2025.1
```

* `tar` up the desired package as shown below:

``` Shell
> tar -C src -cvf gen/network-infra-health-package_1.1.3.tar network-infra-health-package
a network-infra-health-package
a network-infra-health-package/dashboard-network-infra-health
a network-infra-health-package/config.yaml
a network-infra-health-package/dashboard-network-infra-health/config.yaml
```