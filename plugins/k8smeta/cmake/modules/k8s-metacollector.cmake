message(
  STATUS
    "Fetching k8s-metacollector at 'https://github.com/falcosecurity/k8s-metacollector.git'"
)

# Download a non cmake project
FetchContent_Declare(
  k8s-metacollector
  GIT_REPOSITORY https://github.com/falcosecurity/k8s-metacollector.git
  GIT_TAG 982c40ac128cc94557b98d81210cbb13e7825129
  CONFIGURE_COMMAND "" BUILD_COMMAND "")

FetchContent_Populate(k8s-metacollector)
set(K8S_METACOLLECTOR_DIR "${k8s-metacollector_SOURCE_DIR}")
