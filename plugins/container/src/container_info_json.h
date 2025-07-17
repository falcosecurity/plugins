#pragma once

#include "container_info.h"

#include <nlohmann/json.hpp>

void from_json(const nlohmann::json& j, container_health_probe& probe);
void from_json(const nlohmann::json& j, container_mount_info& mount);
void from_json(const nlohmann::json& j, container_port_mapping& port);
void from_json(const nlohmann::json& j, std::shared_ptr<container_info>& cinfo);

void to_json(nlohmann::json& j, const container_health_probe& probe);
void to_json(nlohmann::json& j, const container_mount_info& mount);
void to_json(nlohmann::json& j, const container_port_mapping& port);
void to_json(nlohmann::json& j,
             const std::shared_ptr<const container_info>& cinfo);
