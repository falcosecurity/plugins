/*
Copyright (C) 2023 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <falcosecurity/api/event_sourcing.h>
#include <falcosecurity/api/field_extraction.h>
#include "dummy.h"

std::unique_ptr<falcosecurity::plugin> falcosecurity::factory() noexcept
{
    return std::unique_ptr<falcosecurity::plugin>(new dummy_plugin());
}
