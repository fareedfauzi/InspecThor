#pragma once

#include "target_resolver.h"

namespace Inspecthor {

bool IsSupportedOfficeTarget(const std::wstring& path);
TargetProfile ResolveOfficeTargetProfile(const std::wstring& targetPath, const std::wstring& userArguments);

} // namespace Inspecthor
