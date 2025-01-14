#pragma once

#include "GView.hpp"

#include <any>
#include <array>
#include <map>
#include <nlohmann/json.hpp>
#include <cstdlib>
#include <codecvt>

namespace GView::GenericPlugins::FileAnalysis
{
using namespace AppCUI;
using namespace AppCUI::Utils;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;
using namespace GView::View;
using namespace GView::Hashes;

enum class Hashes : uint32 {
    None   = 0,
    MD5    = 1,
    SHA1   = 2,
    SHA256 = 3,
};

// Function declarations
bool UploadFile(Reference<GView::Object> object, std::string& response);
bool GetFileReport(Reference<GView::Object> object, std::string& response);
std::string ComputeHash(Reference<GView::Object> object, Hashes hash_type);

} // namespace GView::GenericPlugins::FileAnalysis
