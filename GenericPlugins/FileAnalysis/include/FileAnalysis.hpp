#pragma once

#include "GView.hpp"

#include <any>
#include <array>
#include <map>
#include <curl/curl.h>
#include <nlohmann/json.hpp>

namespace GView::GenericPlugins::FileAnalysis
{
using namespace AppCUI;
using namespace AppCUI::Utils;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;
using namespace GView::View;
using namespace GView::Hashes;

class VirusTotalUploader
{
  public:
    static bool UploadFile(const std::string& filePath, const std::string& apiKey, std::string& response);

  private:
    static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* outputBuffer);
};

class VirusTotalReport
{
  public:
    static bool GetFileReport(const std::string& fileHash, const std::string& apiKey, std::string& response);

  private:
    static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* outputBuffer);
};

class FileHasher
{
  public:
    static bool ComputeHashes(const std::string& filePath, std::map<std::string, std::string>& hashResults, const std::vector<std::string>& hashTypes);
};

} // namespace GView::GenericPlugins::FileAnalysis
