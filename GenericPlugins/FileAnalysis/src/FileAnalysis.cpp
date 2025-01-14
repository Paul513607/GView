#define CURL_STATICLIB

#include "FileAnalysis.hpp"

#include "curl/curl.h"

#pragma comment(lib, "Normaliz.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Wldap32.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "advapi32.lib")

#undef MessageBox

namespace GView::GenericPlugins::FileAnalysis
{
static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* outputBuffer)
{
    size_t totalSize = size * nmemb;
    if (outputBuffer) {
        outputBuffer->append(static_cast<char*>(contents), totalSize);
    }
    return totalSize;
}

bool getenv(const char* name, std::string& env)
{
    const char* ret = std::getenv(name);
    if (ret)
        env = std::string(ret);
    return !!ret;
}

static bool UploadFile(Reference<GView::Object> object, std::string& response)
{
    if (!object.IsValid()) {
        return false;
    }

     CURL* curl = curl_easy_init();
     if (!curl) {
         return false;
     }

     const auto filePath = object->GetPath(); // std::u16string_view

     std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> converter;
     std::string filePathStr = converter.to_bytes(filePath.data(), filePath.data() + filePath.size());

     std::string apiKey;
     if (!getenv("VIRUSTOTAL_API_KEY", apiKey)) {
         return false;
     }

     struct curl_slist* headers = nullptr;
     headers                    = curl_slist_append(headers, ("x-apikey: " + apiKey).c_str());

     struct curl_httppost* form = nullptr;
     struct curl_httppost* last = nullptr;

     curl_formadd(&form, &last, CURLFORM_COPYNAME, "file", CURLFORM_FILE, filePathStr.c_str(), CURLFORM_END);

     response.clear();
     curl_easy_setopt(curl, CURLOPT_URL, "https://www.virustotal.com/api/v3/files");
     curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
     curl_easy_setopt(curl, CURLOPT_HTTPPOST, form);
     curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
     curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

     CURLcode res = curl_easy_perform(curl);
     curl_easy_cleanup(curl);
     curl_formfree(form);
     curl_slist_free_all(headers);

     return res == CURLE_OK;
}

static bool GetFileReport(Reference<GView::Object> object, std::string& response)
{
    if (!object.IsValid()) {
        return false;
    }

     CURL* curl = curl_easy_init();
     if (!curl) {
         return false;
     }

     std::string fileHash = "d50fa9b5d542aa37b75123c0a0ac399a70a6a01988a748742cf6cfb407f19071";
     std::string apiKey;
     if (!getenv("VIRUSTOTAL_API_KEY", apiKey)) {
         return false;
     }

     std::string url = "https://www.virustotal.com/api/v3/files/" + fileHash;

     struct curl_slist* headers = nullptr;
     headers                    = curl_slist_append(headers, ("x-apikey: " + apiKey).c_str());

     response.clear();
     curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
     curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
     curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
     curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

     CURLcode res = curl_easy_perform(curl);
     curl_easy_cleanup(curl);
     curl_slist_free_all(headers);

     return res == CURLE_OK;
}

static std::string ComputeHash(Reference<GView::Object> object, Hashes hashType)
{
    return "";
}
} // namespace GView::GenericPlugins::FileAnalysis


extern "C"
{
PLUGIN_EXPORT bool Run(const string_view command, Reference<GView::Object> object)
{
    if (command == "UploadCurrent") {
        std::string response;
        if (!GView::GenericPlugins::FileAnalysis::UploadFile(object, response)) {
            Dialogs::MessageBox::ShowError("Error!", "Failed to upload file to VirusTotal.");
            return false;
        }

        auto json = nlohmann::json::parse(response, nullptr, false);
        if (!json.is_discarded()) {
            AppCUI::OS::Clipboard::SetText(json.dump());
            Dialogs::MessageBox::ShowNotification("Upload Success", "File uploaded successfully to VirusTotal. Response copied.");
        } else {
            Dialogs::MessageBox::ShowNotification("Upload Success", "File uploaded successfully to VirusTotal.");
        }

        return true;
    } else if (command == "CheckByHash") {
        std::string response;
        if (!GView::GenericPlugins::FileAnalysis::GetFileReport(object, response)) {
            Dialogs::MessageBox::ShowError("Error!", "Failed to fetch file report from VirusTotal.");
            return false;
        }

        auto json = nlohmann::json::parse(response, nullptr, false);
        if (!json.is_discarded()) {
            AppCUI::OS::Clipboard::SetText(json.dump());
            Dialogs::MessageBox::ShowNotification("Report Retrieved", "File report copied to clipboard.");
        } else {
            Dialogs::MessageBox::ShowNotification("Report Retrieved", "File report fetched successfully from VirusTotal.");
        }

        return true;
    }

    return false;
}

PLUGIN_EXPORT void UpdateSettings(IniSection sect)
{
    sect["Command.UploadCurrent"] = Input::Key::F6;
    sect["Command.CheckByHash"]   = Input::Key::F7;
}
}
