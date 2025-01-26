#define CURL_STATICLIB

#include "FileAnalysis.hpp"



#pragma comment(lib, "Normaliz.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Wldap32.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "advapi32.lib")

#undef MessageBox

namespace GView::GenericPlugins::FileAnalysis
{
constexpr std::string_view CMD_UPLOAD_CURRENT = "UploadCurrent";
constexpr std::string_view CMD_CHECK_BY_HASH = "CheckByHash";

constexpr std::string_view MSG_OBJECT_NOT_VALID = "Current object is not valid.";
constexpr std::string_view MSG_CURL_COULD_NOT_BE_INITIATED = "CURL could not be initiated.";
constexpr std::string_view MSG_VIRUSTOTAL_API_KEY_NOT_FOUND = "VIRUSTOTAL_API_KEY not found in evironment.";

static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* outputBuffer)
{
    size_t totalSize = size * nmemb;
    if (outputBuffer) {
        outputBuffer->append(static_cast<char*>(contents), totalSize);
    }
    return totalSize;
}

static bool GetEnv(const char* name, std::string& env)
{
    const char* ret = std::getenv(name);
    if (ret)
        env = std::string(ret);
    return !!ret;
}

static std::string FilePathFromGViewObject(Reference<GView::Object> object)
{
    const auto filePath = object->GetPath(); // std::u16string_view

    std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> converter;
    std::string filePathStr = converter.to_bytes(filePath.data(), filePath.data() + filePath.size());

    return filePathStr;
}

static bool UploadFile(Reference<GView::Object> object, std::string& response)
{
    if (!object.IsValid()) {
        response = MSG_OBJECT_NOT_VALID;
        return false;
    }

     CURL* curl = curl_easy_init();
     if (!curl) {
         response = MSG_CURL_COULD_NOT_BE_INITIATED;
         return false;
     }

     std::string filePathStr = FilePathFromGViewObject(object);

     std::string apiKey;
     if (!GetEnv("VIRUSTOTAL_API_KEY", apiKey)) {
         response = MSG_VIRUSTOTAL_API_KEY_NOT_FOUND;
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
        response = MSG_OBJECT_NOT_VALID;
        return false;
    }

     CURL* curl = curl_easy_init();
    if (!curl) {
        response = MSG_CURL_COULD_NOT_BE_INITIATED;
        return false;
    }

     bool hashComputedSuccessfuly;
     std::string fileHash = ComputeHash(object, hashComputedSuccessfuly);
     //if hash did not compute successfully, the fileHash is the error message to be returned
     if (!hashComputedSuccessfuly) {
         response = fileHash;
         return false;
     }

     std::string apiKey;
     if (!GetEnv("VIRUSTOTAL_API_KEY", apiKey)) {
         response = MSG_VIRUSTOTAL_API_KEY_NOT_FOUND;
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

static std::string MD5HashToHexString(unsigned char* digest)
{
     static const char hexDigits[17] = "0123456789ABCDEF";
     char digest_str[2 * MD5_DIGEST_LENGTH + 1];
     // Convert the hash into a hex string form
     for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
         digest_str[i * 2]     = hexDigits[(digest[i] >> 4) & 0xF];
         digest_str[i * 2 + 1] = hexDigits[digest[i] & 0xF];
     }
     digest_str[MD5_DIGEST_LENGTH * 2] = '\0';

     return digest_str;
}

//if hashComputedSuccessfully is false, the returned string will be the error message
static std::string ComputeHash(Reference<GView::Object> object, bool& hashComputedSuccessfuly, Hashes hashType)
{
    hashComputedSuccessfuly  = false;
    std::string filePathStr = FilePathFromGViewObject(object);
    std::ifstream file(filePathStr, std::ios::in | std::ios::binary | std::ios::ate);

    if (!file.is_open()) {
         return "Error: Cannot open file: " + filePathStr;
    }

    // Get file size
    long fileSize = file.tellg();

    // Allocate memory to hold the entire file
    char* memBlock = new char[fileSize];

    // Read the file into memory
    file.seekg(0, std::ios::beg);
    file.read(memBlock, fileSize);
    file.close();

    std::string fileHash;
    switch (hashType) {
    case Hashes::MD5:
    default:
         // Compute the MD5 hash of the file content
         unsigned char result[MD5_DIGEST_LENGTH];
         MD5((unsigned char*) memBlock, fileSize, result);
         fileHash                = MD5HashToHexString(result);
         hashComputedSuccessfuly = true;
    }
    // Clean up
    delete[] memBlock;

    return fileHash;
}
} // namespace GView::GenericPlugins::FileAnalysis

extern "C"
{
PLUGIN_EXPORT bool Run(const string_view command, Reference<GView::Object> object)
{
    if (command == GView::GenericPlugins::FileAnalysis::CMD_UPLOAD_CURRENT) {
        std::string response;
        if (!GView::GenericPlugins::FileAnalysis::UploadFile(object, response)) {
            Dialogs::MessageBox::ShowError("Error!", response);
            RETURNERROR(false, response.c_str());
        }

        auto json = nlohmann::json::parse(response, nullptr, false);
        if (!json.is_discarded()) {
            AppCUI::OS::Clipboard::SetText(json.dump());
            Dialogs::MessageBox::ShowNotification("Upload Success", "File uploaded successfully to VirusTotal. Response copied.");
        } else {
            Dialogs::MessageBox::ShowNotification("Upload Success", "File uploaded successfully to VirusTotal.");
        }

        return true;
    } else if (command == GView::GenericPlugins::FileAnalysis::CMD_CHECK_BY_HASH) {
        std::string response;
        if (!GView::GenericPlugins::FileAnalysis::GetFileReport(object, response)) {
            Dialogs::MessageBox::ShowError("Error!", response);
            RETURNERROR(false, response.c_str());
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
