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

    class TextWindow : public Window, public Handlers::OnButtonPressedInterface
    {

    public:
        TextWindow(std::string textAreaCaption, std::string textAreaContent)
            : Window(textAreaCaption, "d:c,w:70,h:25", WindowFlags::Sizeable | WindowFlags::Maximized)
        {
            Factory::TextArea::Create(this, textAreaContent, "l:1,t:1,r:1,b:3", TextAreaFlags::Readonly | TextAreaFlags::ScrollBars | TextAreaFlags::ShowLineNumbers);
            Factory::Button::Create(this, "&Close", "d:b,w:20", 1)->Handlers()->OnButtonPressed = this;
        }

        void OnButtonPressed(Reference<Button>) override
        {
            this->Exit();
        }
    };
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
        return false;
    }

     CURL* curl = curl_easy_init();
     if (!curl) {
         return false;
     }

     std::string filePathStr = FilePathFromGViewObject(object);

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

     bool hashComputedSuccessfuly;
     std::string fileHash = ComputeHash(object, hashComputedSuccessfuly);
     //if hash did not compute successfully, the fileHash is the error message to be returned
     if (!hashComputedSuccessfuly) {
         response = fileHash;
         return false;
     }

     std::string apiKey;
     if (!getenv("VIRUSTOTAL_API_KEY", apiKey)) {
         response = "No VIRUSTOTAL_API_KEY - add one to your computers environment variables";
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

std::string MD5HashToHexString(unsigned char* digest)
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
static std::string ExtractFileAnalysisReport(nlohmann::json fileAnalysisResults)
{
    std::stringstream report;
    nlohmann::json attributes = fileAnalysisResults["data"]["attributes"];
    report << "File name: " << attributes["meaningful_name"] << '\n';
    report << "Size in bytes: " << attributes["size"] << '\n';
    report << "File type: " << attributes["type_description"] << '\n';
    report << "MD5: " << attributes["md5"] << '\n';
    report << "SHA1: " << attributes["sha1"] << '\n';
    report << "SHA256: " << attributes["sha256"] << '\n';
    report << "Last submission date: " << attributes["last_submission_date"] << '\n';
    report << "Last analysis date: " << attributes["last_analysis_date"] << '\n';
    report << "Times submitted: " << attributes["times_submitted"] << '\n';
    report << "Unique sources: " << attributes["unique_sources"] << '\n';
    report << "Self link: " << fileAnalysisResults["data"]["links"]["self"] << '\n' << '\n';

    nlohmann::json lastAnalisysStats = attributes["last_analysis_stats"];
    report << "Last analysis stats:" << '\n';
    report << '\t' << "Confirmed timeout: " << lastAnalisysStats["confirmed-timeout"] << '\n';
    report << '\t' << "Failure: " << lastAnalisysStats["failure"] << '\n';
    report << '\t' << "Harmless: " << lastAnalisysStats["harmless"] << '\n';
    report << '\t' << "Malicious: " << lastAnalisysStats["malicious"] << '\n';
    report << '\t' << "Suspicious: " << lastAnalisysStats["suspicious"] << '\n';
    report << '\t' << "Timeout: " << lastAnalisysStats["timeout"] << '\n';
    report << '\t' << "Type unsupported: " << lastAnalisysStats["type-unsupported"] << '\n';
    report << '\t' << "Undetected: " << lastAnalisysStats["undetected"];

    return report.str();
}

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
            Dialogs::MessageBox::ShowError("Error!", "Failed to fetch file report from VirusTotal.\n" + response);
            return false;
        }

        auto json = nlohmann::json::parse(response, nullptr, false);
        if (!json.is_discarded()) {
            std::string fileReport = ExtractFileAnalysisReport(json);
            AppCUI::OS::Clipboard::SetText(fileReport);
            Dialogs::MessageBox::ShowNotification("Report Retrieved", "File report copied to clipboard.");
            //Window resultWindow("Results", "d:c,w:70,h20", WindowFlags::Sizeable | WindowFlags::Maximized);
            GView::GenericPlugins::FileAnalysis::TextWindow window("Analysis results", fileReport);
            window.Show();
            //Dialogs::MessageBox::ShowNotification("Results:", fileReport);
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
