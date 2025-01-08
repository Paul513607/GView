#include "FileAnalysis.hpp"

namespace GView::GenericPlugins::FileAnalysis
{

} // namespace GView::GenericPlugins::FileAnalysis

extern "C"
{
    PLUGIN_EXPORT bool Run(const string_view command, Reference<GView::Object> object)
    {
        CURL curl = nullptr;
        printf("stuff");
        return false;
    }

    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        sect["Command.FileAnalysis"] = Input::Key::F11;
    }
}
