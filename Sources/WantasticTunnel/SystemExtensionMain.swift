#if WANTASTIC_SYSTEM_EXTENSION_ENTRY
import Dispatch
import NetworkExtension

@main
enum WantasticSystemExtensionMain {
    static func main() {
        NEProvider.startSystemExtensionMode()
        dispatchMain()
    }
}
#endif
