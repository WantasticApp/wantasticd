import Foundation
import WantasticLocalAccessHelperCore

// LaunchDaemon entry point. Installation and authorization are intentionally
// separate from the app build; only launchd should start this process as root.
MacLocalAccessHelperListener().runForever()
