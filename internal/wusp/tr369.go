// tr369.go — TR-181 Issue 2 Amendment 20 Device.LocalAgent.* sub-table params.
//
// Device.LocalAgent.* is the TR-369 (USP) agent configuration object tree
// defined in tr-181-2-localagent.xml. Top-level LocalAgent params are already
// defined in device.go (DeviceLocalAgentParams). This file covers all
// sub-tables and their parameters.
//
// Source: BroadbandForum/device-data-model tr-181-2-localagent.xml
// https://usp-data-models.broadband-forum.org/tr-181-2-20-1-usp-full.xml
package wusp

// ---------------------------------------------------------------------------
// Additional objects (not already in DeviceObjects in device.go)
// ---------------------------------------------------------------------------

var LocalAgentExtraObjects = []Object{
	// MTP sub-objects
	{Path: "Device.LocalAgent.MTP.{i}.STOMP.", MultiInstance: false, SinceVersion: "2.12",
		Description: "STOMP MTP configuration for a LocalAgent MTP instance."},
	{Path: "Device.LocalAgent.MTP.{i}.WebSocket.", MultiInstance: false, SinceVersion: "2.12",
		Description: "WebSocket MTP configuration for a LocalAgent MTP instance."},
	{Path: "Device.LocalAgent.MTP.{i}.MQTT.", MultiInstance: false, SinceVersion: "2.13",
		Description: "MQTT MTP configuration for a LocalAgent MTP instance."},
	{Path: "Device.LocalAgent.MTP.{i}.UDS.", MultiInstance: false, SinceVersion: "2.16",
		Description: "Unix Domain Socket MTP configuration for a LocalAgent MTP instance."},
	// Controller sub-objects
	{Path: "Device.LocalAgent.Controller.{i}.MTP.{i}.", MultiInstance: true, SinceVersion: "2.12",
		Description: "Per-controller MTP configuration — how this agent reaches the controller."},
	{Path: "Device.LocalAgent.Controller.{i}.MTP.{i}.STOMP.", MultiInstance: false, SinceVersion: "2.12",
		Description: "STOMP outbound MTP for a Controller."},
	{Path: "Device.LocalAgent.Controller.{i}.MTP.{i}.WebSocket.", MultiInstance: false, SinceVersion: "2.12",
		Description: "WebSocket outbound MTP for a Controller."},
	{Path: "Device.LocalAgent.Controller.{i}.MTP.{i}.MQTT.", MultiInstance: false, SinceVersion: "2.13",
		Description: "MQTT outbound MTP for a Controller."},
	{Path: "Device.LocalAgent.Controller.{i}.MTP.{i}.UDS.", MultiInstance: false, SinceVersion: "2.16",
		Description: "Unix Domain Socket outbound MTP for a Controller."},
	{Path: "Device.LocalAgent.Controller.{i}.BootParameter.{i}.", MultiInstance: true, SinceVersion: "2.12",
		Description: "Parameter to include in the USP Boot notification sent to this Controller."},
	// ControllerTrust sub-objects
	{Path: "Device.LocalAgent.ControllerTrust.Role.{i}.", MultiInstance: true, SinceVersion: "2.12",
		Description: "Named role granting a set of permissions to controllers."},
	{Path: "Device.LocalAgent.ControllerTrust.Role.{i}.Permission.{i}.", MultiInstance: true, SinceVersion: "2.12",
		Description: "Ordered permission entry within a ControllerTrust Role."},
	{Path: "Device.LocalAgent.ControllerTrust.Credential.{i}.", MultiInstance: true, SinceVersion: "2.12",
		Description: "Certificate-to-role mapping for trusted controller credentials."},
	{Path: "Device.LocalAgent.ControllerTrust.Challenge.{i}.", MultiInstance: true, SinceVersion: "2.12",
		Description: "Challenge definition for Trust-On-First-Use (TOFU) passphrase authentication."},
}

// ---------------------------------------------------------------------------
// Device.LocalAgent.MTP.{i}. parameters
// ---------------------------------------------------------------------------

var LocalAgentMTPParams = []Param{
	{
		Path: "Device.LocalAgent.MTP.{i}.Alias", Type: TypeAlias, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "USP non-functional unique key (writeOnce after creation).",
		Limits:       Limits{MinLength: 1, MaxLength: 64},
	},
	{
		Path: "Device.LocalAgent.MTP.{i}.Enable", Type: TypeBoolean, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Enables or disables this MTP instance.",
	},
	{
		Path: "Device.LocalAgent.MTP.{i}.Status", Type: TypeString, Access: ReadOnly,
		SinceVersion: "2.12",
		Description:  "Operational status of this MTP.",
		Limits:       Limits{Enums: []string{"Up", "Down", "Error"}},
	},
	{
		Path: "Device.LocalAgent.MTP.{i}.Protocol", Type: TypeString, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Protocol used by this MTP (must be in Device.LocalAgent.SupportedProtocols).",
		Limits:       Limits{Enums: []string{"WebSocket", "STOMP", "MQTT", "UDS"}},
	},
	{
		Path: "Device.LocalAgent.MTP.{i}.EnableMDNS", Type: TypeBoolean, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Advertise this MTP endpoint via mDNS. Default: true.",
	},
}

// ---------------------------------------------------------------------------
// Device.LocalAgent.MTP.{i}.STOMP. parameters
// ---------------------------------------------------------------------------

var LocalAgentMTPSTOMPParams = []Param{
	{
		Path: "Device.LocalAgent.MTP.{i}.STOMP.Reference", Type: TypePathRef, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Strong pathRef to the Device.STOMP.Connection.{i}. to use.",
	},
	{
		Path: "Device.LocalAgent.MTP.{i}.STOMP.Destination", Type: TypeString, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "STOMP destination the agent subscribes to for incoming USP messages.",
	},
	{
		Path: "Device.LocalAgent.MTP.{i}.STOMP.DestinationFromServer", Type: TypeString, Access: ReadOnly,
		SinceVersion: "2.12",
		Description:  "Destination received from the broker's CONNECTED frame subscribe-dest header.",
	},
}

// ---------------------------------------------------------------------------
// Device.LocalAgent.MTP.{i}.WebSocket. parameters
// ---------------------------------------------------------------------------

var LocalAgentMTPWebSocketParams = []Param{
	{
		Path: "Device.LocalAgent.MTP.{i}.WebSocket.Interfaces", Type: TypeList, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Strong pathRefs to Device.IP.Interface.{i}. rows this WebSocket MTP binds to.",
	},
	{
		Path: "Device.LocalAgent.MTP.{i}.WebSocket.Port", Type: TypeUnsignedInt, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "TCP port the WebSocket MTP listens on. Default: 8443.",
		Limits:       Limits{Min: iptr(1), Max: iptr(65535)},
	},
	{
		Path: "Device.LocalAgent.MTP.{i}.WebSocket.Path", Type: TypeString, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "URI path component (RFC 3986 §3.3) for this WebSocket endpoint.",
	},
	{
		Path: "Device.LocalAgent.MTP.{i}.WebSocket.EnableEncryption", Type: TypeBoolean, Access: ReadWrite,
		SinceVersion: "2.14",
		Description:  "Enable TLS on the WebSocket connection. Default: true.",
	},
	{
		Path: "Device.LocalAgent.MTP.{i}.WebSocket.KeepAliveInterval", Type: TypeUnsignedInt, Access: ReadWrite,
		SinceVersion: "2.15",
		Description:  "WebSocket ping keepalive interval in seconds. Default: 60.",
		Limits:       Limits{Min: iptr(1)},
	},
}

// ---------------------------------------------------------------------------
// Device.LocalAgent.MTP.{i}.MQTT. parameters
// ---------------------------------------------------------------------------

var LocalAgentMTPMQTTParams = []Param{
	{
		Path: "Device.LocalAgent.MTP.{i}.MQTT.Reference", Type: TypePathRef, Access: ReadWrite,
		SinceVersion: "2.13",
		Description:  "Strong pathRef to the Device.MQTT.Client.{i}. connection to use.",
	},
	{
		Path: "Device.LocalAgent.MTP.{i}.MQTT.ResponseTopicConfigured", Type: TypeString, Access: ReadWrite,
		SinceVersion: "2.13",
		Description:  "MQTT topic the agent publishes responses to (configured).",
		Limits:       Limits{MaxLength: 65535},
	},
	{
		Path: "Device.LocalAgent.MTP.{i}.MQTT.ResponseTopicDiscovered", Type: TypeString, Access: ReadOnly,
		SinceVersion: "2.13",
		Description:  "MQTT response topic discovered via broker subscription (auto-discovered).",
		Limits:       Limits{MaxLength: 65535},
	},
	{
		Path: "Device.LocalAgent.MTP.{i}.MQTT.PublishQoS", Type: TypeUnsignedInt, Access: ReadWrite,
		SinceVersion: "2.13",
		Description:  "MQTT QoS level for published USP messages (0=AtMostOnce, 1=AtLeastOnce, 2=ExactlyOnce).",
		Limits:       Limits{Min: iptr(0), Max: iptr(2)},
	},
}

// ---------------------------------------------------------------------------
// Device.LocalAgent.MTP.{i}.UDS. parameters
// ---------------------------------------------------------------------------

var LocalAgentMTPUDSParams = []Param{
	{
		Path: "Device.LocalAgent.MTP.{i}.UDS.UnixDomainSocketRef", Type: TypePathRef, Access: ReadWrite,
		SinceVersion: "2.16",
		Description:  "Strong pathRef to the Device.UnixDomainSockets.UnixDomainSocket.{i}. to use.",
	},
}

// ---------------------------------------------------------------------------
// Device.LocalAgent.Controller.{i}. parameters
// ---------------------------------------------------------------------------

var LocalAgentControllerParams = []Param{
	{
		Path: "Device.LocalAgent.Controller.{i}.Alias", Type: TypeAlias, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "USP non-functional unique key (writeOnce after creation).",
		Limits:       Limits{MinLength: 1, MaxLength: 64},
	},
	{
		Path: "Device.LocalAgent.Controller.{i}.Enable", Type: TypeBoolean, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Enables or disables communications with this controller.",
	},
	{
		Path: "Device.LocalAgent.Controller.{i}.EndpointID", Type: TypeString, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Functional unique key. USP EndpointID of the controller.",
	},
	{
		Path: "Device.LocalAgent.Controller.{i}.ControllerCode", Type: TypeString, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Opaque string identifying the controller software/vendor.",
		Limits:       Limits{MaxLength: 128},
	},
	{
		Path: "Device.LocalAgent.Controller.{i}.ProvisioningCode", Type: TypeString, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Opaque provisioning code set by the controller.",
		Limits:       Limits{MaxLength: 64},
	},
	{
		Path: "Device.LocalAgent.Controller.{i}.AssignedRole", Type: TypeList, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Strong pathRefs to ControllerTrust.Role.{i}. rows directly assigned to this controller.",
	},
	{
		Path: "Device.LocalAgent.Controller.{i}.InheritedRole", Type: TypeList, Access: ReadOnly,
		SinceVersion: "2.12",
		Description:  "Strong pathRefs to roles inherited via ControllerTrust.Credential entries (read-only).",
	},
	{
		Path: "Device.LocalAgent.Controller.{i}.Credential", Type: TypeList, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Strong pathRefs to LocalAgent.Certificate.{i}. rows presenting this controller's identity.",
	},
	{
		Path: "Device.LocalAgent.Controller.{i}.PeriodicNotifInterval", Type: TypeUnsignedInt, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Interval in seconds for periodic ValueChange notifications to this controller.",
		Limits:       Limits{Min: iptr(1)},
	},
	{
		Path: "Device.LocalAgent.Controller.{i}.PeriodicNotifTime", Type: TypeDateTime, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "UTC reference time for computing the periodic-notification schedule.",
	},
	{
		Path: "Device.LocalAgent.Controller.{i}.USPNotifRetryMinimumWaitInterval", Type: TypeUnsignedInt, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Base retry wait-interval in seconds for failed USP notifications. Default: 5.",
		Limits:       Limits{Min: iptr(1), Max: iptr(65535)},
	},
	{
		Path: "Device.LocalAgent.Controller.{i}.USPNotifRetryIntervalMultiplier", Type: TypeUnsignedInt, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Retry back-off multiplier in units of 0.001 (range 1000–65535; 2000 = ×2). Default: 2000.",
		Limits:       Limits{Min: iptr(1000), Max: iptr(65535)},
	},
	{
		Path: "Device.LocalAgent.Controller.{i}.OnBoardingComplete", Type: TypeBoolean, Access: ReadWrite,
		SinceVersion: "2.17",
		Description:  "True once the agent has completed on-boarding with this controller. Default: false.",
	},
	{
		Path: "Device.LocalAgent.Controller.{i}.OnBoardingRestartTime", Type: TypeUnsignedInt, Access: ReadWrite,
		SinceVersion: "2.17",
		Description:  "Seconds after which the agent retries on-boarding if not complete. 0 = disabled.",
	},
	{
		Path: "Device.LocalAgent.Controller.{i}.BootParameterNumberOfEntries", Type: TypeUnsignedInt, Access: ReadOnly,
		SinceVersion: "2.12",
		Description:  "Number of entries in Controller.{i}.BootParameter.{i}.",
	},
	{
		Path: "Device.LocalAgent.Controller.{i}.MTPNumberOfEntries", Type: TypeUnsignedInt, Access: ReadOnly,
		SinceVersion: "2.12",
		Description:  "Number of entries in Controller.{i}.MTP.{i}.",
	},
}

// ---------------------------------------------------------------------------
// Device.LocalAgent.Controller.{i}.BootParameter.{i}. parameters
// ---------------------------------------------------------------------------

var LocalAgentControllerBootParamParams = []Param{
	{
		Path: "Device.LocalAgent.Controller.{i}.BootParameter.{i}.Alias", Type: TypeAlias, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Non-functional unique key for this BootParameter instance.",
		Limits:       Limits{MinLength: 1, MaxLength: 64},
	},
	{
		Path: "Device.LocalAgent.Controller.{i}.BootParameter.{i}.Enable", Type: TypeBoolean, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Enable inclusion of this parameter in the Boot notification.",
	},
	{
		Path: "Device.LocalAgent.Controller.{i}.BootParameter.{i}.ParameterName", Type: TypeString, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Parameter path (or wildcard pattern) to include in the USP Boot notification.",
	},
}

// ---------------------------------------------------------------------------
// Device.LocalAgent.Controller.{i}.MTP.{i}. parameters
// ---------------------------------------------------------------------------

var LocalAgentControllerMTPParams = []Param{
	{
		Path: "Device.LocalAgent.Controller.{i}.MTP.{i}.Alias", Type: TypeAlias, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Non-functional unique key for this Controller MTP instance.",
		Limits:       Limits{MinLength: 1, MaxLength: 64},
	},
	{
		Path: "Device.LocalAgent.Controller.{i}.MTP.{i}.Enable", Type: TypeBoolean, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Enables or disables this outbound MTP for the controller.",
	},
	{
		Path: "Device.LocalAgent.Controller.{i}.MTP.{i}.Protocol", Type: TypeString, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Functional unique key. MTP protocol used to reach this controller.",
		Limits:       Limits{Enums: []string{"WebSocket", "STOMP", "MQTT", "UDS"}},
	},
	{
		Path: "Device.LocalAgent.Controller.{i}.MTP.{i}.Order", Type: TypeUnsignedInt, Access: ReadWrite,
		SinceVersion: "2.15",
		Description:  "Priority order — lower value = higher priority when multiple MTPs are enabled.",
		Limits:       Limits{Min: iptr(1)},
	},
}

// ---------------------------------------------------------------------------
// Device.LocalAgent.Controller.{i}.MTP.{i}.STOMP. parameters
// ---------------------------------------------------------------------------

var LocalAgentControllerMTPSTOMPParams = []Param{
	{
		Path: "Device.LocalAgent.Controller.{i}.MTP.{i}.STOMP.Reference", Type: TypePathRef, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Strong pathRef to the Device.STOMP.Connection.{i}. for this outbound MTP.",
	},
	{
		Path: "Device.LocalAgent.Controller.{i}.MTP.{i}.STOMP.Destination", Type: TypeString, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "STOMP destination to which USP messages for this controller are published.",
	},
}

// ---------------------------------------------------------------------------
// Device.LocalAgent.Controller.{i}.MTP.{i}.WebSocket. parameters
// ---------------------------------------------------------------------------

var LocalAgentControllerMTPWSParams = []Param{
	{
		Path: "Device.LocalAgent.Controller.{i}.MTP.{i}.WebSocket.Host", Type: TypeString, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Controller WebSocket server hostname or IP address.",
		Limits:       Limits{MaxLength: 256},
	},
	{
		Path: "Device.LocalAgent.Controller.{i}.MTP.{i}.WebSocket.Port", Type: TypeUnsignedInt, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Controller WebSocket server TCP port.",
		Limits:       Limits{Min: iptr(1), Max: iptr(65535)},
	},
	{
		Path: "Device.LocalAgent.Controller.{i}.MTP.{i}.WebSocket.Path", Type: TypeString, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "URI path on the controller's WebSocket server.",
	},
	{
		Path: "Device.LocalAgent.Controller.{i}.MTP.{i}.WebSocket.EnableEncryption", Type: TypeBoolean, Access: ReadWrite,
		SinceVersion: "2.14",
		Description:  "Use TLS on the outbound WebSocket connection. Default: true.",
	},
	{
		Path: "Device.LocalAgent.Controller.{i}.MTP.{i}.WebSocket.KeepAliveInterval", Type: TypeUnsignedInt, Access: ReadWrite,
		SinceVersion: "2.15",
		Description:  "WebSocket ping keepalive interval in seconds.",
		Limits:       Limits{Min: iptr(1)},
	},
	{
		Path: "Device.LocalAgent.Controller.{i}.MTP.{i}.WebSocket.CurrentRetryCount", Type: TypeUnsignedInt, Access: ReadOnly,
		SinceVersion: "2.12",
		Description:  "Number of consecutive connection attempts without a successful session.",
	},
	{
		Path: "Device.LocalAgent.Controller.{i}.MTP.{i}.WebSocket.SessionRetryMinimumWaitInterval", Type: TypeUnsignedInt, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Base retry wait in seconds after a failed WebSocket session. Default: 5.",
		Limits:       Limits{Min: iptr(1), Max: iptr(65535)},
	},
	{
		Path: "Device.LocalAgent.Controller.{i}.MTP.{i}.WebSocket.SessionRetryIntervalMultiplier", Type: TypeUnsignedInt, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Retry back-off multiplier in units of 0.001. Default: 2000.",
		Limits:       Limits{Min: iptr(1000), Max: iptr(65535)},
	},
}

// ---------------------------------------------------------------------------
// Device.LocalAgent.Controller.{i}.MTP.{i}.MQTT. parameters
// ---------------------------------------------------------------------------

var LocalAgentControllerMTPMQTTParams = []Param{
	{
		Path: "Device.LocalAgent.Controller.{i}.MTP.{i}.MQTT.Topic", Type: TypeString, Access: ReadWrite,
		SinceVersion: "2.13",
		Description:  "MQTT topic to which USP messages for this controller are published.",
		Limits:       Limits{MaxLength: 65535},
	},
	{
		Path: "Device.LocalAgent.Controller.{i}.MTP.{i}.MQTT.PublishRetainResponse", Type: TypeBoolean, Access: ReadWrite,
		SinceVersion: "2.13",
		Description:  "Set MQTT retain flag on USP response messages. Default: false.",
	},
	{
		Path: "Device.LocalAgent.Controller.{i}.MTP.{i}.MQTT.PublishRetainNotify", Type: TypeBoolean, Access: ReadWrite,
		SinceVersion: "2.13",
		Description:  "Set MQTT retain flag on USP notification messages. Default: false.",
	},
}

// ---------------------------------------------------------------------------
// Device.LocalAgent.Subscription.{i}. parameters
// ---------------------------------------------------------------------------

var LocalAgentSubscriptionParams = []Param{
	{
		Path: "Device.LocalAgent.Subscription.{i}.Alias", Type: TypeAlias, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "USP non-functional unique key (writeOnce after creation).",
		Limits:       Limits{MinLength: 1, MaxLength: 64},
	},
	{
		Path: "Device.LocalAgent.Subscription.{i}.Enable", Type: TypeBoolean, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Enables or disables this subscription.",
	},
	{
		Path: "Device.LocalAgent.Subscription.{i}.Recipient", Type: TypePathRef, Access: ReadOnly,
		SinceVersion: "2.12",
		Description:  "Strong pathRef to the Controller.{i}. that created this subscription (auto-populated).",
	},
	{
		Path: "Device.LocalAgent.Subscription.{i}.ID", Type: TypeString, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Subscription ID included in Notify messages sent to the recipient (1–64 chars).",
		Limits:       Limits{MinLength: 1, MaxLength: 64},
	},
	{
		Path: "Device.LocalAgent.Subscription.{i}.NotifType", Type: TypeString, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Type of event this subscription monitors.",
		Limits: Limits{
			Enums: []string{
				"ValueChange", "ObjectCreation", "ObjectDeletion",
				"OperationComplete", "Event",
			},
		},
	},
	{
		Path: "Device.LocalAgent.Subscription.{i}.ReferenceList", Type: TypeList, Access: ReadWrite,
		SinceVersion: "2.13",
		Description:  "List of parameter/object/event paths this subscription monitors. Immutable once set.",
		Limits:       Limits{MaxLength: 256},
	},
	{
		Path: "Device.LocalAgent.Subscription.{i}.Persistent", Type: TypeBoolean, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "If true, subscription survives agent restart. Default: false.",
	},
	{
		Path: "Device.LocalAgent.Subscription.{i}.TimeToLive", Type: TypeUnsignedInt, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Subscription lifetime in seconds. 0 = ignored (use Delete or Persistent=true).",
	},
	{
		Path: "Device.LocalAgent.Subscription.{i}.NotifRetry", Type: TypeBoolean, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Retry delivery of failed notifications. Default: false.",
	},
	{
		Path: "Device.LocalAgent.Subscription.{i}.NotifExpiration", Type: TypeUnsignedInt, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Maximum retry window in seconds (ignored if NotifRetry=false). 0 = no expiry.",
	},
	{
		Path: "Device.LocalAgent.Subscription.{i}.CreationDate", Type: TypeDateTime, Access: ReadOnly,
		SinceVersion: "2.12",
		Description:  "UTC timestamp when this subscription was created (auto-populated).",
	},
	{
		Path: "Device.LocalAgent.Subscription.{i}.TriggerAction", Type: TypeString, Access: ReadWrite,
		SinceVersion: "2.16",
		Description:  "Action taken when subscription condition fires.",
		Limits:       Limits{Enums: []string{"Notify", "Config", "NotifyAndConfig"}},
	},
	{
		Path: "Device.LocalAgent.Subscription.{i}.TriggerConfigSettings", Type: TypeList, Access: ReadWrite,
		SinceVersion: "2.16",
		Description:  "Config changes applied on trigger (max 16 entries; format \"ParamName=Value\").",
		Limits:       Limits{MaxItems: 16},
	},
}

// ---------------------------------------------------------------------------
// Device.LocalAgent.Request.{i}. parameters
// ---------------------------------------------------------------------------

var LocalAgentRequestParams = []Param{
	{
		Path: "Device.LocalAgent.Request.{i}.Alias", Type: TypeAlias, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Non-functional unique key for this Request instance.",
		Limits:       Limits{MinLength: 1, MaxLength: 64},
	},
	{
		Path: "Device.LocalAgent.Request.{i}.Originator", Type: TypeString, Access: ReadOnly,
		SinceVersion: "2.12",
		Description:  "USP EndpointID of the controller that issued the async command.",
	},
	{
		Path: "Device.LocalAgent.Request.{i}.Command", Type: TypeString, Access: ReadOnly,
		SinceVersion: "2.12",
		Description:  "Full path to the command being executed (e.g. \"Device.Foo.Bar()\").",
	},
	{
		Path: "Device.LocalAgent.Request.{i}.CommandKey", Type: TypeString, Access: ReadOnly,
		SinceVersion: "2.12",
		Description:  "command_key value from the USP Operate message that triggered this request.",
	},
	{
		Path: "Device.LocalAgent.Request.{i}.Status", Type: TypeString, Access: ReadOnly,
		SinceVersion: "2.12",
		Description:  "Current execution state of the async command.",
		Limits: Limits{
			Enums: []string{"Requested", "Active", "Canceling", "Canceled", "Success", "Error"},
		},
	},
}

// ---------------------------------------------------------------------------
// Device.LocalAgent.Certificate.{i}. parameters
// ---------------------------------------------------------------------------

var LocalAgentCertificateParams = []Param{
	{
		Path: "Device.LocalAgent.Certificate.{i}.Alias", Type: TypeAlias, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Non-functional unique key for this Certificate instance.",
		Limits:       Limits{MinLength: 1, MaxLength: 64},
	},
	{
		Path: "Device.LocalAgent.Certificate.{i}.Enable", Type: TypeBoolean, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Enable use of this certificate for controller authentication.",
	},
	{
		Path: "Device.LocalAgent.Certificate.{i}.SerialNumber", Type: TypeString, Access: ReadOnly,
		SinceVersion: "2.12",
		Description:  "X.509 SerialNumber field (RFC 5280) of this certificate. Functional unique key (with Issuer).",
		Limits:       Limits{MaxLength: 64},
	},
	{
		Path: "Device.LocalAgent.Certificate.{i}.Issuer", Type: TypeString, Access: ReadOnly,
		SinceVersion: "2.12",
		Description:  "Distinguished Name of the certificate's signing CA (RFC 5280). Functional unique key (with SerialNumber).",
		Limits:       Limits{MaxLength: 256},
	},
}

// ---------------------------------------------------------------------------
// Device.LocalAgent.ControllerTrust. parameters
// ---------------------------------------------------------------------------

var LocalAgentControllerTrustParams = []Param{
	{
		Path: "Device.LocalAgent.ControllerTrust.UntrustedRole", Type: TypeList, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Strong pathRef to the Role assigned to controllers presenting no known credential (max 1 entry).",
		Limits:       Limits{MaxItems: 1},
	},
	{
		Path: "Device.LocalAgent.ControllerTrust.BannedRole", Type: TypePathRef, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Strong pathRef to the Role with no permissions assigned to banned controllers.",
	},
	{
		Path: "Device.LocalAgent.ControllerTrust.SecuredRoles", Type: TypeList, Access: ReadWrite,
		SinceVersion: "2.16",
		Description:  "Strong pathRefs to Roles that require a secured connection (TLS/mTLS) to apply.",
	},
	{
		Path: "Device.LocalAgent.ControllerTrust.TOFUAllowed", Type: TypeBoolean, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Allow Trust-On-First-Use: accept the first controller presenting credentials and assign the TOFU role.",
	},
	{
		Path: "Device.LocalAgent.ControllerTrust.TOFUInactivityTimer", Type: TypeUnsignedInt, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Seconds of inactivity before TOFU is disabled. 0 = disabled (TOFU stays active indefinitely).",
	},
	{
		Path: "Device.LocalAgent.ControllerTrust.RoleNumberOfEntries", Type: TypeUnsignedInt, Access: ReadOnly,
		SinceVersion: "2.12",
		Description:  "Number of entries in ControllerTrust.Role.{i}.",
	},
	{
		Path: "Device.LocalAgent.ControllerTrust.CredentialNumberOfEntries", Type: TypeUnsignedInt, Access: ReadOnly,
		SinceVersion: "2.12",
		Description:  "Number of entries in ControllerTrust.Credential.{i}.",
	},
	{
		Path: "Device.LocalAgent.ControllerTrust.ChallengeNumberOfEntries", Type: TypeUnsignedInt, Access: ReadOnly,
		SinceVersion: "2.12",
		Description:  "Number of entries in ControllerTrust.Challenge.{i}.",
	},
}

// ---------------------------------------------------------------------------
// Device.LocalAgent.ControllerTrust.Role.{i}. parameters
// ---------------------------------------------------------------------------

var LocalAgentRoleParams = []Param{
	{
		Path: "Device.LocalAgent.ControllerTrust.Role.{i}.Alias", Type: TypeAlias, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "USP non-functional unique key (writeOnce after creation).",
		Limits:       Limits{MinLength: 1, MaxLength: 64},
	},
	{
		Path: "Device.LocalAgent.ControllerTrust.Role.{i}.Enable", Type: TypeBoolean, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Enable this role.",
	},
	{
		Path: "Device.LocalAgent.ControllerTrust.Role.{i}.Name", Type: TypeString, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Functional unique key. Human-readable name for this role.",
	},
	{
		Path: "Device.LocalAgent.ControllerTrust.Role.{i}.PermissionNumberOfEntries", Type: TypeUnsignedInt, Access: ReadOnly,
		SinceVersion: "2.12",
		Description:  "Number of entries in Role.{i}.Permission.{i}.",
	},
}

// ---------------------------------------------------------------------------
// Device.LocalAgent.ControllerTrust.Role.{i}.Permission.{i}. parameters
// ---------------------------------------------------------------------------

var LocalAgentPermissionParams = []Param{
	{
		Path: "Device.LocalAgent.ControllerTrust.Role.{i}.Permission.{i}.Alias", Type: TypeAlias, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "USP non-functional unique key (writeOnce after creation).",
		Limits:       Limits{MinLength: 1, MaxLength: 64},
	},
	{
		Path: "Device.LocalAgent.ControllerTrust.Role.{i}.Permission.{i}.Enable", Type: TypeBoolean, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Enable this permission entry.",
	},
	{
		Path: "Device.LocalAgent.ControllerTrust.Role.{i}.Permission.{i}.Order", Type: TypeUnsignedInt, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Priority order among permissions for the same target. Higher value = higher priority. Default: 0.",
	},
	{
		Path: "Device.LocalAgent.ControllerTrust.Role.{i}.Permission.{i}.Targets", Type: TypeList, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "List of path names or search-path patterns this permission applies to.",
	},
	{
		Path: "Device.LocalAgent.ControllerTrust.Role.{i}.Permission.{i}.Param", Type: TypeString, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Permission bits for parameters: 4-char string [r-][w-][x-][n-] (read/write/execute/notify). Default: \"----\".",
		Limits:       Limits{MinLength: 4, MaxLength: 4, Pattern: `[r\-][w\-][x\-][n\-]`},
	},
	{
		Path: "Device.LocalAgent.ControllerTrust.Role.{i}.Permission.{i}.Obj", Type: TypeString, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Permission bits for objects: 4-char string [r-][w-][x-][n-]. Default: \"----\".",
		Limits:       Limits{MinLength: 4, MaxLength: 4, Pattern: `[r\-][w\-][x\-][n\-]`},
	},
	{
		Path: "Device.LocalAgent.ControllerTrust.Role.{i}.Permission.{i}.InstantiatedObj", Type: TypeString, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Permission bits for instantiated (existing) objects. 4-char string [r-][w-][x-][n-]. Default: \"----\".",
		Limits:       Limits{MinLength: 4, MaxLength: 4, Pattern: `[r\-][w\-][x\-][n\-]`},
	},
	{
		Path: "Device.LocalAgent.ControllerTrust.Role.{i}.Permission.{i}.CommandEvent", Type: TypeString, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Permission bits for commands and events. 4-char string [r-][w-][x-][n-]. Default: \"----\".",
		Limits:       Limits{MinLength: 4, MaxLength: 4, Pattern: `[r\-][w\-][x\-][n\-]`},
	},
}

// ---------------------------------------------------------------------------
// Device.LocalAgent.ControllerTrust.Credential.{i}. parameters
// ---------------------------------------------------------------------------

var LocalAgentCredentialParams = []Param{
	{
		Path: "Device.LocalAgent.ControllerTrust.Credential.{i}.Alias", Type: TypeAlias, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "USP non-functional unique key (writeOnce after creation).",
		Limits:       Limits{MinLength: 1, MaxLength: 64},
	},
	{
		Path: "Device.LocalAgent.ControllerTrust.Credential.{i}.Enable", Type: TypeBoolean, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Enable this credential-to-role mapping.",
	},
	{
		Path: "Device.LocalAgent.ControllerTrust.Credential.{i}.Role", Type: TypeList, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Strong pathRefs to ControllerTrust.Role.{i}. rows granted to controllers presenting this credential.",
	},
	{
		Path: "Device.LocalAgent.ControllerTrust.Credential.{i}.Credential", Type: TypePathRef, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Functional unique key. Strong pathRef to LocalAgent.Certificate.{i}. entry.",
	},
	{
		Path: "Device.LocalAgent.ControllerTrust.Credential.{i}.AllowedUses", Type: TypeString, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Contexts in which this credential may be used for authentication.",
		Limits:       Limits{Enums: []string{"MTP-only", "MTP-and-USP", "MTP-and-broker"}},
	},
}

// ---------------------------------------------------------------------------
// Device.LocalAgent.ControllerTrust.Challenge.{i}. parameters
// ---------------------------------------------------------------------------

var LocalAgentChallengeParams = []Param{
	{
		Path: "Device.LocalAgent.ControllerTrust.Challenge.{i}.Alias", Type: TypeAlias, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "USP non-functional unique key (writeOnce after creation).",
		Limits:       Limits{MinLength: 1, MaxLength: 64},
	},
	{
		Path: "Device.LocalAgent.ControllerTrust.Challenge.{i}.Enable", Type: TypeBoolean, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Enable this challenge definition.",
	},
	{
		Path: "Device.LocalAgent.ControllerTrust.Challenge.{i}.Description", Type: TypeString, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Human-readable description of this challenge.",
	},
	{
		Path: "Device.LocalAgent.ControllerTrust.Challenge.{i}.Role", Type: TypeList, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Strong pathRefs to Role.{i}. rows granted on successful challenge response.",
	},
	{
		Path: "Device.LocalAgent.ControllerTrust.Challenge.{i}.Type", Type: TypeString, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Challenge type.",
		Limits:       Limits{Enums: []string{"Passphrase"}},
	},
	{
		Path: "Device.LocalAgent.ControllerTrust.Challenge.{i}.Value", Type: TypeBase64, Access: WriteOnly,
		SinceVersion: "2.12",
		Description:  "The passphrase value (write-only / secured).",
	},
	{
		Path: "Device.LocalAgent.ControllerTrust.Challenge.{i}.ValueType", Type: TypeString, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "MIME type of the Value field.",
		Limits:       Limits{Enums: []string{"text/plain", "image/jpeg"}},
	},
	{
		Path: "Device.LocalAgent.ControllerTrust.Challenge.{i}.Instruction", Type: TypeBase64, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Instruction payload shown to the operator performing the challenge.",
	},
	{
		Path: "Device.LocalAgent.ControllerTrust.Challenge.{i}.InstructionType", Type: TypeString, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "MIME type of the Instruction field.",
		Limits:       Limits{Enums: []string{"text/plain", "image/jpeg", "text/html"}},
	},
	{
		Path: "Device.LocalAgent.ControllerTrust.Challenge.{i}.Retries", Type: TypeUnsignedInt, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Maximum consecutive failed challenge responses before lockout.",
	},
	{
		Path: "Device.LocalAgent.ControllerTrust.Challenge.{i}.LockoutPeriod", Type: TypeInt, Access: ReadWrite,
		SinceVersion: "2.12",
		Description:  "Seconds of lockout after exceeding Retries. Default: 30.",
		Limits:       Limits{Min: iptr(0)},
	},
}

// ---------------------------------------------------------------------------
// Aggregated slice
// ---------------------------------------------------------------------------

// AllLocalAgentSubParams is the union of all Device.LocalAgent.* sub-table
// parameter definitions not already in DeviceLocalAgentParams (device.go).
// Merged into AllDeviceParams at package init time.
var AllLocalAgentSubParams = concat(
	LocalAgentMTPParams,
	LocalAgentMTPSTOMPParams,
	LocalAgentMTPWebSocketParams,
	LocalAgentMTPMQTTParams,
	LocalAgentMTPUDSParams,
	LocalAgentControllerParams,
	LocalAgentControllerBootParamParams,
	LocalAgentControllerMTPParams,
	LocalAgentControllerMTPSTOMPParams,
	LocalAgentControllerMTPWSParams,
	LocalAgentControllerMTPMQTTParams,
	LocalAgentSubscriptionParams,
	LocalAgentRequestParams,
	LocalAgentCertificateParams,
	LocalAgentControllerTrustParams,
	LocalAgentRoleParams,
	LocalAgentPermissionParams,
	LocalAgentCredentialParams,
	LocalAgentChallengeParams,
)
