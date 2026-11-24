package wusp

// Web-UI pages of the QoS Policy menu (see olt_spec.go).
//
// Packed arrays (qosQueue[8], cosPriority[8], dscpQueue[64]) cannot be
// written per element: the current values are read-only comma-separated
// parameters and each array is written whole by an Operate command with a
// Codec "list" input (comma-separated values posted as a JSON array).

var qosPriorityEnum = []string{"0", "1", "2", "3", "4", "5", "6", "7"}

var oltPagesQoS = []OLTPage{
	{
		Route: "/qos/queue", Title: "QoS Scheduler",
		Forms: []OLTForm{
			{
				Object: "QoS.Scheduler",
				Get:    OLTCall{Path: "/goform/getQoSScheduleInfo"},
				// The UI posts the mode together with the eight weights
				// (re-posted unchanged when only the mode changes).
				Set: &OLTWrite{Path: "/goform/setQoSScheduleInfo", Body: []string{"qosMode", "qosQueue"}},
				Fields: []OLTField{
					{Leaf: "Mode", Vendor: "qosMode", Write: true, Effect: OLTEffectDisruptive, Label: "QoS mode",
						Enum: []string{"SP", "WRR"}, EnumLabels: []string{"Strict Priority", "Weighted Priority"},
						Help: "Egress queue scheduling: SP (strict priority) or WRR (weighted round robin). Changing it briefly disturbs forwarding."},
					{Leaf: "QueueWeights", Vendor: "qosQueue", Codec: "list", Label: "Queue weights",
						Help: "WRR weights of queue0..queue7 (comma-separated, 1-10 each). Change with SetQueueWeights()."},
				},
			},
			{
				// Drop-queue switch: getter/setter exist in the UI code but no
				// control is rendered; exposed read-only.
				Object: "QoS.DropQueue",
				Get:    OLTCall{Path: "/goform/getQoSDropQueueEn"},
				Fields: []OLTField{
					{Leaf: "Enable", Vendor: "dropQueueExitEn", Codec: "bool01", Label: "Drop queue exit enable"},
				},
			},
		},
		Actions: []OLTAction{{
			Command: "QoS.Scheduler.SetQueueWeights()",
			Label:   "Set WRR queue weights", Effect: OLTEffectDisruptive,
			Help:  "setQoSScheduleInfo {qosMode, qosQueue:[w0..w7]}: Weights = 8 comma-separated values 1-10 (queue0..queue7); Mode left empty keeps the current mode.",
			Read:  &OLTCall{Path: "/goform/getQoSScheduleInfo"},
			Write: OLTWrite{Path: "/goform/setQoSScheduleInfo", Body: []string{"qosMode", "qosQueue"}},
			Inputs: []OLTField{
				{Leaf: "Weights", Vendor: "qosQueue", Codec: "list", Required: true, Label: "Queue weights (8 values, 1-10)"},
				{Leaf: "Mode", Vendor: "qosMode", Enum: []string{"SP", "WRR"}, EnumLabels: []string{"Strict Priority", "Weighted Priority"}, Label: "QoS mode"},
			},
		}},
	},
	{
		Route: "/qos/802p", Title: "802.1P",
		Forms: []OLTForm{{
			Object: "QoS.Dot1p",
			Get:    OLTCall{Path: "/goform/getCosPriorityInfo"},
			Fields: []OLTField{
				{Leaf: "PriorityQueue", Vendor: "cosPriority", Codec: "list", Label: "802.1p priority -> queue",
					Help: "Queue (0-7) of 802.1p priority 0..7, comma-separated. Change with SetPriorityQueue()."},
			},
		}},
		Actions: []OLTAction{{
			Command: "QoS.Dot1p.SetPriorityQueue()",
			Label:   "Set 802.1p priority to queue map",
			Help:    "setCosPriorityInfo {cosPriority:[q0..q7]}: Queues = 8 comma-separated queue indexes 0-7 (for priority 0..7).",
			Write:   OLTWrite{Path: "/goform/setCosPriorityInfo", Body: []string{"cosPriority"}},
			Inputs: []OLTField{
				{Leaf: "Queues", Vendor: "cosPriority", Codec: "list", Required: true, Label: "Queues (8 values, 0-7)"},
			},
		}},
	},
	{
		Route: "/qos/dscp", Title: "DSCP",
		Forms: []OLTForm{{
			Object: "QoS.DSCP",
			Get:    OLTCall{Path: "/goform/getDscpQueueInfo"},
			Fields: []OLTField{
				{Leaf: "Enable", Vendor: "dscpEn", Codec: "bool01", Write: true, Label: "DSCP mapping enable",
					Set: &OLTWrite{Path: "/goform/setDscpQueueEn", Body: []string{}}},
				{Leaf: "PriorityMap", Vendor: "dscpQueue", Codec: "list", Label: "DSCP -> priority",
					Help: "Priority (0-7) of DSCP 0..63, comma-separated. Change with SetPriorityMap()."},
			},
		}},
		Actions: []OLTAction{{
			Command: "QoS.DSCP.SetPriorityMap()",
			Label:   "Set DSCP to priority map",
			Help:    "setDscpQueueInfo {dscpQueue:[64]}: Priorities = 64 comma-separated values 0-7 for DSCP 0..63; \"-1\" leaves an entry unchanged (the UI sends -1 for untouched entries). Length is not validated by the agent.",
			Write:   OLTWrite{Path: "/goform/setDscpQueueInfo", Body: []string{"dscpQueue"}},
			Inputs: []OLTField{
				{Leaf: "Priorities", Vendor: "dscpQueue", Codec: "list", Required: true, Label: "Priorities (64 values, 0-7 or -1)"},
			},
		}},
	},
	{
		Route: "/qos/port", Title: "Port Priority",
		Tables: []OLTTable{{
			Object: "QoS.PortPriority",
			Get:    OLTCall{Path: "/goform/getPortPriorityList"},
			Key:    []string{"portNum"},
			Label:  "Port priority",
			// Row edit: action "one", port:[row.portNum].
			Edit: &OLTWrite{Path: "/goform/setPortPriorityInfo", Body: []string{"cosPriority", "trustMode"}, Extra: map[string]any{"action": "one"}, Port: "num"},
			Columns: []OLTField{
				{Leaf: "Port", Vendor: "portNum", Label: "Port"},
				{Leaf: "CoSPriority", Vendor: "cosPriority", Write: true, Enum: qosPriorityEnum, Label: "CoS priority"},
				{Leaf: "TrustMode", Vendor: "trustMode", Write: true, Enum: []string{"unTrust", "dscp"}, EnumLabels: []string{"Non-Trust", "DSCP Trust"}, Label: "Trust mode"},
			},
		}},
		Actions: []OLTAction{{
			Command: "QoS.PortPriority.SetPorts()",
			Label:   "Set priority on several ports",
			Help:    "setPortPriorityInfo {port:[...], cosPriority, trustMode, action:\"more\"} (toolbar Edit): Ports = comma-separated port values as listed in QoS.PortPriority.{i}.Port.",
			Write:   OLTWrite{Path: "/goform/setPortPriorityInfo", Body: []string{"port", "cosPriority", "trustMode"}, Extra: map[string]any{"action": "more"}},
			Inputs: []OLTField{
				{Leaf: "Ports", Vendor: "port", Codec: "list", Required: true, Label: "Ports"},
				{Leaf: "CoSPriority", Vendor: "cosPriority", Required: true, Enum: qosPriorityEnum, Label: "CoS priority"},
				{Leaf: "TrustMode", Vendor: "trustMode", Required: true, Enum: []string{"unTrust", "dscp"}, EnumLabels: []string{"Non-Trust", "DSCP Trust"}, Label: "Trust mode"},
			},
		}},
	},
}
