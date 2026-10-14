export namespace main {

	export class ClaimLink {
	    public_key: string;
	    server_url: string;
	    claim_url: string;
	    reused: boolean;

	    static createFrom(source: any = {}) {
	        return new ClaimLink(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.public_key = source["public_key"];
	        this.server_url = source["server_url"];
	        this.claim_url = source["claim_url"];
	        this.reused = source["reused"];
	    }
	}
	export class PeerInfo {
	    public_key: string;
	    assigned_ip: string;
	    hostname: string;
	    magic_name: string;
	    endpoint: string;
	    rx_bytes: number;
	    tx_bytes: number;
	    p2p_state: string;
	    connection: string;
	    last_handshake: number;

	    static createFrom(source: any = {}) {
	        return new PeerInfo(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.public_key = source["public_key"];
	        this.assigned_ip = source["assigned_ip"];
	        this.hostname = source["hostname"];
	        this.magic_name = source["magic_name"];
	        this.endpoint = source["endpoint"];
	        this.rx_bytes = source["rx_bytes"];
	        this.tx_bytes = source["tx_bytes"];
	        this.p2p_state = source["p2p_state"];
	        this.connection = source["connection"];
	        this.last_handshake = source["last_handshake"];
	    }
	}
	export class PingResult {
	    target: string;
	    ip: string;
	    reachable: boolean;
	    latency_ms: number;
	    connection: string;
	    message: string;

	    static createFrom(source: any = {}) {
	        return new PingResult(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.target = source["target"];
	        this.ip = source["ip"];
	        this.reachable = source["reachable"];
	        this.latency_ms = source["latency_ms"];
	        this.connection = source["connection"];
	        this.message = source["message"];
	    }
	}
	export class StatusData {
	    configured: boolean;
	    running: boolean;
	    device_running: boolean;
	    tun_mode: boolean;
	    tun_name: string;
	    offer_exit_node: boolean;
	    local_access: boolean;
	    local_access_routes: string[];
	    magic_dns: boolean;
	    dns_servers: string[];
	    ips: string[];
	    pubkey: string;
	    rx_bytes: number;
	    tx_bytes: number;
	    peers: PeerInfo[];

	    static createFrom(source: any = {}) {
	        return new StatusData(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.configured = source["configured"];
	        this.running = source["running"];
	        this.device_running = source["device_running"];
	        this.tun_mode = source["tun_mode"];
	        this.tun_name = source["tun_name"];
	        this.offer_exit_node = source["offer_exit_node"];
	        this.local_access = source["local_access"];
	        this.local_access_routes = source["local_access_routes"];
	        this.magic_dns = source["magic_dns"];
	        this.dns_servers = source["dns_servers"];
	        this.ips = source["ips"];
	        this.pubkey = source["pubkey"];
	        this.rx_bytes = source["rx_bytes"];
	        this.tx_bytes = source["tx_bytes"];
	        this.peers = this.convertValues(source["peers"], PeerInfo);
	    }

		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}
