export namespace main {
	
	export class AccountInfo {
	    logged_in: boolean;
	    token: string;
	    display_name: string;
	    email: string;
	    avatar_url: string;
	
	    static createFrom(source: any = {}) {
	        return new AccountInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.logged_in = source["logged_in"];
	        this.token = source["token"];
	        this.display_name = source["display_name"];
	        this.email = source["email"];
	        this.avatar_url = source["avatar_url"];
	    }
	}
	export class PeerInfo {
	    public_key: string;
	    name: string;
	    hostname: string;
	    endpoint: string;
	    allowed_ips: string;
	    rx_bytes: number;
	    tx_bytes: number;
	    last_handshake: string;
	    is_relay: boolean;
	    is_exit_node: boolean;
	    latency_ms: number;
	
	    static createFrom(source: any = {}) {
	        return new PeerInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.public_key = source["public_key"];
	        this.name = source["name"];
	        this.hostname = source["hostname"];
	        this.endpoint = source["endpoint"];
	        this.allowed_ips = source["allowed_ips"];
	        this.rx_bytes = source["rx_bytes"];
	        this.tx_bytes = source["tx_bytes"];
	        this.last_handshake = source["last_handshake"];
	        this.is_relay = source["is_relay"];
	        this.is_exit_node = source["is_exit_node"];
	        this.latency_ms = source["latency_ms"];
	    }
	}
	export class StatusData {
	    configured: boolean;
	    running: boolean;
	    device_running: boolean;
	    tun_mode: boolean;
	    tun_name: string;
	    exit_node: boolean;
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
	        this.exit_node = source["exit_node"];
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

