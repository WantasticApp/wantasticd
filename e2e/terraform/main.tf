terraform {
  required_providers {
    docker = {
      source  = "kreuzwerker/docker"
      version = "~> 3.0.0"
    }
  }
}

provider "docker" {
  host = "unix:///var/run/docker.sock"
}

variable "clients" {
  description = "List of wantasticd clients to run"
  type        = list(string)
  default     = ["client1", "client2", "client3"]
}

# Assumes you have already built or pulled the wantasticd image locally
# If you want Terraform to build it, you can use the docker_image resource with a build block.
resource "docker_image" "wantasticd" {
  name         = "wantasticd:latest"
  keep_locally = true
}

resource "docker_container" "wantasticd_client" {
  for_each = toset(var.clients)

  name  = "wantasticd-${each.key}"
  image = docker_image.wantasticd.image_id

  # Start the command with the specific config file
  command = ["-config", "/etc/wantasticd/config.json"]

  # They need TUN device for WireGuard/networking
  devices {
    host_path      = "/dev/net/tun"
    container_path = "/dev/net/tun"
  }

  capabilities {
    add = ["NET_ADMIN"]
  }

  # Ensure the container can resolve the wg.wantastic.local domain
  # Adjust the IP depending on where your localized target actually lives (e.g. host.docker.internal)
  extra_hosts = [
    "wg.wantastic.local:host-gateway"
  ]

  # Mount the config file inside the container
  volumes {
    host_path      = abspath("${path.module}/configs/${each.key}.json")
    container_path = "/etc/wantasticd/config.json"
    read_only      = true
  }

  restart = "unless-stopped"
}
