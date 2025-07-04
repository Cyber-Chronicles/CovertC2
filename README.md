# Covert C2 Server w/ Terraform + AWS

## Overview

This repository contains the Terraform/AWS infrastructure setup for deploying a covert Command and Control (C2) infrastructure for red team ops. 
The agents on a workstation connect through to your domain, then have the traffic filtered thoroughly first by the Apache Redirector(EC2) and then once meets the specifications it will pass it onto the C2 server over TLS. This is just a Tier 1 setup, a Tier 2 setup would normally have an additional redirector in front of the Redirector EC2 like a Lambda Function.
[Checkout the write up here!](https://cyberchronicles.org/posts/5/)

## Architecture
![architecture diagram](/architecture.png)
```
Linux/Windows Agent → Domain → Public EC2 (Apache ProxyPass) → Private EC2 (C2 Server)
```

The infrastructure provides:
- **Covert Communications**: TLS-encrypted traffic through legitimate-looking endpoints
- **Network Isolation**: C2 server isolated in private subnet with no public IP
- **Stealth Operations**: Apache ProxyPass redirector filters out bots and malicious user-agents
- **GET Requests**: Are done via this endpoint only `/api/v2/status`
- **POST Requests**: Are done via this endpoint only `/api/v2/users/update`
- **Headers**: A valid user-agent and custom header `Access-X-Control: 000000011110000000` are required to reach the C2.
- **AWS US-WEST-2**: This setup uses us-west-2 by default, for local engagement ensure to edit the variables.tf to a closer region to you.
  
## Prerequisites

Before deploying this infrastructure ensure you have:

- ✅ **Domain Ownership**: A domain you own (I recommend using Cloudflare as the registrar)
- ✅ **AWS Account**: A valid AWS account with root access
- ✅ **AWS Credentials**: An IAM user with `AdministratorAccess` policy and generated access keys
- ✅ **Linux Environment**: Linux distro for deployment (I prefer Kali)
- ✅ **Terraform+AWS**: Terraform and awscli installed

### Optional
      
Before running Terraform, if you wish to change the values of the custom access control header or the redirect url, they can be found at:
- Google.com references:
    - File:redirectorconfig.sh Line:147, 196, 223, 230, 234, 238, 248, 366, 387, 404, 422, 439, 457, 496, 500, 633, 637, 641
- Custom access control headers references:
    - File:redirectorconfig.sh Line:188
    - File:linux_agent.py.tpl Line:23
    - File:windows_agent.pls1.tpl Line:14

---

### 1. The Setup

```bash
git clone https://github.com/h1dz/C2deploy && cd C2deploy

#Now you need to configure your AWS keys that you generated earlier on your Linux host, (ensure awscli is installed):
aws configure

#Next is to run Terraform:
terraform fmt
terraform init
terraform plan
terraform validate
terraform apply

#During setup you will be asked to enter your FQDN, this will be the domain you own, like example.com.
#If all went well, after 3-5 minutes or so it should finish and the output should be a public IP of the Redirector, a private IP of the C2,
#And two SSH commands, make a note of the commands and we will come back to them later.
#Also the linux and windows agents have been setup and are ready to use, found in the repo folder after running terraform apply. You can safely delete the .tpl files now.
#Now to update the DNS records of your site.
#Set an A record with name: www to your EC2 Redirector IP > proxy status is DNS Only(disabled/off) 
#Set another A record with the name @ > proxy status is DNS Only(disabled/off). 
#Wait at least 15 minutes for the DNS to propagate and/or check to see if it points to new IP yet:
dig +short <yourdomain.com> 

#SSH into the redirector EC2 and run the Apache config script 'redirectorconfig.sh', ensure you change the file name ###### to whats in your directory.
eval "$(ssh-agent -s)"
ssh-add ubuntu-SSH-Key-######.pem 
ssh -A ubuntu@<redirectorIP> -i ubuntu-SSH-Key-######.pem 
sudo nano redirectorconfig.sh
#Copy the code from the script 'redirectorconfig.sh' and paste it to this file on the Redirect server, then run it using your Root Domain and TLD, (ie sudo ./redirectorconfig.sh example com):
sudo ./redirectorconfig.sh <domain> <com>
#Allow some time for this to complete, usually takes another 3-5 minutes. Don't touch it until you see "[+] Successfully commented duplicate VirtualHost blocks after first SSL config in /etc/apache2/sites-available/########-le-ssl.conf".

#Once done, try SSH into the C2 server and setup a nc listener to check its working: 
ssh -A -J ubuntu@<redirectorIP> -i ubuntu-SSH-Key-######.pem ubuntu@10.10.1.204
nc -lvnp 4443
#Test connections from your Linux host by sending some curl requests with and without headers to make sure they are handled properly with redirects.
curl -X GET https://<yourdomain.com>/     #should be a 302 Found response~
curl -X GET https://<yourdomain.com>/api/v2/status -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"    #should be a 302 Found response~
#This last test should hang and there should now be some garbled output from the nc listener on the C2, it looks like this because its encrypted TLS traffic using a basic HTTP listener.
curl -X GET https://<yourdomain.com>/api/v2/status -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" -H "Access-X-Control: 000000011110000000"    #should hang with a response on the C2
#C2 Infra setup complete and ready to use.
#Should you wish to destroy the infrastructure, simply run: terraform destroy
```

### 2. C2 + Agent Deployment
**C2**:
```bash
sudo python3 C2.py
```

**Linux Agent**:
```bash
python3 linux_agent.py
```

**Windows Agent**:
```powershell
.\windows_agent.ps1
```

## C2 Commands

| Command | Description |
|---------|-------------|
| `sessions` | Lists all active callbacks/sessions |
| `sessions <AgentID>` | Joins selected session by Agent ID |
| `kill <AgentID>` | Terminates selected session |

## Future Additions
- *Monitor error and access logs of EC2s for better security with CloudWatch — not currently implemented in this setup.*
- *Change local terraform state file to be stored in an s3 bucket instead of a local machine.*
- *Improve C2 script.*
- *Create a Tier 2 setup by adding additional hop with a lambda Function and API Gateway that routes the initial traffic to the Redirector EC2.*

## Conclusion
- Was a pleasure to build this setup, as of 05/07/25 the windows_agent.ps1 did not get detected by local Defender.
- If you have not got an AWS account handy or a spare domain to use, it could take anywhere from 20 ~ 30 minutes to set this all up.
- If you already have an AWS account ready and a domain, the time to setup the infrastructure with this repo is 10 minutes.
- Average cost per 30 days if not shutdown: $33
- Average cost per day: $1~$2
```
