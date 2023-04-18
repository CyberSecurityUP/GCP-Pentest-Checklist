# GCP-Pentest-Checklist

## PenTest Guideline

### Network mapping and reconnaissance:

- Technique: Gather information about your GCP infrastructure using DNS enumeration, IP scanning, and network topology discovery.
- Tools: Nmap, DNSRecon, and Google Cloud SDK.

### Virtual machine (VM) vulnerability scanning:

- Technique: Identify vulnerabilities in your Compute Engine instances by scanning the operating system, services, and applications.
- Tools: OpenVAS, Nessus, or Qualys.

### Cloud Storage bucket permissions:

- Technique: Check for misconfigured access control lists (ACLs) and permissions that may expose sensitive data in Google Cloud Storage buckets.
- Tools: GCPBucketBrute or BucketScanner.

### Identity and Access Management (IAM) review:

- Technique: Review IAM roles and permissions to ensure the principle of least privilege is enforced.
- Tools: GCP's IAM & Admin console, Google Cloud SDK, or Forseti Security.

### Web application vulnerability assessment:

- Technique: Test for common vulnerabilities in web applications, such as SQL injection, Cross-Site Scripting (XSS), and Cross-Site Request Forgery (CSRF).
- Tools: Burp Suite, OWASP ZAP, or SQLMap.

### Container security assessment:

- Technique: Assess vulnerabilities in container images deployed in your GCP environment, including Docker and Kubernetes.
- Tools: Trivy, Clair, or Google Cloud Container Registry Vulnerability Scanning.

### Cloud API security testing:

- Technique: Test for vulnerabilities in GCP APIs, such as authentication and authorization flaws, insecure endpoints, or data exposure.
- Tools: Postman, Rest-Assured, or SoapUI.

### Infrastructure as Code (IaC) review:

- Technique: Analyze your IaC templates (e.g., Terraform, Google Cloud Deployment Manager) for security misconfigurations.
- Tools: Checkov, Kics, or Google Cloud Security Scanner

### Data exfiltration testing:

- Technique: Simulate data exfiltration attempts to ensure security controls prevent unauthorized data transfers.
- Tools: Google Cloud SDK, Ncat, or CURL.

### Social engineering and phishing:

- Technique: Test employees' awareness of social engineering and phishing attacks by simulating real-world scenarios.
- Tools: Gophish, Social-Engineer Toolkit (SET), or King Phisher.

## Lateral Movement

### Techniques

- Create a controlled testing environment: Set up a separate, isolated GCP environment that mirrors your production environment to prevent any potential damage or disruption during the security testing process.
- Simulate lateral movement scenarios: Use test credentials or service accounts with limited privileges, similar to what an attacker might gain access to in a real-world scenario.
- Test Workspace access: Verify if the test account can access sensitive resources or data within Google Workspace, such as Google Drive, Google Docs, or other applications.
- Test IAM policies and permissions: Assess whether it's possible to grant additional permissions or roles to the test account or other accounts within your environment, allowing unauthorized access to other resources.
- Test network configurations: Check if the test account can access or exploit network configurations, such as VPCs, firewall rules, or VPN tunnels, to move laterally within the environment.
- Evaluate the potential for pivoting: Determine if the test account can leverage gained access to one resource (e.g., a VM instance) to compromise other resources within the environment.
- Monitor and log access attempts: Ensure your monitoring and logging systems can effectively detect and alert you to unauthorized access attempts or lateral movement.
- Review potential attack vectors: Examine your infrastructure and applications for vulnerabilities that could allow an attacker to move laterally, such as insecure APIs, unpatched systems, or weak authentication mechanisms.

### Commands

- gcloud compute networks list --project=PROJECT_ID
- gcloud compute firewall-rules list --project=PROJECT_ID
- gcloud compute instances list --project=PROJECT_ID
- gcloud compute ssh INSTANCE_NAME --zone=ZONE

### Links

- https://hackingthe.cloud/gcp/post_exploitation/lateral-movement/

- https://panther.com/blog/analyzing-lateral-movement-in-google-cloud-platform/

- https://infosecwriteups.com/enumeration-and-lateral-movement-in-gcp-environments-c3b82d342794

- /https://i.blackhat.com/executive-interviews/2020/Informa-BH_20200903_GCP-Lateral-Movement-and-Privilege-Escalation_v2.pdf

- https://www.classcentral.com/course/youtube-lateral-movement-privilege-escalation-in-gcp-compromise-organizations-without-dropping-an-implant-139733

- https://gsl.dome9.com/D9.GCP.IAM.11.html

## Hunting Credentials

- https://hackingthe.cloud/gcp/post_exploitation/treasure_hunting/

- https://www.mitiga.io/blog/google-cloud-platform-exfiltration-a-threat-hunting-guide

- https://www.youtube.com/watch?v=mJ_CoVevVP0&ab_channel=CloudSecurityPodcast

- https://lightrun.com/answers/googlecloudplatform-spring-cloud-gcp-fetch-new-secrets-by-spring-cloud-gcp-secretmanager-after-secrets-updated-in-google-secret-manager

- https://github.com/google-github-actions/get-secretmanager-secrets

- https://github.com/GoogleCloudPlatform/berglas

- https://github.com/jenkinsci/gcp-secrets-manager-credentials-provider-plugin

- https://www.strongdm.com/docs/admin/secret-stores/gcp-secret-manager

- https://github.com/go-task/task/pull/905

- https://medium.com/google-cloud/store-service-account-keys-in-gcp-secret-manager-d74f0a1d11fc

- https://www.freecodecamp.org/news/google-cloud-platform-from-zero-to-hero/

- https://blog.marcolancini.it/2018/blog-arsenal-cloud-native-security-tools/

- https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html

## Initial Access 

### Stolen Credential

- https://akbu.medium.com/gcp-oauth-token-hijacking-in-google-cloud-part-1-fbf85333e6f5
- https://hackingthe.cloud/gcp/general-knowledge/client-credential-search-order/
- https://research.splunk.com/stories/gcp_account_takeover/
- https://www.youtube.com/watch?v=olthxiRoj_o&ab_channel=DayCyberwox
- https://book.hacktricks.xyz/network-services-pentesting/3690-pentesting-subversion-svn-server
- Mitigation

	- Use strong, unique passwords for each account and enforce multi-factor authentication (MFA) where possible.
	- Implement the principle of least privilege and regularly review IAM roles and permissions.
	- Monitor and log access attempts, and set up alerts for suspicious activity.
	- Keep your infrastructure and applications up-to-date and patched to minimize vulnerabilities.
	- Train your team on security awareness and best practices, including how to recognize and report phishing attempts and social engineering tactics.

- Create a controlled testing environment: Set up a separate, isolated GCP environment that mirrors your production environment to prevent any potential damage or disruption to your actual infrastructure during the penetration testing process.
- Simulate the stolen credential scenario: Use test credentials with similar privileges to those that may be targeted in a real-world attack. This will help you assess the potential impact and scope of a compromised account.
- Test access controls and monitoring: Verify if the stolen credentials can be used to access sensitive resources, such as source code repositories, databases, or virtual machines. Additionally, check if your monitoring and logging systems can effectively detect and alert you to unauthorized access attempts.
- Evaluate the potential for privilege escalation: Assess if the compromised account can be used to escalate privileges, either through the abuse of Identity and Access Management (IAM) roles or by exploiting misconfigurations in your environment.
- Identify potential attack vectors: Review your infrastructure and applications for vulnerabilities that could allow an attacker to leverage stolen credentials, such as insecure APIs, unpatched systems, or weak authentication mechanisms.

### Kubernetes

- Misconfigured RBAC (Role-Based Access Control): Attackers may exploit weak RBAC policies that grant excessive privileges or access to unauthorized users.
- Mitigation: Implement the principle of least privilege, ensuring users and service accounts have the minimum necessary permissions.
- Exposed Dashboard: An unprotected Kubernetes dashboard may provide attackers with unauthorized access to the cluster.
- Mitigation: Secure the dashboard using authentication and limit access to trusted IP addresses, or disable the dashboard if not needed.
- Unprotected etcd Data Store: The etcd data store contains sensitive information about the cluster. If it's exposed, an attacker can access secrets and configuration data.
- Mitigation: Enable authentication and secure communication with etcd using TLS. Limit access to etcd to trusted IPs and nodes.
- Insecure Container Images: Attackers may exploit known vulnerabilities in container images or use malicious images.
- Mitigation: Use trusted and up-to-date base images, scan images for vulnerabilities, and implement image signing and verification.
- Container Runtime Vulnerabilities: Vulnerabilities in the container runtime, such as Docker or containerd, can lead to security breaches.
- Mitigation: Keep container runtime software up-to-date and patched.
- Insecure Network Policies: Weak or missing network policies may enable unauthorized access between pods or services.
- Mitigation: Implement network segmentation using Kubernetes network policies or third-party solutions to limit communication between resources.
- Secrets Management: Improper handling of secrets can expose sensitive data, such as credentials or API keys, to unauthorized users.
- Mitigation: Use Kubernetes Secrets or third-party secret management solutions to securely store and manage sensitive data.
- API Server Exploitation: Attackers may target the Kubernetes API server to gain unauthorized access or perform malicious actions.
- Mitigation: Enable API server authentication and authorization, use TLS for communication, and limit API access to trusted IPs.
- Node-level Security: Compromised nodes can pose a risk to the entire cluster.
- Mitigation: Harden node security by keeping the host OS patched and secure, using security profiles, and monitoring node activity.
- Pod Security: Attackers may exploit vulnerabilities in pod configurations to gain unauthorized access or escalate privileges.
- Techniques

	- https://cloud.hacktricks.xyz/pentesting-cloud/kubernetes-security
	- https://www.4armed.com/case-studies/kubernetes-penetration-test-payments/
	- https://www.4armed.com/blog/hacking-kubelet-on-gke/
	- https://rhinosecuritylabs.com/cloud-security/kubelet-tls-bootstrap-privilege-escalation/
	- https://rhinosecuritylabs.com/assessment-services/gcp-penetration-testing/
	- https://sysdig.com/learn-cloud-native/kubernetes-security/gke-security-best-practices-guide/

## TOP 10 Vulnerabilities

### Insecure Cloud Storage Buckets:

- Exploit: Unauthorized access to publicly accessible or misconfigured storage buckets, leading to data leakage or unauthorized modification.

### Overly Permissive Identity and Access Management (IAM) Roles:

- Exploit: Assigning excessive privileges to users, allowing them to perform unintended actions, access sensitive data, or compromise resources.

### Weak Authentication and Authorization:

- Exploit: Insecure implementation of authentication and authorization mechanisms in GCP applications or APIs, enabling unauthorized access.

### Misconfigured Firewall Rules:

- Exploit: Inappropriate or overly permissive firewall rules in VPCs, leading to unauthorized access to Compute Engine instances or other resources.

### Unpatched VM Images or Containers:

- Exploit: Exploitation of known vulnerabilities in VM instances or containers due to missing security updates or use of outdated images.

### Insecure Secrets Management:

- Exploit: Improper handling of sensitive data, such as hardcoding secrets in source code or using insecure storage, which can lead to unauthorized access.

### Server-Side Request Forgery (SSRF) in GCP Applications:

- Exploit: Exploiting vulnerabilities in web applications or APIs to perform unauthorized requests, potentially accessing sensitive internal resources or metadata.

### Container Orchestration Misconfigurations:

- Exploit: Exploiting insecure configurations in Kubernetes clusters, such as weak RBAC policies or exposed dashboards, allowing unauthorized control over the cluster.

### Insecure Network Connections and Encryption:

- Exploit: Exploiting unencrypted communication or weak encryption protocols to intercept or modify data transmitted between GCP resources.

### Exposed APIs:

- Exploit: Inadvertently exposing APIs, making them publicly accessible or lacking proper access control, allowing unauthorized actions on GCP resources.

## Tools

- https://github.com/carlospolop/PurplePanda

- https://github.com/DenizParlak/hayat

- https://github.com/RhinoSecurityLabs/GCPBucketBrute

- https://github.com/marcin-kolda/gcp-iam-collector

- https://gitlab.com/gitlab-com/gl-security/security-operations/gl-redteam/gcp_firewall_enum

- https://github.com/initstring/cloud_enum

- https://github.com/0xsha/CloudBrute

- https://github.com/google/gcp_scanner

- https://gitlab.com/gitlab-com/gl-security/threatmanagement/redteam/redteam-public/gcp_enum

- https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation

- https://www.cyberwarfare.live/trainings/certified-google-cloud-red-team-specialist

## Recon DNS (Passive and Active)

### Passive DNS Reconnaissance:

- Google Public DNS (https://developers.google.com/speed/public-dns)
- SecurityTrails (https://securitytrails.com/)
- VirusTotal (https://www.virustotal.com/gui/home/search)
- PassiveTotal (https://www.passivetotal.org/)
- DNSDumpster (https://dnsdumpster.com/)

### Active DNS Reconnaissance:

- Dig: Command-line tool available on most Unix-based systems to query DNS servers directly (https://linux.die.net/man/1/dig).
- Nslookup: Command-line tool available on most operating systems to query DNS records (https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/nslookup).
- DNSRecon: Python-based tool for enumerating DNS records, zone transfers, and more (https://github.com/darkoperator/dnsrecon).
- Fierce: Perl-based tool for DNS enumeration, subdomain scanning, and zone transfers (https://github.com/mschwager/fierce).
- Sublist3r: Python-based tool for enumerating subdomains using various search engines and services (https://github.com/aboul3la/Sublist3r).

## GCP Cli

### Manage oauth2 credentials for the Google Cloud CLI

- gcloud auth login
- gcloud auth activate-service-account --key-file creds.json
- gcloud auth activate-service-account --project=<projectid> --key-file=filename.json
- gcloud auth list
- gcloud auth revoke test@gmail.com
- gcloud config configurations activate stolenkeys
- gcloud config list
- gcloud organizations list
- gcloud organizations get-iam-policy <org ID>
- gcloud projects get-iam-policy <project ID>
- gcloud iam roles list  --project=<project ID>
- gcloud beta asset search-all-iam-policies --query policy:"projects/xxxxxxxx/roles/CustomRole436" --project=xxxxxxxx
- gcloud projects list
- gcloud config set project <project name>
- gcloud services list
- gcloud projects list
- gcloud config set project [Project-Id]
- gcloud source repos list
- gcloud source repos clone <repo_name>

### Org Enumeration

- gcloud organizations list: This command lists all the organizations that the authenticated user has access to.
- gcloud organizations describe [ORGANIZATION_ID]: This command describes an organization, including its display name, ID, and creation time.
- gcloud organizations get-iam-policy [ORGANIZATION_ID]: This command gets the IAM policy of an organization, which specifies who has what permissions within the organization.
- gcloud organizations get-iam-policy [ORGANIZATION_ID] --flatten: This command gets the flattened IAM policy of an organization, which combines all the policies that apply to the organization into a single policy.
- gcloud organizations get-iam-policy [ORGANIZATION_ID] --format=json: This command gets the IAM policy of an organization in JSON format.

### GCP IAM Enumeration

- # Roles
- ## List roles
- gcloud iam roles list --project $PROJECT_ID # List only custom roles
- gcloud iam roles list --filter='etag:AA=='
- ## Get permis and description of role
- gcloud iam roles describe roles/container.admin
- gcloud iam roles describe --project <proj-name> <role-name>
- # Policies
- gcloud organizations get-iam-policy <org_id>
- gcloud resource-manager folders get-iam-policy <folder-id>
- gcloud projects get-iam-policy <project-id>
- # MISC
- ## Testable permissions in resource
- gcloud iam list-testable-permissions --filter "NOT apiDisabled: true" <resource>
- ## Grantable roles to a resource
- gcloud iam list-grantable-roles <project URL>
- Enumeration via cloudasset

	- gcloud asset search-all-iam-policies #By default uses current configured folder
	- gcloud asset search-all-iam-policies --scope folders/1234567
	- gcloud asset search-all-iam-policies --scope organizations/123456
	- # Needs perm "cloudasset.assets.analyzeIamPolicy" over the asset
	- gcloud asset analyze-iam-policy --organization=<org-id> \
	-             --identity='user:carlos.polop@hacktricks.xyz'
	- gcloud asset analyze-iam-policy --folder=<folder-id> \
	-             --identity='user:carlos.polop@hacktricks.xyz'
	- gcloud asset analyze-iam-policy --project=<project-name> \
	-             --identity='user:carlos.polop@hacktricks.xyz'

- https://cloud.hacktricks.xyz/pentesting-cloud/gcp-security/gcp-services/gcp-iam-and-org-policies-enum

### Service Enumeration

- gcloud services list: This command lists all the available services in the current project and their statuses.
- gcloud services list --enabled: This command lists only the enabled services in the current project.
- gcloud services list --filter="state:ACTIVE": This command lists only the active services in the current project.
- gcloud services list --filter="config.name:compute.googleapis.com": This command lists only the services that contain "compute.googleapis.com" in their config name.
- gcloud services describe [SERVICE_NAME]: This command describes a service, including its display name, ID, and documentation link.
- gcloud services list --format="table(config.name, state)": This command lists the services in a tabular format, including their config name and state.
- gcloud services enable [SERVICE_NAME]: This command enables a service in the current project.
- gcloud services disable [SERVICE_NAME]: This command disables a service in the current project.
- gcloud services usage [SERVICE_NAME]: This command shows the usage statistics for a particular service.
- gcloud services list --project=[PROJECT_ID]: This command lists all the services available in a specified project.

### GCP No Authenticated 

- gcloud compute images list --project=ubuntu-os-cloud: This command lists the publicly available Ubuntu images in the ubuntu-os-cloud project.
- gcloud compute machine-types list --project=debian-cloud: This command lists the publicly available machine types in the debian-cloud project.
- gcloud compute zones list: This command lists the available compute zones in the current project.
- gcloud components list: This command lists the available components that can be installed using the gcloud command-line tool.
- gcloud help: This command displays the list of available gcloud command-line tools and their description.

### Capture Glocud and Gsutil

- gcloud config set proxy/address 127.0.0.1
- gcloud config set proxy/port 8080
- gcloud config set proxy/type http
- gcloud config set auth/disable_ssl_validation True
- # If you don't want to completely disable ssl_validation use:
- gcloud config set core/custom_ca_certs_file cert.pem
- # Back to normal
- gcloud config unset proxy/address
- gcloud config unset proxy/port
- gcloud config unset proxy/type
- gcloud config unset auth/disable_ssl_validation
- gcloud config unset core/custom_ca_certs_file

## Privilege Escalation 

### Techniques

- Create a controlled testing environment: Set up a separate, isolated GCP environment that mirrors your production environment to prevent any potential damage or disruption during the security testing process.
- Simulate the privilege escalation scenario: Use test credentials or service accounts with limited privileges, similar to what an attacker might gain access to in a real-world scenario.
- Test IAM policies and permissions: Assess whether it's possible to grant additional permissions or roles to the test account or other accounts within your environment.
- Test resource access: Verify if the test account can access or modify resources it should not be able to, such as Compute Engine instances, Cloud Storage buckets, or databases.
- Test service account keys and API access: Check whether the test account can access or modify service account keys, or exploit API access to gain additional privileges.
- Monitor and log access attempts: Ensure your monitoring and logging systems can effectively detect and alert you to unauthorized access attempts or privilege escalation.
- Review potential attack vectors: Examine your infrastructure and applications for vulnerabilities that could allow an attacker to escalate privileges, such as insecure APIs, unpatched systems, or weak authentication mechanisms.

### Commands

- gcloud projects get-iam-policy PROJECT_ID --flatten="bindings[].members" --format='table(bindings.role,bindings.members)' --filter="bindings.members:ACCOUNT_EMAIL"
- gcloud projects add-iam-policy-binding PROJECT_ID --member=user:ACCOUNT_EMAIL --role=roles/ROLE_NAME
- gcloud iam service-accounts list --project=PROJECT_ID
- gcloud iam service-accounts keys create ~/key.json --iam-account=SERVICE_ACCOUNT_EMAIL
- gcloud auth activate-service-account --key-file=~/key.json
- gcloud COMMAND --project=PROJECT_ID

- https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation

- https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/

- https://hackingthe.cloud/gcp/exploitation/gcp-priv-esc/

- https://about.gitlab.com/blog/2020/02/12/plundering-gcp-escalating-privileges-in-google-cloud-platform/

- https://www.praetorian.com/blog/google-cloud-platform-gcp-service-account-based-privilege-escalation-paths/

- https://www.youtube.com/watch?v=kyqeBGNSEIc&ab_channel=BlackHat

- https://gcpgoat.joshuajebaraj.com/privilege-escalation-compute.html

