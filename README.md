# email-validator
High-Level Architecture
                                   ┌─────────────────┐
                                   │                 │
                                ┌──►  Redis Cache    │
                                │  │                 │
                                │  └─────────────────┘
                                │
┌─────────┐     ┌──────────┐    │     ┌─────────────────┐
│         │     │          │    │     │                 │
│ Users   ├────►│  Nginx   ├────┼────►  API Service     │
│         │     │          │    │     │  (Golang)       │
└─────────┘     └──────────┘    │     └────────┬────────┘
                                │              │
                                │              │
                                │     ┌────────▼────────┐
                                │     │                 │
                                └────►│  PostgreSQL DB  │
                                      │                 │
                                      └─────────────────┘
Cyberattacks has been on rise recently and the Company would like to setup a website to allow 
users to check if their accounts have been compromised.  
## You have been tasked to do the following in Golang: 
• Create a simple Web that allow users to input their email address and validate if their 
accounts have been compromised 
• An HTTP RESTful API that validates against the cache and database if the email address is 
compromised 
• A Database that stores a list of emails that are compromised 
## Complete the exercise with the following: 
1. Deploy the workloads using containers (docker or Kubernetes) 
2. Demonstrate access to the website using Nginx Reverse Proxy 
3. [Bonus] Implement with security features in place 
4. [Bonus] Demonstrate load balancing using Nginx 
5. Describe the risks associated with the current solution and possible mitigation plans 
Please save your answers in the following format, and send it back to us. 
• Codes: Zip or provide a Github link 
• Screenshots of the Results 
• Setup Guide 
• High level architecture diagram and overview of your solution (PDF or Word is fine) 