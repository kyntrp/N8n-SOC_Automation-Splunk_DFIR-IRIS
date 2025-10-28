# SOC Automation Project with Splunk, n8n, and Atomic Red Team

## **Overview**


This project demonstrates how to build a SOC automation pipeline that detects suspicious activity on Windows endpoints, forwards telemetry to Splunk, and automates enrichment and triage using n8n, Slack, AbuseIPDB, and DFIR IRIS.
The workflow simulates adversary techniques with Atomic Red Team, generates alerts in Splunk, and forwards them via webhook to n8n for automated enrichment, case creation, and reporting.


<img width="1125" height="465" alt="image" src="https://github.com/user-attachments/assets/ab8f068e-d25a-4ae0-bae2-a5410ee61b28" />


## **Lab Environment**


•	**Windows 10** – endpoint for telemetry and Atomic Red Team execution <br>
•	**Kali Linux** – optional attack simulation (e.g., brute force with Hydra) <br>
•	**Ubuntu Server (Splunk Enterprise)** – SIEM for log ingestion and alerting <br>
•	**Ubuntu Server (n8n)** – automation/orchestration platform <br>
• **Ubuntu Server (DFIR-IRIS)** - incident response and case management platform for collaborative triage and investigation <br>



## **Automation Workflow**

**1.	Webhook Trigger (n8n)** <br>
-	Receives Splunk alert payload via HTTP POST. <br>
-	Example: EventCode 104 (System log cleared) or EventCode 4625 (failed logon) <br>


**2.	AI Agent (OpenAI)** <br>
-	Summarizes the alert. <br>
-	Maps to MITRE ATT&CK tactics/techniques. <br>
-	Provides initial severity assessment and recommended actions. <br>


**3.	AbuseIPDB Enrichment** <br>
-	Checks IP reputation for any source IPs in the alert. <br>


**4.	Slack Notification** <br>
- Sends enriched alert summary to a SOC channel for visibility. <br>


**5.	DFIR-IRIS Integration** <br>
-	Creates or updates a case for collaborative investigation. <br>


**6.	JavaScript Parser Node** <br>
-	Ensures consistent field naming for downstream systems. <br>
-	Makes Airtable and DFIR‑IRIS records easier to filter, categorize, and report on. <br>


**7.	Airtable Logging** <br>
-	Stores normalized alert data for backlog triage, manual resolution, and reporting. <br>
-	Enables weekly/monthly reporting by filtering on structured fields (e.g., by MITRE technique or severity). <br>


<br>
<br>

## **Splunk Setup**
<br>
Go to :  https://www.splunk.com/ <br>
Login or create an account. <br>
Click ‘platform’ > ‘free trials and downloads’. <br>


<img width="560" height="577" alt="image" src="https://github.com/user-attachments/assets/ecee5921-f07c-4c0c-a9c7-dc0472c01218" /> <br>
<br>


Under the ‘Splunk Enterprise’, select ‘Start trial’ <br>
Go to ‘Linux’ tab then click ‘copy wget link’  in ‘.deb’ <br>
<img width="1125" height="484" alt="image" src="https://github.com/user-attachments/assets/99c7bcaa-2f60-448c-8495-e41d6ddc37ae" /> <br>


connected using ssh, Paste it to CLI of ‘ubuntu server for splunk’ <br>
<img width="1125" height="466" alt="image" src="https://github.com/user-attachments/assets/8837ad39-2574-492f-af1e-9bce50815121" /> <br>


Once the download is done, install the package :
 ``` sudo dpkg -i splunk-10.0.1-c486717c322b-linux-amd64.deb ```
 <br>
 <img width="988" height="263" alt="image" src="https://github.com/user-attachments/assets/d2bbb6bc-5703-4cac-aec3-b90f74e14877" /> <br>


Change directory to splunk : ``` cd /opt/splunk ```  <br>
Change to splunk user : ``` sudo -u splunk bash ``` <br>
<img width="1125" height="477" alt="image" src="https://github.com/user-attachments/assets/c7a41e42-84b8-40eb-9c9b-975f5224f4a5" />
<br>



Run splunk : ``` ./splunk start ``` <br>
Press ‘spacebar’ until you reach the end of agreement. Create an account. <br>
<img width="1209" height="685" alt="image" src="https://github.com/user-attachments/assets/89edc998-a54b-4019-a311-c4e519bfcc94" /> <br>


Once it is done, exit the splunk account : ``` exit ``` <br> 
And go back to binary directory : ``` cd /opt/splunk/bin ``` <br> 
Make sure that the splunk run upon reboot : ``` sudo ./splunk enable boot-start -user splunk ``` <br>
<img width="1125" height="83" alt="image" src="https://github.com/user-attachments/assets/6a34e382-674a-49a6-8b00-f61035ca6fad" /> <br>


Using web browser and access splunk using the IP of the ubuntu server where the splunk is installed. <br>
<img width="938" height="670" alt="image" src="https://github.com/user-attachments/assets/7da3ddee-88d7-42d0-93a3-de99c132e561" /> <br>


Login the account created earlier : <br>
<img width="1125" height="353" alt="image" src="https://github.com/user-attachments/assets/ac872083-9315-4586-b597-759b3bafb7f6" /> <br>


On the upper right, click ‘settings’ >‘forwarding and receiving’ > ‘configure receiving’ > ‘new receiving port’  <br>
Input ‘9997’ which is the default port then click ‘save’  <br>
<img width="882" height="255" alt="image" src="https://github.com/user-attachments/assets/ba0b6113-5683-41b2-a765-cadc1be0bcab" /> <br>


Click the ‘settings’ > ‘indexes’ > ‘new index’ in the upper right.  <br>
Put the name of your index then click save. <br>

Click ‘Apps’ in the upper right > ‘Find more Apps’.  <br>
Search for ‘windows event’  then install the ‘Splunk Add-on for Microsoft Windows’  <br>
Note : login the account (email address) that used to download the splunk. Not the one created inside the splunk.  <br>
<img width="1125" height="483" alt="image" src="https://github.com/user-attachments/assets/f71d6a8c-33f8-4e74-917c-24f11e9e37ad" /> <br>


## **Windows Forwarder Setup**  
<br>


Next, go to windows 10 machine. Open the internet browser and go to ‘splunk.com’  <br>
Click ‘Trials and Downloads’ > download ‘Universal Forwarder’ <br>
<img width="1125" height="450" alt="image" src="https://github.com/user-attachments/assets/b6b9725b-3424-47fe-9ad8-b6fb9f937a8c" />  <br>


Select the ‘windows 10 64-bit’ <br>
<img width="1125" height="185" alt="image" src="https://github.com/user-attachments/assets/c97e2a56-1a60-4daf-bca8-52eb37a6275d" />



Run the downloaded file, accept the license agreement > ‘Next’ > create credential for admin account > skip the deployment server > in the receiving indexer, input the IP of ubuntu server for splunk. <br>
Input also the same port that we put in the splunk indexer that created earlier.
<br>
<img width="850" height="577" alt="image" src="https://github.com/user-attachments/assets/aa75d63e-ef86-4920-85ed-8d73d5c2ef99" /> <br>


One the installation succeded. This will appear : <br>
<img width="1125" height="682" alt="image" src="https://github.com/user-attachments/assets/9575cb9d-3f03-4e22-a795-0c124ef1c408" />  <br>


For configuration, go to : C:\Program Files\SplunkUniversalForwarder\etc\system\local <br>
Check if there is an ‘inputs.conf’ file. If none. Create it using notepad with admin elevation access. <br>


Paste this : <br>

```
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
index = insert-index-name-here
disabled = false
renderXml = true
source = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

[WinEventLog://Microsoft-Windows-Windows Defender/Operational]
index = insert-index-name-here
disabled = false
source = Microsoft-Windows-Windows Defender/Operational
blacklist = 1151,1150,2000,1002,1001,1000

[WinEventLog://Microsoft-Windows-PowerShell/Operational]
index = insert-index-name-here
disabled = false
source = Microsoft-Windows-PowerShell/Operational
blacklist = 4100,4105,4106,40961,40962,53504

[WinEventLog://Application]
index = insert-index-name-here
disabled = false

[WinEventLog://Security]
index = insert-index-name-here
disabled = false

[WinEventLog://System]
index = insert-index-name-here
disabled = false

[WinEventLog://Microsoft-Windows-TerminalServices-LocalSessionManager/Operational]
index = insert-index-name-here
disabled = false
```

<br>
then save as ‘inputs.conf’ make sure it is in the folder : C:\Program Files\SplunkUniversalForwarder\etc\system\local <br>
<img width="1125" height="296" alt="image" src="https://github.com/user-attachments/assets/15982488-16ba-4a07-965f-84d0359a6997" /> <br>


Search for ‘Services’ > right click ‘Run as administrator’ <br>
<img width="732" height="286" alt="image" src="https://github.com/user-attachments/assets/2d0644b4-14dd-4a3e-aab7-4626ae9a1a30" /> <br>


Search for ‘Splunk Forwarder’ > double click > go to ‘logon’ tab > select ‘Local System Account’ > ‘apply’  <br>
Restart the ‘Splunk Forwarder’ by right-clicking it > restart <br>
Confirm that the windows machine now send telemetry in splunk. <br>
Go back to splunk machine webpage. <br>
Click ‘Apps’ > ‘Search  and Reporting’ > search ‘index=<insert the name of your index>’ <br>
You must see a telemetry to the splunk : <br>
<img width="1125" height="627" alt="image" src="https://github.com/user-attachments/assets/d0c8d69f-60b1-474d-ae42-c0e5770c4ebb" /> <br>



## **N8n Setup**
<br>
Install docker in a ubuntu server :  <br>

``` sudo apt install docker.io ```  <br>
``` sudo apt install docker-compose ``` <br> 



Make a directory for the n8n : <br>
``` mkdir n8n-compose ```  <br>



Create a file for docker : <br>
``` sudo nano docker-compose.yaml ``` <br>


Input this inside : <br>
```
services:
  n8n:
    image: n8nio/n8n:latest
    restart: always
    ports:
      - "5678:5678"
    environment:
      - N8N_HOST=<insert the ip of ubuntu server for n8n>
      - N8N_PORT=5678
      - N8N_PROTOCOL=http
      - N8N_SECURE_COOKIE=false
      - GENERIC_TIMEZONE=America/Toronto
    volumes:
      - ./n8n_data:/home/node/.n8n
```
<br>
<img width="643" height="271" alt="image" src="https://github.com/user-attachments/assets/6d273540-401e-4812-bb56-b781ac647ff4" /> <br>


Save and exit then type :  : ``` sudo docker-compose pull ``` <br>
<img width="1125" height="116" alt="image" src="https://github.com/user-attachments/assets/9e3c54e3-1dce-4871-bf8f-f95f85589eed" /> <br>

Once the pulling is done, change the permission of the files downloaded  :  <br>

``` sudo chown -R 1000:1000 n8n_data ```
<br>
<img width="745" height="314" alt="image" src="https://github.com/user-attachments/assets/153f374c-8ed6-42d5-a511-52dbb427f284" /> <br>


Now try to start the docker-compose : ``` sudo docker-compose up -d ```  <br>
Wait for atleast 2-3mins then check if the n8n is accessible in browser : <br>
<img width="908" height="618" alt="image" src="https://github.com/user-attachments/assets/61fe68fa-1aab-4b7f-ad7b-8d1cd8e0ce2c" /> <br>



## **Splunk Alert → n8n Webhook**
<br>

Now for the alert that will be used for the automation, we can use any bruteforce available in kali (hydra, crowbar etc.) or just attempt to login with wrong credential multiple times for manual bruteforce.
<br>
We just need an event code 4625 (unsuccessful logon attempt on a windows computer) for our n8n automation. <br>

``` index="project-elias" EventCode=4625 ```

<br>
<img width="1125" height="631" alt="image" src="https://github.com/user-attachments/assets/9618987c-6575-4f73-991f-8633bbd61256" />  <br>


```Index="project-elias" EventCode=4625 | stats count by _time,ComputerName,user,src_ip```  <br>
<img width="1125" height="502" alt="image" src="https://github.com/user-attachments/assets/b8a59fb7-53b5-4b59-9b19-fa215654afcd" />
<br>
Click the ‘Save As’ in the upper right, select ‘Alert’ <br>


Input a title > change the schedule ‘Run on Cron Schedule’ > change the number in ‘Cron Expression to Asterisk ‘*’ > click ‘+Add Actions’ >  ‘Add to Triggere Alerts’ > add ‘Webhook’ too.  <br>
<img width="999" height="1357" alt="image" src="https://github.com/user-attachments/assets/9371a8ef-f1ef-4d1a-8ff2-5d3668b3723d" />  <br>


Go to n8n and create a new workflow. Add a trigger as ‘Webhook’ <br>
Change the HTTP Method to ‘POST’ then copy the Test URL.  <br>
<img width="1125" height="1093" alt="image" src="https://github.com/user-attachments/assets/07d5ef56-4260-44df-816b-ca42a2311ded" />
<br>


Go back to splunk and paste the copied URL to webhook URL, then hit ‘Save’. <br>
<img width="1125" height="713" alt="image" src="https://github.com/user-attachments/assets/0da02e34-805c-4508-ba1e-3aec3e985461" /> <br>


In N8n webhook, click ‘Listen for test event’ <br>
<img width="620" height="263" alt="image" src="https://github.com/user-attachments/assets/c92c6e4a-1395-4d1f-b009-95be511f08b8" /> <br>
Wait for 1-3mins
<br>
<img width="1125" height="525" alt="image" src="https://github.com/user-attachments/assets/e9d71f90-398e-41ac-866f-f90b9f4faf1b" />
<br>


Once you got the alert in n8n. Pin it and disable the alert in splunk. <br>
<img width="1125" height="208" alt="image" src="https://github.com/user-attachments/assets/449b98c2-0da2-4429-99a8-cf3f91f9e564" /> <br>



## **AI Model Setup**
<br>
Back to n8n. add another node > search for OpenAI > select ‘Message a model’ <br>
<img width="1125" height="876" alt="image" src="https://github.com/user-attachments/assets/f0a01615-5c7a-4f1a-a00c-881c64ad4666" />
<br>



Create new credential. Head over  to openai.com > click the ‘Login’ on the upper right > select ‘API platform’ > create an account > create an organization  > copy the API key > paste it to API Key for OpenAI Account : <br>
<img width="936" height="401" alt="image" src="https://github.com/user-attachments/assets/d7389553-c439-414a-a142-6d6ab3673506" />
<br>


<img width="1125" height="697" alt="image" src="https://github.com/user-attachments/assets/367e6ec5-a759-4c71-8edc-c4162925203f" />
<br>


Get free credit for OpenAI : <br>
1.	Go to the OpenAI Platform Dashboard <br>
- Visit: https://platform.openai.com <br>
- Log in with your OpenAI account. <br>
2.	Access Your Account Settings <br>
- Click your profile icon in the top-right corner. <br>
- Select “Settings” from the dropdown menu. <br>
3.	Navigate to the “Data Controls” Section <br>
- In the left sidebar, click on “Data Controls”. <br>
- This section manages how your data is used for model training and improvement. <br>
4.	Enable “Share Data for Training” <br>
- Look for a toggle or checkbox labeled “Improve model performance” or “Share data to help improve our models”. <br>
- Turn it ON to opt in. <br>



<img width="1125" height="797" alt="image" src="https://github.com/user-attachments/assets/8639c3f8-cc76-4cb1-81d5-3031d88bcdca" />
<br>


Check the usage, you will be given a $5 free credit : <br>
<img width="1125" height="325" alt="image" src="https://github.com/user-attachments/assets/e73c02bf-286d-4eb9-9cea-eddc6fd5214c" />
<br>



Back to n8n workflow, double click the AI agent, input this prompt : <br>

``` 
Act as Tier 1 SOC Analyst assistant. When provided with a security alert or incident details (including indicators of compromise, logs, or materials), perform the following steps:

Summarize the alert - Provide a clear summary of what triggered the alert, which system/users are affected, and the nature of the activity (for example: suspicious login, malware detection, lateral movement).

Enrich with threat intelligence - correlate any IOCs (IP addresses, domains, hashes) with known threat intel sources. Highlight if the indicators are associated with known malware or threat actors.

Assess severity - Based on MITRE ATT&CK mapping. Identify tactics/techniques, and provide and initial severity rating (Low, Medium, High, Critical).

Recommend next actions - Suggest investigation steps and potential containment actions. 
```

<br>


Set the role to ‘Assistant’ <br>
Click ‘Add Message’ to create another > set the role to ‘System’ <br>
Put this under the Prompt : <br>
``` Format output clearly - Return findings in a structured format (Summary, IOC, Enrichment, Severity Assesment, Recommended Actions). ```
<br>


Add another message and set the role to : User <br>
Input this under the prompt:   <br>

```
Alert : {{ $json.body.search_name }}
Alert Details : {{ JSON.stringify ($json.body.result,null,2)}}
```
<br>

<img width="466" height="815" alt="image" src="https://github.com/user-attachments/assets/39bdb4cb-a894-44a7-896b-b46ae7c8b68c" />   <img width="547" height="812" alt="image" src="https://github.com/user-attachments/assets/7ff3bb87-5b8e-4380-a535-9f7477fc3239" />

<br>


<img width="1326" height="328" alt="image" src="https://github.com/user-attachments/assets/14d0ed42-be28-40f2-a04a-645b384dee9c" />
<br>



## **Slack Setup **
<br>
Go to slack app or browser, Create an account > Create an Organization > create a channel. <br>

Go back to n8n, add another node for Slack with a  “send a message” action. <br>
Create new credential > go to slack API page :  https://api.slack.com/apps > create new app <br>
<img width="1125" height="441" alt="image" src="https://github.com/user-attachments/assets/63f6fabc-e81d-4ea4-8013-d4b246f2be44" />
<br>


Input a name and select the workspace you created earlier . <br>
Click ‘OAuth & Permissions’ in the left side > ‘Add an OAuth Scope’ under ‘Bot Token Scopes’ <br>
<img width="934" height="914" alt="image" src="https://github.com/user-attachments/assets/4af7083b-ac3d-45a7-b759-5427a856d0da" /> <br>


Under the ‘OAuth Tokens’ click ‘Install to <name of workspace>’ <br>
<img width="1125" height="394" alt="image" src="https://github.com/user-attachments/assets/9500d83d-5316-458c-a487-d68440c40a86" /> <br>


Copy the OAuth token and paste it to n8n ‘Access Token’  then click ‘Save’ <br>


<img width="443" height="736" alt="image" src="https://github.com/user-attachments/assets/5933571f-edee-471d-94bb-f5ca2ac281d5" /> <br>


Back in slack, right click the channel then ‘View channel details’ > integrations > add an Apps
<br>
<img width="776" height="630" alt="image" src="https://github.com/user-attachments/assets/c200e57e-98e5-4c64-a583-02b65c13de0b" />
<br>


Select you workspace : <br>
<img width="613" height="708" alt="image" src="https://github.com/user-attachments/assets/f6861b14-199f-43c5-b7be-aca711adda0f" />
<br>


Now in n8n, try the slack connection by clicking ‘Execute step’. <br>
<img width="917" height="824" alt="image" src="https://github.com/user-attachments/assets/c2776a5e-8c68-434e-97b4-bd7f563aa59f" />
<br>


<img width="1125" height="189" alt="image" src="https://github.com/user-attachments/assets/e36b1b61-1fa4-43af-931e-915b3ac7f426" />
<br>


Now we confirm that we connected the n8n to slack, remove the message text in the slack node. <br>
And replace it by dragging the ‘content’ from the left side to the textbox :  <br>
<img width="1167" height="632" alt="image" src="https://github.com/user-attachments/assets/80caa9ff-88c6-44e3-b324-6c32dd77cea6" />
<br>


Click the ‘execute step’ again in the slack node and check the slacks If it got the message : <br>
<img width="1125" height="639" alt="image" src="https://github.com/user-attachments/assets/b55267ff-b71f-45bb-9ac1-45ae5568e3a3" />
<br>


## **AI Agent Tool - AbuseIPDB Setup**
Since this lab is on-prem and the source IP I used to brute force can’t be detected as malicious.  <br>
I will try to manual input the source IP and use a malicious IP from ‘abuseipdb’ to simulate what it looks like when a bad actor try to brute force my system. <br>


Copy one of the IP in the ‘Reported IPs’ <br>
<img width="1125" height="605" alt="image" src="https://github.com/user-attachments/assets/02a5fed3-ec33-44df-97dd-d6141f0a8bee" /> <br>


Click the AI model. In Prompt, change the alert details. <br>
Remove the ‘null’ and change it to : 'user','ComputerName','_time' <br>
Then at the bottom of it, add the ‘Source IP : (paste  IP copied earlier from AbuseIPDB)' <br>
<img width="704" height="1069" alt="image" src="https://github.com/user-attachments/assets/c61bad66-f4ad-42f9-9d64-c1bbe12024df" />
<br>


Register or login to abuseIPDB, head over to ‘API’ then ‘create key’ <br>
Go to abuseIPDB manual : https://docs.abuseipdb.com/#introduction <br>
Click ‘CHECK Endpoint’ in the left side. <br>
Copy the curl :  <br>
<img width="1125" height="224" alt="image" src="https://github.com/user-attachments/assets/07c40251-af0b-4e84-b653-a2cc353bc8d5" />
<br>


```
curl -G https://api.abuseipdb.com/api/v2/check \
  --data-urlencode "ipAddress=118.25.6.39" \
  -d maxAgeInDays=90 \
  -d verbose \
  -H "Key: YOUR_OWN_API_KEY" \
  -H "Accept: application/json"
```
<br>


Add a node in the ‘Tools’ of the model, search HTTP Request Tool. Click the ‘Import cURL’ at the bottom of Description then paste the cURL from abuseIPDB : <br>
<img width="344" height="288" alt="image" src="https://github.com/user-attachments/assets/744c176a-055d-4889-9ace-8aadda996177" />
<br>


<img width="748" height="590" alt="image" src="https://github.com/user-attachments/assets/d9779389-7cbf-464d-bc5e-f6494f153c8b" />
<br>
Under the ‘ipAddress’ remove the IP in the value and use the same IP address we put in the AI model prompt :
<br>
<img width="656" height="788" alt="image" src="https://github.com/user-attachments/assets/4da1d1d6-3700-4c08-990f-8f574ae2d3c8" />
<br>


Scroll down in the Header Parameters named ‘Key’ replace the value of your own API key created ealier : <br>
<img width="461" height="688" alt="image" src="https://github.com/user-attachments/assets/88dd2fde-0846-45e1-a18d-dd1558ce4677" />
<br>


Try to ‘Execute step’  to check if the API is working :  <br>
<img width="1125" height="973" alt="image" src="https://github.com/user-attachments/assets/eb5af149-a039-405d-9de5-6571c68c75d0" />
<br>


Now, remove the IP under ‘ipAddress’ and click the icon on the right side, so that the AI will decide the IP to use. <br>
<img width="495" height="950" alt="image" src="https://github.com/user-attachments/assets/0136ddaa-d8a5-45d3-a073-0f4fee5e7cd9" /> <br>


Rename the’ HTTP request’ to ‘AbuseIPDB’ <br>


Go back to ‘message a model’. Under the Prompt of ‘Assistant’ <br>
Add : For any IP enrichment, use the tool named 'AbuseIPDB-Enrichment' <br>
<img width="659" height="1165" alt="image" src="https://github.com/user-attachments/assets/adafbe99-8978-45da-8827-ce4c6ab4f6ca" /> <br>


Try to ‘Execute step’ :  <br>
<img width="1125" height="893" alt="image" src="https://github.com/user-attachments/assets/d73a9424-757e-4256-b73a-efc22daa98e0" />
<br>


Try to execute step also in ‘Slack’ node :  <br>
<img width="1125" height="517" alt="image" src="https://github.com/user-attachments/assets/8c2d6807-887e-4263-bbf8-b0805bc336c7" />


## **DFIR-IRIS Setup**
<br>


Install DFIR-IRIS (https://github.com/dfir-iris/iris-web?tab=readme-ov-file) <br>
Clone the iris-web repository : <br>
```
git clone https://github.com/dfir-iris/iris-web.git
cd iris-web
```
<br>


Checkout to the last tagged version  :  ``` git checkout v2.4.20 ```
<br>

Copy the environment file  :  ``` cp .env.model .env ```
<br>
Pull the dockers : ``` docker compose pull ```
<br>
Run IRIS  : ``` docker compose up ```
<br>


Iris shall be available on the host interface, port 443, protocol HTTPS -  https://<your_instance_ip>.


<br>
By default, an administrator account is created. The password is printed in stdout the very first time Iris is started. It won't be printed anymore after that.
<br>

```  docker logs iriswebapp_app | grep create_safe_admin ```
<br>
<img width="1125" height="106" alt="image" src="https://github.com/user-attachments/assets/e0cc7a27-21ed-471a-b06e-0ba088869090" />
<br>


 Try to access the webpage using browser and login the account : <br>
 <img width="1125" height="657" alt="image" src="https://github.com/user-attachments/assets/10a3b132-ea40-4d7b-9d70-9cc6fc185e63" />
<br>


Back to n8n, add a node, search for ‘DFIR-IRIS’ <br>
<img width="621" height="333" alt="image" src="https://github.com/user-attachments/assets/40e159b2-0804-4c58-bffc-971ece1a4ee7" />
<br>


For credential, go to ‘My settings’ : <br>
<img width="494" height="225" alt="image" src="https://github.com/user-attachments/assets/ed99d7b7-d425-42f7-8569-73ceaf185af9" /> 
<br>


Copy the API Key then go back to n8n credential creation, paste it. Then Base URL, paste the IRIS address, enable also the ‘Ignore SSL Issues(insecure) : <br>
<img width="1125" height="680" alt="image" src="https://github.com/user-attachments/assets/6908bd39-cefa-41c8-a6bd-1926964ef92d" />
<br>


My IRIS has expired SSL so it can be connected even it’s insecure. Not a big deal since this is just a lab. But in production, make sure all SSL issue is attended and fixed before deploying. <br>
<img width="905" height="131" alt="image" src="https://github.com/user-attachments/assets/9775d2c2-b064-423b-a2cf-b27edc53883c" />
<br>


Next, go to DFIR-IRIS documentation, copy the cURL :  <br>
<img width="662" height="232" alt="image" src="https://github.com/user-attachments/assets/e5067cc4-1f3c-4fcd-a188-16197ea47d20" />
<br>


Then paste it to n8n ‘import cURL’ <br>
<img width="582" height="302" alt="image" src="https://github.com/user-attachments/assets/e4e89ae1-f0bf-440e-bf5d-049ce49fd53c" />
<br>


Back to DFIR-IRIS node, use this URL : ```https://<IP-of-IRIS-here>/manage/cases/add``` <br>
Set it to ‘POST’ method <br>
<img width="488" height="786" alt="image" src="https://github.com/user-attachments/assets/2f51905c-2579-40b0-bc0c-e4582c3b61d9" />
<br>


In Headers, input ‘Authorization’ in name’ and value ‘Bearer (IP key)’ <br>
<img width="453" height="369" alt="image" src="https://github.com/user-attachments/assets/1563836e-eaa2-4e71-be6b-be4c1cd1d511" />
<br>


In body, create ‘case_soc_id’  --this is the ticket number in DFIR-IRIS
<br>

In value, put : <br>
```
{{ new Date().toISOString().replace(/[-:T.Z]/g, '').slice(0,12) }}
```
<br>

what does it do is  <br>
- new Date().toISOString() → gives you 2025-10-20T14:36:45.000Z <br>
- .replace(/[-:T.Z]/g, '') → removes dashes, colons, and time markers <br>
- .slice(0,12) → trims to YYYYMMDDHHMM <br>


Ticket must be unique so this is perfect for this. <br>
<img width="576" height="309" alt="image" src="https://github.com/user-attachments/assets/f50d9c7b-aad3-4dba-bbd2-63b14adb3447" /> <br>


Add more parameter : <br>
case_customer 1  <br>
case_name test_alert001 <br>
case_description (paste the content in input from previous node) <br>
Add option to accept again the ‘SSL insecure issue’ : <br>
<img width="1125" height="941" alt="image" src="https://github.com/user-attachments/assets/a9afa1fa-0b9b-43c3-ad02-e4c6b16ca8e6" />
<br>


Note that you can customize this depends on what you want to see in the DFIR dashboard. <br>
Try it by clicking ‘Execute step’ check also the dashboard of DFIR-IRIS to confirm. <br>
<img width="767" height="659" alt="image" src="https://github.com/user-attachments/assets/68362764-bb1d-4678-ada7-8b3bacd29d2b" /> 
<br>


<img width="1125" height="311" alt="image" src="https://github.com/user-attachments/assets/11087066-b603-4d27-a7c4-cb2ac628a289" />
<br>


## **Airtable Setup**
<br>


 Add ‘code in javascript’ node <br>
<img width="398" height="306" alt="image" src="https://github.com/user-attachments/assets/dab7f2cc-3da8-4c3b-a08a-79818300ae42" /> <br>

Paste : <br>

```
// Robust, tolerant parser for unpredictable DFIR-IRIS case_description
const caseId = $json.data?.case_soc_id || null;
const desc = $json.data?.case_description || $json.case_description || "";

if (!desc) return { error: "Missing case_description" };

// Normalize and prepare lines
const raw = desc;
const norm = raw.replace(/\r/g, "");
const lines = norm.split("\n").map(l => l.trim()).filter(l => l);

// Helpers
function findFirstIPv4(s) {
  const m = s.match(/\b(?:25[0-5]|2[0-4]\d|1?\d{1,2})(?:\.(?:25[0-5]|2[0-4]\d|1?\d{1,2})){3}\b/);
  return m ? m[0] : null;
}
function quotedOrAfterLabel(line, labels) {
  // returns quoted value or value after any label in labels array
  const q = line.match(/["'](.+?)["']/);
  if (q) return q[1].trim();
  for (const lab of labels) {
    const re = new RegExp(lab + '\\s*[:\\-]?\\s*(.+)$', 'i');
    const m = line.match(re);
    if (m && m[1]) return m[1].replace(/^[:"'\s]+|[."'\s]+$/g, '').trim();
  }
  return null;
}
function clean(val) {
  if (!val) return null;
  return String(val).replace(/^[\s"']+|[\s"'.,:;]+$/g, '').trim();
}
function isLikelyHost(v) {
  if (!v) return false;
  if (/\b(ip|36\.97|192\.168|10\.)/i.test(v)) return false;
  return v.length >= 3 && v.length < 64;
}
function isLikelyUser(v) {
  if (!v) return false;
  return /^[\w\-.@]{2,64}$/.test(v);
}

// Collect candidate values (don't assign immediately)
const candidates = {
  title: [],
  host: [],
  user: [],
  source_ips: [],
  isp: [],
  abuse_scores: [],
  mitre_codes: [],
  mitre_texts: [],
  severity: []
};

// line-level passes: precise labels and loose context
for (const line of lines) {
  const lower = line.toLowerCase();

  // Title candidates
  if (/alert name\b|alert titled\b|the alert\b|^-\s*alert name\b|^alert\b/i.test(line)) {
    const t = quotedOrAfterLabel(line, ['alert name', 'alert titled', 'the alert', 'alert']);
    if (t) candidates.title.push(clean(t));
  }

  // Host candidates (various labels)
  if (/\b(system|computer|host|target host|affected host|local machine|destination)\b/i.test(line)) {
    const h = quotedOrAfterLabel(line, ['system named', 'computer named', 'computer', 'system', 'local machine', 'target host', 'affected host', 'destination', 'affected system']);
    if (h) candidates.host.push(clean(h));
  }

  // User candidates
  if (/\b(user|affected user|target user)\b/i.test(line)) {
    const u = quotedOrAfterLabel(line, ['user', 'affected user', 'target user', 'running user']);
    if (u) candidates.user.push(clean(u.replace(/^user\s+/i, '')));
  }

  // IPs: collect any IPv4s on the line
  const ips = [...(line.matchAll(/\b(?:25[0-5]|2[0-4]\d|1?\d{1,2})(?:\.(?:25[0-5]|2[0-4]\d|1?\d{1,2})){3}\b/g))].map(m=>m[0]);
  for (const ip of ips) candidates.source_ips.push(ip);

  // ISP candidates
  if (/\bISP\b|associated with|provider|network/i.test(line)) {
    const ispVal = quotedOrAfterLabel(line, ['isp', 'associated with', 'associated to', 'provider', 'network']);
    if (ispVal) candidates.isp.push(clean(ispVal));
  }

  // Abuse score
  if (/abuse confidence score|abuse score|confidence score/i.test(line)) {
    const m = line.match(/(\d{1,3})/);
    if (m) candidates.abuse_scores.push(m[1]);
  }

  // MITRE codes and descriptions
  if (/T\d{4}/i.test(line)) {
    const codes = [...line.matchAll(/T\d{4}/g)].map(m=>m[0]);
    for (const c of codes) candidates.mitre_codes.push(c);
    // also capture surrounding text as possible tactic description
    const before = line.replace(/\s+/g, ' ').trim();
    candidates.mitre_texts.push(clean(before));
  } else if (/mitre/i.test(line)) {
    const t = quotedOrAfterLabel(line, ['mitre att&ck mapping', 'mitre att&ck tactic', 'mitre att&ck', 'mitre att&ck mapping:', 'mitre']);
    if (t) candidates.mitre_texts.push(clean(t));
    const code = (line.match(/T\d{4}/i) || [null])[0];
    if (code) candidates.mitre_codes.push(code);
  }

  // Severity
  if (/\bseverity\b/i.test(line)) {
    const m = line.match(/\b(Medium|High|Low|Critical)\b/i);
    if (m) candidates.severity.push(m[1]);
  }
}

// Deduplicate helpers
function pickFirstUnique(arr) {
  const seen = new Set();
  for (const v of arr) {
    if (!v) continue;
    const c = String(v).toLowerCase();
    if (!seen.has(c)) { seen.add(c); return v; }
  }
  return null;
}
function pickBestHost(arr) {
  for (const v of arr) {
    if (isLikelyHost(v)) return v;
  }
  return pickFirstUnique(arr);
}
function pickBestUser(arr) {
  for (const v of arr) if (isLikelyUser(v)) return v;
  return pickFirstUnique(arr);
}

// Final selection with validation and fallbacks
let title = pickFirstUnique(candidates.title) || null;
let destination_host = pickBestHost(candidates.host) || null;
let user = pickBestUser(candidates.user) || null;

// IP selection: prefer public IP over private when both present
let source_ip = null;
if (candidates.source_ips.length) {
  // prioritize public (not RFC1918)
  const publics = candidates.source_ips.filter(ip => !/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1]))/.test(ip));
  source_ip = publics.length ? publics[0] : candidates.source_ips[0];
}

// ISP: pick non-trivial candidate containing letters and not equal to user/title
let isp = null;
for (const v of candidates.isp) {
  if (!v) continue;
  const low = v.toLowerCase();
  if (low.includes('ip') || low.length < 3) continue;
  isp = v; break;
}

// Abuse score
const abuse_score = pickFirstUnique(candidates.abuse_scores) || null;

// MITRE: prefer codes first, then text
let mitre_technique = null;
let mitre_tactic = null;
if (candidates.mitre_codes.length) {
  mitre_technique = pickFirstUnique(candidates.mitre_codes);
  // try to derive tactic from mitre_texts containing keywords
  for (const t of candidates.mitre_texts) {
    if (!t) continue;
    if (/initial access|credential access|ta0001|ta0006/i.test(t)) {
      mitre_tactic = t; break;
    }
  }
}
if (!mitre_tactic && candidates.mitre_texts.length) mitre_tactic = pickFirstUnique(candidates.mitre_texts);

// Severity
let severity = pickFirstUnique(candidates.severity) || null;

// Safety: avoid accidental assignment of the same value to multiple fields (title leaking)
function distinctAssign(primary, ...others) {
  if (!primary) return primary;
  for (const o of others) {
    if (!o) continue;
    if (String(primary).toLowerCase() === String(o).toLowerCase()) return null;
  }
  return primary;
}
title = distinctAssign(title, destination_host, user, isp) || title;
destination_host = distinctAssign(destination_host, title, user, isp) || destination_host;
user = distinctAssign(user, title, destination_host, isp) || user;

// Final clean
const out = {
  case_soc_id: caseId,
  title: clean(title),
  destination_host: clean(destination_host),
  user: clean(user),
  source_ip: clean(source_ip),
  isp: clean(isp),
  abuse_score: clean(abuse_score),
  mitre_tactic: clean(mitre_tactic),
  mitre_technique: clean(mitre_technique),
  severity: clean(severity),
  description: raw
};

return out;

```
<br>


<img width="1125" height="571" alt="image" src="https://github.com/user-attachments/assets/1de2dbd8-1edb-4fd5-8bec-4249debd36c5" />
<br>


The purpose of this is to extract the key parameters in ‘case_description’ that I will be using in the airtable. in real-job simulation, <br>
this will be used for weekly/monthly report. It will be categorized so it can be filtered easily. <br>


Prepare the sheet that will be use for documentation in airtable (https://airtable.com/). <br>
Create account or login. Create a simple database :  <br>
<img width="1125" height="152" alt="image" src="https://github.com/user-attachments/assets/2305cfee-f185-4b44-ac3f-07f7451c8b39" />
<br>


Click the ‘account’ at the bottom left, select ‘builder hub’  <br>
<img width="392" height="545" alt="image" src="https://github.com/user-attachments/assets/df848a8c-b592-4a26-8db7-aa0ac27846b1" />
<br>


Create a Personal Access Token with scopes: <br> 
-	data.records:read <br> 
-	data.records:write <br>
<img width="1125" height="139" alt="image" src="https://github.com/user-attachments/assets/ae3281a1-b2f1-494d-aef6-4dd8aff87b5a" />
<br>


Back to n8n, create a credential for airtable, select ‘Airtable Personal Access Token API : <br>
<img width="444" height="241" alt="image" src="https://github.com/user-attachments/assets/f62e70a7-8381-4995-ab25-a9f4c99f0b2e" /> <br>


Paste the Token ID from airtable to n8n airtable API then save it. <br>
Add new airtable node(create a record) next to ‘code in javascript’ node. <br>
Drag each parameter for each field. Then try to execute. <br>
<img width="1125" height="975" alt="image" src="https://github.com/user-attachments/assets/b6c130cc-ad44-46e4-8819-15dbd5ec128d" />
<br>


The javascript node is not perfect and need more refining atleast it provided the important part that can be used for filtering) <br>
Check also the result in DFIR-IRIS and airtable :  <br>


<img width="1125" height="170" alt="image" src="https://github.com/user-attachments/assets/b88f33bb-9e9c-4dde-ba27-8ef03a164e14" /> <br>



<img width="1125" height="321" alt="image" src="https://github.com/user-attachments/assets/d5d098de-c4bd-4518-b198-15cf047d842a" />



## **Atomic Red Team Setup**
<br>


First, open powershell as administrator then type : <br>
``` Set-ExecutionPolicy Bypass CurrentUser ``` <br>
then press ‘y’
<br>
<img width="1125" height="201" alt="image" src="https://github.com/user-attachments/assets/5984e756-3bc0-409e-bb6a-767e4d4d1cf9" />
<br>


Go to windows Security then ‘Add or remove exclusions’ then add the Drive C. <br>
We need to do this because Windows Security will automatically block the AtomicRedTeam. <br>
<img width="483" height="361" alt="image" src="https://github.com/user-attachments/assets/b2ae0f0e-3c73-4c10-ba77-07c0562c5d89" />
<br>


Type this on the powershell : <br>
``` IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing); ```
<br>
``` Install-AtomicRedTeam -getAtomics ```
<br>
<img width="1125" height="189" alt="image" src="https://github.com/user-attachments/assets/be032dcc-fa70-44bb-9b5f-47795f983e17" />
<br>



Once the installation is done, head into C:\AtomicRedTeam\atomics  <br>
You’ll see a bunch of technique ID aligned to MITRE ATT&CK framework.  <br>
You can check all of this in https://attack.mitre.org/ <br> 
<img width="1125" height="726" alt="image" src="https://github.com/user-attachments/assets/14b9310c-a058-4200-95c1-cc31f0e568f5" />
<br>


Let’s try Atomic Red Team T1070 – Indicator Removal on Host (Clear Logs) <br>
It will generates Event ID 1102 (audit log cleared) in the Security log. Very high‑value detection. <br>


Open Windows Powershell as Administrator. <br>
Import the Atomic Red Team module if not already loaded: <br>
``` Import-Module C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1 ``` <br>


Run the PowerShell atomic: <br>
``` Invoke-AtomicTest T1070.001 -TestNumbers 1 ``` <br>
<img width="1125" height="160" alt="image" src="https://github.com/user-attachments/assets/08ecffe6-7bdd-4852-9919-f929cbe4d152" /> <br>


Back to splunk. Look for EventCode 104 : <br>
<img width="1125" height="676" alt="image" src="https://github.com/user-attachments/assets/92d37c89-3228-4dfb-b301-c5caa6fdd40f" />
<br>


```
index=project-elias EventCode=104
| stats count min(_time) as firstTime max(_time) as lastTime by ComputerName, User, EventCode, Message

``` 
<br>
<img width="1125" height="257" alt="image" src="https://github.com/user-attachments/assets/1a23b51b-b891-4077-a4ba-ab37cd3704a7" />
<br>


Click ‘Save as’ > ‘Alert’ in upper right : <br>
<img width="822" height="514" alt="image" src="https://github.com/user-attachments/assets/9b074322-f830-4bce-b7a3-6321481d3ae0" />
<br>


Same process with the previous webhook. Copy the ‘POST’ URL of webhook node in N8n then paste it to Splunk <br>
<img width="1125" height="1412" alt="image" src="https://github.com/user-attachments/assets/a1f56d69-32e7-4aa6-8a7c-64df3eb0c3f9" />
<br>
Listen for test event and wait for 1-3mins.
<br>
<img width="1125" height="1228" alt="image" src="https://github.com/user-attachments/assets/af1b0c7a-586e-4064-8f38-da6208ec89f4" />
<br>
<img width="1125" height="1044" alt="image" src="https://github.com/user-attachments/assets/32bfa592-8407-4502-8731-8438a3e302bf" />
<br>
Pin the output and connect it to the rest of node. Then execute the whole workflow. <br>



<img width="1125" height="580" alt="image" src="https://github.com/user-attachments/assets/744b66bd-66f1-40e9-bedd-d56b46d8abab" />
<br>
<img width="1125" height="714" alt="image" src="https://github.com/user-attachments/assets/59ce48c1-8483-420f-8edd-5e964ac4e944" />
<br>
<img width="1125" height="202" alt="image" src="https://github.com/user-attachments/assets/51c5ed5e-158a-4c27-9c70-d8d6e4f37a68" />


















































































