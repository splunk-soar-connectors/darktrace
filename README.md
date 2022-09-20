[comment]: # "Auto-generated SOAR connector documentation"
# Darktrace

Publisher: Darktrace  
Connector Version: 1\.0\.5  
Product Vendor: Darktrace  
Product Name: Darktrace  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.3\.0  

This app integrates with Darktrace to perform investigative and containment actions

[comment]: # " File: README.md"
[comment]: # "  Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "  you may not use this file except in compliance with the License."
[comment]: # "  You may obtain a copy of the License at"
[comment]: # "      http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # "  Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "  the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "  either express or implied. See the License for the specific language governing permissions"
[comment]: # "  and limitations under the License."
[comment]: # ""
The Darktrace app for Splunk Phantom allows users to enrich investigations and workflows with
insights from the Darktrace Threat Visualizer. The integration enables users to ingest Darktrace
model breaches and Cyber AI Analyst incidents as the basis for an investigation. Actions can be
triggered manually or automatically via existing playbooks to acquire additional Darktrace
information. These actions include gathering device summaries, connection details and comments
existing within Darktrace. Additionally, acknowledgments and comments can be sent to Darktrace for
optimized security workflows.


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Darktrace asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**base\_url** |  required  | string | IP address of the Darktrace Master
**poll\_aia** |  optional  | boolean | Ingest Cyber AI Analyst Investigations
**poll\_mb** |  optional  | boolean | Ingest Model Breaches
**private\_token** |  required  | password | Darktrace API Private Token
**public\_token** |  required  | password | Darktrace API Public Token
**tls\_verify** |  optional  | boolean | Enable TLS Certificate Verification

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using the supplied configuration  
[get device tags](#action-get-device-tags) - Receive all of the tags that are currently applied to a device  
[get tagged devices](#action-get-tagged-devices) - Receive all of the devices that currently have a given tag  
[get breach comments](#action-get-breach-comments) - Receive all comments made on a model breach  
[on poll](#action-on-poll) - Ingests Darktrace model breaches and Cyber AI Analyst investigations  
[get device description](#action-get-device-description) - Receive device description for the specified device  
[get device modelbreaches](#action-get-device-modelbreaches) - Receive recent model breaches for the specified device  
[acknowledge breach](#action-acknowledge-breach) - Acknowledge a model breach  
[unacknowledge breach](#action-unacknowledge-breach) - Unacknowledge a model breach  
[post comment](#action-post-comment) - Post a comment to a model breach  
[post tag](#action-post-tag) - Post a tag to a device  
[get breach connections](#action-get-breach-connections) - Receive connections involved in a model breach  

## action: 'test connectivity'
Validate the asset configuration for connectivity using the supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'get device tags'
Receive all of the tags that are currently applied to a device

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device\_id** |  required  | See artifact details to get the device\_ID | numeric |  `darktrace device id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.device\_id | numeric |  `darktrace device id` 
action\_result\.data\.\*\.name | string |  `darktrace tag` 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get tagged devices'
Receive all of the devices that currently have a given tag

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**tag** |  required  | The name of an existing tag | string |  `darktrace tag` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.tag | string |  `darktrace tag` 
action\_result\.data | string | 
action\_result\.data\.\*\.entityValue | string | 
action\_result\.summary\.\*\.did | string |  `darktrace device id` 
action\_result\.summary\.\*\.hostname | string |  `host name`  `darktrace saas credential` 
action\_result\.summary\.\*\.ip | string |  `ip` 
action\_result\.summary\.\*\.label | string | 
action\_result\.summary\.\*\.mac | string |  `mac address` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get breach comments'
Receive all comments made on a model breach

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**model\_breach\_id** |  required  | See artifact details to get the model\_breach\_id | numeric |  `darktrace model breach id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.model\_breach\_id | numeric |  `darktrace model breach id` 
action\_result\.data | string | 
action\_result\.summary\.\*\.comment | string | 
action\_result\.summary\.\*\.time | string | 
action\_result\.summary\.\*\.username | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'on poll'
Ingests Darktrace model breaches and Cyber AI Analyst investigations

Type: **ingest**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**artifact\_count** |  optional  | Maximum number of artifact records to query for | numeric | 
**container\_count** |  optional  | Maximum number of container records to query for | numeric | 
**container\_id** |  optional  | Container IDs to limit the ingestion to | string | 
**end\_time** |  optional  | End of the time range, in epoch time \(milliseconds\) | numeric | 
**start\_time** |  optional  | Start of the time range, in epoch time \(milliseconds\) | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.summary | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.status | string | 
action\_result\.data | string | 
action\_result\.parameter\.container\_id | string | 
action\_result\.parameter\.start\_time | numeric | 
action\_result\.parameter\.end\_time | numeric | 
action\_result\.parameter\.container\_count | numeric | 
action\_result\.parameter\.artifact\_count | numeric |   

## action: 'get device description'
Receive device description for the specified device

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device\_id** |  required  | See artifact details to get the device\_id | numeric |  `darktrace device id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.device\_id | numeric |  `darktrace device id` 
action\_result\.data\.\*\.devices\.devicelabel | string | 
action\_result\.data\.\*\.devices\.did | numeric |  `darktrace device id` 
action\_result\.data\.\*\.devices\.hostname | string |  `host name`  `darktrace saas credential` 
action\_result\.data\.\*\.devices\.ip | string |  `ip` 
action\_result\.data\.\*\.devices\.macaddress | string |  `mac address` 
action\_result\.data\.\*\.devices\.typename | string | 
action\_result\.summary\.\*\.acknowledged | string | 
action\_result\.summary\.\*\.name | string | 
action\_result\.summary\.\*\.score | string | 
action\_result\.summary\.\*\.time | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get device modelbreaches'
Receive recent model breaches for the specified device

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device\_id** |  required  | See artifact details to get the device\_id | numeric |  `darktrace device id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.device\_id | numeric |  `darktrace device id` 
action\_result\.data\.\*\.acknowledged | string | 
action\_result\.data\.\*\.model\.then\.name | string | 
action\_result\.data\.\*\.pbid | string |  `darktrace model breach id` 
action\_result\.data\.\*\.score | string | 
action\_result\.data\.\*\.time | numeric | 
action\_result\.summary\.\*\.darktrace\_url | numeric | 
action\_result\.summary\.\*\.severity | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'acknowledge breach'
Acknowledge a model breach

Type: **correct**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**model\_breach\_id** |  required  | See artifact details to get the model\_breach\_id | numeric |  `darktrace model breach id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.model\_breach\_id | numeric |  `darktrace model breach id` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'unacknowledge breach'
Unacknowledge a model breach

Type: **correct**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**model\_breach\_id** |  required  | See artifact details to get the model\_breach\_id | numeric |  `darktrace model breach id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.model\_breach\_id | numeric |  `darktrace model breach id` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'post comment'
Post a comment to a model breach

Type: **correct**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**message** |  required  | Comment to post | string | 
**model\_breach\_id** |  required  | See artifact details to get the model\_breach\_id | numeric |  `darktrace model breach id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.message | string | 
action\_result\.parameter\.model\_breach\_id | numeric |  `darktrace model breach id` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'post tag'
Post a tag to a device

Type: **correct**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device\_id** |  required  | See artifact details to get the device\_id | numeric |  `darktrace device id` 
**duration** |  optional  | How long this tag be applied for \(seconds\)\. Ex\: enter 3600 for 1 hour\. Leave this entry empty if you do not want it to expire | numeric | 
**tag** |  required  | Choose a tag to apply to the device | string |  `darktrace tag` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.device\_id | numeric |  `darktrace device id` 
action\_result\.parameter\.duration | numeric | 
action\_result\.parameter\.tag | string |  `darktrace tag` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get breach connections'
Receive connections involved in a model breach

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**model\_breach\_id** |  required  | See artifact details to get the model\_breach\_id | string |  `darktrace model breach id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.model\_breach\_id | numeric |  `darktrace model breach id` 
action\_result\.data\.\*\.dest\_hostname | string | 
action\_result\.data\.\*\.dest\_ip | string | 
action\_result\.data\.\*\.dest\_port | numeric | 
action\_result\.data\.\*\.proto | string | 
action\_result\.data\.\*\.src\_hostname | string | 
action\_result\.data\.\*\.src\_ip | string | 
action\_result\.data\.\*\.src\_port | numeric | 
action\_result\.data\.\*\.time | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 