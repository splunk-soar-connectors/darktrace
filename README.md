# Darktrace

Publisher: Darktrace \
Connector Version: 1.0.8 \
Product Vendor: Darktrace \
Product Name: Darktrace \
Minimum Product Version: 5.3.0

This app integrates with Darktrace to perform investigative and containment actions

The Darktrace app for Splunk Phantom allows users to enrich investigations and workflows with
insights from the Darktrace Threat Visualizer. The integration enables users to ingest Darktrace
model breaches and Cyber AI Analyst incidents as the basis for an investigation. Actions can be
triggered manually or automatically via existing playbooks to acquire additional Darktrace
information. These actions include gathering device summaries, connection details and comments
existing within Darktrace. Additionally, acknowledgments and comments can be sent to Darktrace for
optimized security workflows.

### Configuration variables

This table lists the configuration variables required to operate Darktrace. These variables are specified when configuring a Darktrace asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**base_url** | required | string | IP address of the Darktrace Master |
**poll_aia** | optional | boolean | Ingest Cyber AI Analyst Investigations |
**poll_mb** | optional | boolean | Ingest Model Breaches |
**private_token** | required | password | Darktrace API Private Token |
**public_token** | required | password | Darktrace API Public Token |
**tls_verify** | optional | boolean | Enable TLS Certificate Verification |

### Supported Actions

[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using the supplied configuration \
[get device tags](#action-get-device-tags) - Receive all of the tags that are currently applied to a device \
[get tagged devices](#action-get-tagged-devices) - Receive all of the devices that currently have a given tag \
[get breach comments](#action-get-breach-comments) - Receive all comments made on a model breach \
[on poll](#action-on-poll) - Ingests Darktrace model breaches and Cyber AI Analyst investigations \
[get device description](#action-get-device-description) - Receive device description for the specified device \
[get device modelbreaches](#action-get-device-modelbreaches) - Receive recent model breaches for the specified device \
[acknowledge breach](#action-acknowledge-breach) - Acknowledge a model breach \
[unacknowledge breach](#action-unacknowledge-breach) - Unacknowledge a model breach \
[post comment](#action-post-comment) - Post a comment to a model breach \
[post tag](#action-post-tag) - Post a tag to a device \
[get breach connections](#action-get-breach-connections) - Receive connections involved in a model breach

## action: 'test connectivity'

Validate the asset configuration for connectivity using the supplied configuration

Type: **test** \
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

No Output

## action: 'get device tags'

Receive all of the tags that are currently applied to a device

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device_id** | required | See artifact details to get the device_ID | numeric | `darktrace device id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.device_id | numeric | `darktrace device id` | 1234 |
action_result.data.\*.name | string | `darktrace tag` | Admin |
action_result.summary | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get tagged devices'

Receive all of the devices that currently have a given tag

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**tag** | required | The name of an existing tag | string | `darktrace tag` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.tag | string | `darktrace tag` | Admin |
action_result.data | string | | |
action_result.data.\*.entityValue | string | | |
action_result.summary.\*.did | string | `darktrace device id` | 1234 |
action_result.summary.\*.hostname | string | `host name` `darktrace saas credential` | |
action_result.summary.\*.ip | string | `ip` | 1.2.3.4 |
action_result.summary.\*.label | string | | |
action_result.summary.\*.mac | string | `mac address` | AA:BB:CC:DD:EE:FF |
action_result.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get breach comments'

Receive all comments made on a model breach

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**model_breach_id** | required | See artifact details to get the model_breach_id | numeric | `darktrace model breach id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.model_breach_id | numeric | `darktrace model breach id` | 12345 |
action_result.data | string | | |
action_result.summary.\*.comment | string | | |
action_result.summary.\*.time | string | | |
action_result.summary.\*.username | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'on poll'

Ingests Darktrace model breaches and Cyber AI Analyst investigations

Type: **ingest** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**artifact_count** | optional | Maximum number of artifact records to query for | numeric | |
**container_count** | optional | Maximum number of container records to query for | numeric | |
**container_id** | optional | Container IDs to limit the ingestion to | string | |
**end_time** | optional | End of the time range, in epoch time (milliseconds) | numeric | |
**start_time** | optional | Start of the time range, in epoch time (milliseconds) | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.summary | string | | |
action_result.status | string | | success failed |
action_result.message | string | | |
action_result.status | string | | success failed |
action_result.data | string | | |
action_result.parameter.container_id | string | | |
action_result.parameter.start_time | numeric | | |
action_result.parameter.end_time | numeric | | |
action_result.parameter.container_count | numeric | | |
action_result.parameter.artifact_count | numeric | | |

## action: 'get device description'

Receive device description for the specified device

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device_id** | required | See artifact details to get the device_id | numeric | `darktrace device id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.device_id | numeric | `darktrace device id` | 1234 |
action_result.data.\*.devices.devicelabel | string | | |
action_result.data.\*.devices.did | numeric | `darktrace device id` | 1234 |
action_result.data.\*.devices.hostname | string | `host name` `darktrace saas credential` | |
action_result.data.\*.devices.ip | string | `ip` | 1.2.3.4 |
action_result.data.\*.devices.macaddress | string | `mac address` | AA:BB:CC:DD:EE:FF |
action_result.data.\*.devices.typename | string | | Desktop |
action_result.summary.\*.acknowledged | string | | |
action_result.summary.\*.name | string | | |
action_result.summary.\*.score | string | | |
action_result.summary.\*.time | numeric | | |
action_result.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get device modelbreaches'

Receive recent model breaches for the specified device

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device_id** | required | See artifact details to get the device_id | numeric | `darktrace device id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.device_id | numeric | `darktrace device id` | 1234 |
action_result.data.\*.acknowledged | string | | |
action_result.data.\*.model.then.name | string | | |
action_result.data.\*.pbid | string | `darktrace model breach id` | 12345 |
action_result.data.\*.score | string | | |
action_result.data.\*.time | numeric | | |
action_result.summary.\*.darktrace_url | numeric | | |
action_result.summary.\*.severity | numeric | | |
action_result.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'acknowledge breach'

Acknowledge a model breach

Type: **correct** \
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**model_breach_id** | required | See artifact details to get the model_breach_id | numeric | `darktrace model breach id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.model_breach_id | numeric | `darktrace model breach id` | 12345 |
action_result.data | string | | |
action_result.summary | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'unacknowledge breach'

Unacknowledge a model breach

Type: **correct** \
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**model_breach_id** | required | See artifact details to get the model_breach_id | numeric | `darktrace model breach id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.model_breach_id | numeric | `darktrace model breach id` | 12345 |
action_result.data | string | | |
action_result.summary | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'post comment'

Post a comment to a model breach

Type: **correct** \
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**message** | required | Comment to post | string | |
**model_breach_id** | required | See artifact details to get the model_breach_id | numeric | `darktrace model breach id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.message | string | | |
action_result.parameter.model_breach_id | numeric | `darktrace model breach id` | 12345 |
action_result.data | string | | |
action_result.summary | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'post tag'

Post a tag to a device

Type: **correct** \
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device_id** | required | See artifact details to get the device_id | numeric | `darktrace device id` |
**duration** | optional | How long this tag be applied for (seconds). Ex: enter 3600 for 1 hour. Leave this entry empty if you do not want it to expire | numeric | |
**tag** | required | Choose a tag to apply to the device | string | `darktrace tag` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.device_id | numeric | `darktrace device id` | 1234 |
action_result.parameter.duration | numeric | | |
action_result.parameter.tag | string | `darktrace tag` | Admin |
action_result.data | string | | |
action_result.summary | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'get breach connections'

Receive connections involved in a model breach

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**model_breach_id** | required | See artifact details to get the model_breach_id | string | `darktrace model breach id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.model_breach_id | numeric | `darktrace model breach id` | 12345 |
action_result.data.\*.dest_hostname | string | | |
action_result.data.\*.dest_ip | string | | |
action_result.data.\*.dest_port | numeric | | |
action_result.data.\*.proto | string | | |
action_result.data.\*.src_hostname | string | | |
action_result.data.\*.src_ip | string | | |
action_result.data.\*.src_port | numeric | | |
action_result.data.\*.time | string | | |
action_result.summary | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2025 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
