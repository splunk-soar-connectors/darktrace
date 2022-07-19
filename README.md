**Darktrace App for Splunk SOAR**

The Darktrace App for Splunk SOAR allows users to enrich investigations and workflows with insights from the Darktrace Threat Visualizer. The integration enables users to ingest Darktrace model breaches and Cyber AI Analyst incidents as the basis for an investigation. Actions can be triggered manually or automatically via existing playbooks to acquire additional Darktrace information. These actions include gathering device summaries, connection details and comments existing within Darktrace. Additionally, acknowledgments and comments can be sent to Darktrace for optimized security workflows.

**Actions**

- test connectivity - Validate the asset configuration for connectivity using supplied configuration
- on poll - Ingests model breaches and AI Analyst investigations
- get breach comments - Receive all comments made on a model breach
- get breach connections - Receive connections involved in a model breach
- get device summary - Receive device summary for a specified device
- get tagged devices - Receive all of the devices that currently have a given tag
- get device tags - Receive all of the tags that are currently applied to a device
- acknowledge breach - Acknowledge a model breach
- post tag - Post a tag to a device
- post comment - Post a comment to a model breach

**Configuration**

The Darktrace App can be enabled in the Apps menu of the user interface for Splunk SOAR. In the Apps menu, search "Darktrace" and select "Configure New Asset" under the Darktrace App. The following fields are required to configure the new asset:

- Domain or IP address of the Darktrace Master
- Darktrace API Public token
- Darktrace API Private token
- Ingest Cyber AI Analyst Investigations (Boolean)
- Ingest Model Breaches (Boolean)
- Enable TLS Certificate Verification (Boolean)
