# TFTP server with HTTP push

I am storing Cisco hardware configuration in git repository. IOS 15.x and IOS XE have a capability to upload configuration to HTTP endpoint automatically, but IOS 12.x or older and ASA have not.

Telepresense software can also use HttpFeedback to make POST in their own format.

This TFTP server act as a regular TFTP server, but also upload certain files to HTTP endpoint. Files to upload are chosen by regex.

This software is vibecoded mostly.

## Main function

* Downloading files from TFTP server
* Uploading files to TFTP server
* If file matches the mask it will not be stored but uploaded to a HTTP endpoint

## Features

* Client block choice
* Block cound reuse
* Big files upload/download
