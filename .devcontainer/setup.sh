#!/bin/bash

cd /workspaces/hyperlight

# Change group ownership for the $DEVICE so that the user can access it
# NOTE: The $USER has been added to $DEVICE_GROUP during container build time
sudo chown -R ":$DEVICE_GROUP" $DEVICE

