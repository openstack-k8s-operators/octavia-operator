# Octavia Operator Test Setup Automation
This folder contains an Ansible role for setting up an environment for
developing Octavia Operator.

## Variables and Secrets

See `install_yamls_setup/roles/podified_cp/defaults/main.yaml` for variables
and their default values. In addition to that these variables need to be
defined:

    openshift_pull_secret: '<pull secret from https://console.redhat.com/openshift/create/local >'
    podman_dockerio_user: <user>
    podman_dockerio_password: <password>
    podman_quayio_user: <user>
    podman_quayio_password: <password>

The recommended way to manage those secrets is using `ansible-vault`. Pay
attention that `openshift_pull_secret` is put in quotes so that the
JSON structure is stored as a string.

## Playbook

The `playbook.yaml` file can be used for running the role. Create an inventory
file (e.g. named `hosts`) to define the host(s). Then run the playbook like so:

    ansible-playbook -i hosts -D playbook.yaml

When using `ansible-vault` for storing secrets, additional vault specific
arguments will need to be provided. When an encrypted variable file is used add
the `-e @<filename>` argument.
