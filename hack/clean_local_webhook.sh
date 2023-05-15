#!/bin/bash
set -ex

oc delete validatingwebhookconfiguration/voctavia.kb.io --ignore-not-found
oc delete mutatingwebhookconfiguration/moctavia.kb.io --ignore-not-found
