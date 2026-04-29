#!/bin/bash
# PII patterns inside a shell script

# Real email (P1)
EMAIL="charlie@acme-industries.com"

# Internal host (P5)
curl https://db-primary.intranet/healthz

# Private IPv4 (P4)
ssh user@192.168.50.7

# Public DNS — no finding
nslookup example.com 1.1.1.1
