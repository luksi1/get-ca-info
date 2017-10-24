#!/usr/bin/env python3

import urllib.request
from collections import defaultdict
import csv
import io
import re

class CertificateAuthorities():

  def __init__(self, ca_type, relative_path ):
    self.roots_url = 'https://ccadb-public.secure.force.com/mozilla/IncludedCACertificateReportPEMCSV'
    self.intermediates_url = 'https://ccadb-public.secure.force.com/mozilla/PublicAllIntermediateCertsWithPEMCSV'

    self.url = None

    self.ca_type = ca_type
    self.relative_path = relative_path

    self.root_columns = [
      "owner",
      "certificate_issuer_organization",
      "certificate_issuer_organizational_unit",
      "common_name_or_certificate_name",
      "certificate_serial_number", 
      "sha_256_fingerprint", 
      "certificate_id", "valid_from_gmt", 
      "valid_to_gmt", 
      "public_key_algorithm", 
      "signature_hash_algorithm", 
      "trust_bits", 
      "ev_policy_oid", 
      "approval_bug", 
      "nss_release_when_first_included", 
      "firefox_release_when_first_included", 
      "test_website_valid", 
      "mozilla_applied_constraints", 
      "company_website", 
      "geographic_focus", 
      "certificate_policy", 
      "certification_practice_statement", 
      "standard_audit", 
      "br_audit", 
      "ev_audit", 
      "auditor", 
      "standard_audit_type", 
      "standard_audit_statement_dt", 
      "pem_info"
    ] 

    self.intermediate_columns = [
      "ca_owner", #CA Owner
      "parent_name", #Parent Name
      "certificate_name", # Certificate Name
      "certificate_issuer_common_name", # Certificate Issuer Common Name
      "certificate_issuer_organization", # Certificate Issuer Organization
      "certificate_subject_common_name", # Certificate Subject Common Name
      "certificate_subject_organization", # Certificate Subject Organization
      "certificate_serial_number", # Certificate Serial Number
      "sha_256_fingerprint", # SHA-256 Fingerprint
      "certificate_id", # Certificate ID
      "valid_from_gmt", # Valid From [GMT]
      "valid_to_gmt", # Valid To [GMT]
      "public_key_algorithm", # Public Key Algorithm
      "signature_hash_algorithm", # Signature Hash Algorithm
      "extended_key_usage", # Extended Key Usage
      "cp_cps_same_as_parent", # CP/CPS Same As Parent
      "certificate_policy", # Certificate Policy (CP)
      "certification_practice_statement", # Certification Practice Statement (CPS)
      "audits_same_as_parent", # Audits Same As Parent
      "standard_audit", # Standard Audit
      "br_audit", # BR Audit
      "auditor", # Auditor
      "standard_audit_statement_dt", # Standard Audit Statement Dt
      "management_assertions_by", # Management Assertions By
      "comments", # Comments
      "pem_info" # PEM Info
   ]

  def __get_result_dictionary(self):
    result = defaultdict(list)

    if self.ca_type == "root":
      self.url = self.roots_url
      self.columns = self.root_columns
      self.cn_field = "common_name_or_certificate_name"
    elif self.ca_type == "intermediate":
      self.url = self.intermediates_url
      self.columns = self.intermediate_columns
      self.cn_field = "certificate_name"
    else:
      sys.exit('ca_type must be "root" or "intermediate". Your value is: "' + ca_type + '"')

    csv_file = urllib.request.urlopen(self.url)
    datareader = csv.reader(io.TextIOWrapper(csv_file))
    i=0

    for row in datareader:
      # skip the first row, as these are simply the headers
      i += 1
      if i == 1:
        continue

      for idx, column in enumerate(self.columns):
        result[column].append(row[idx])

    return result


  def find_by_common_name(self, common_name):

    result = self.__get_result_dictionary()

    space = re.compile(r"\s+")
    hyphen = re.compile(r"-")
    slash = re.compile(r"/")
    quote = re.compile(r"'")
    non_letter_number = re.compile(r"[^a-zA-Z0-9_]")

    for idx, cn in enumerate(result[self.cn_field]):
      regex = '^.*' + common_name + '.*$'

      match = re.search(regex, cn, re.IGNORECASE)

      if not match:
        continue

      # remove all hyphens from the common names
      c = hyphen.sub("", cn)

      # replace all white continuous space with a underscore
      c = space.sub("_", c)
      c = slash.sub("_", c)
      c = non_letter_number.sub("", c).lower()

      fh = open(c + '.p12', 'w')
      fh.write(quote.sub("", result["pem_info"][idx]))
      fh.write("\n")
      fh.close()


  def find_by_issuer(self, issuer):

    for idx, cn in enumerate(result['certificate_issuer_common_name']):
      regex = '^' + issuer + '$'

      match = re.search(regex, cn, re.IGNORECASE)

      if not match:
        continue

      # remove all hyphens from the common names
      resource_type = hyphen.sub("", cn)

      # replace all white continuous space with a underscore
      resource_type = space.sub("_", resource_type)
      resource_type = slash.sub("_", resource_type)
      resource_type = non_letter_number.sub("", resource_type).lower()

      fh = open(resource_type + 'p12', 'w')
      fh.write(result["pem_info"][idx])
      fh.close()

