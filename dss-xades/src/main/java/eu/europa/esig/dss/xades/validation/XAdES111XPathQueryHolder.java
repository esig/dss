/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.XAdESNamespaces;
import eu.europa.esig.dss.xades.XPathQueryHolder;

/**
 * TODO
 *
 *
 *
 *
 *
 */
public class XAdES111XPathQueryHolder extends XPathQueryHolder {

	public XAdES111XPathQueryHolder() {
		XADES_SIGNED_PROPERTIES = "http://uri.etsi.org/01903/v1.1.1#SignedProperties";

		XPATH_CV = "/xades111:CertificateValues";
		XPATH_EX509C = "/xades111:EncapsulatedX509Certificate";
		XPATH_REV_VALUES = "/xades111:RevocationValues";
		XPATH_CRLV = "/xades111:CRLValues";
		XPATH_OCSPV = "/xades111:OCSPValues";
		XPATH_ECRLV = "/xades111:EncapsulatedCRLValue";
		XPATH_EOCSPV = "/xades111:EncapsulatedOCSPValue";
		XPATH__ECRLV = "." + XPATH_ECRLV;
		XPATH_OCSPREF = "/xades111:OCSPRef";
		XPATH__OCSPREF = "." + XPATH_OCSPREF;

		XPATH__CRL_REF = "./xades111:CRLRef";
		XPATH__COMPLETE_CERTIFICATE_REFS__CERT_DIGEST = "./xades111:CertRefs/xades111:Cert/xades111:CertDigest";
		XPATH__DAAV_DIGEST_METHOD = "./xades111:DigestAlgAndValue/ds:DigestMethod";
		XPATH__DAAV_DIGEST_VALUE = "./xades111:DigestAlgAndValue/ds:DigestValue";
		XPATH__ENCAPSULATED_TIMESTAMP = "./xades111:EncapsulatedTimeStamp";

		XPATH_CERT_REFS = XPATH_COMPLETE_CERTIFICATE_REFS + "/xades111:CertRefs";

		XPATH_QUALIFYING_PROPERTIES = XPATH_OBJECT + "/xades111:QualifyingProperties";
		XPATH__QUALIFYING_PROPERTIES = "./xades111:QualifyingProperties";
		XPATH_QUALIFYING_PROPERTIES_REFERENCE = XPATH_OBJECT + "/xades111:QualifyingPropertiesReference";

		XPATH__QUALIFYING_PROPERTIES_SIGNED_PROPERTIES = XPATH__QUALIFYING_PROPERTIES + "/xades111:SignedProperties";

		XPATH_SIGNED_PROPERTIES = XPATH_QUALIFYING_PROPERTIES + "/xades111:SignedProperties";
		XPATH_SIGNED_SIGNATURE_PROPERTIES = XPATH_SIGNED_PROPERTIES + "/xades111:SignedSignatureProperties";
		XPATH_SIGNING_TIME = XPATH_SIGNED_SIGNATURE_PROPERTIES + "/xades111:SigningTime";
		XPATH_SIGNING_CERTIFICATE_CERT = XPATH_SIGNED_SIGNATURE_PROPERTIES + "/xades111:SigningCertificate/xades111:Cert";
		XPATH_SIGNATURE_POLICY_IDENTIFIER = XPATH_SIGNED_SIGNATURE_PROPERTIES + "/xades111:SignaturePolicyIdentifier";
		XPATH__SIGNATURE_POLICY_IMPLIED = "./xades111:SignaturePolicyImplied";

		XPATH_UNSIGNED_PROPERTIES = XPATH_QUALIFYING_PROPERTIES + "/xades111:UnsignedProperties";
		XPATH_UNSIGNED_SIGNATURE_PROPERTIES = XPATH_UNSIGNED_PROPERTIES + "/xades111:UnsignedSignatureProperties";

		XPATH_ALL_DATA_OBJECTS_TIMESTAMP = XPATH_SIGNED_PROPERTIES + "/xades111:SignedDataObjectProperties/xades111:AllDataObjectsTimeStamp";

		XPATH__X509_ISSUER_NAME = "./xades111:IssuerSerial/ds:X509IssuerName";
		XPATH__X509_SERIAL_NUMBER = "./xades111:IssuerSerial/ds:X509SerialNumber";
		XPATH__CERT_DIGEST = "./xades111:CertDigest";
		XPATH__DIGEST_METHOD = "./xades111:DigestMethod";
		XPATH__CERT_DIGEST_DIGEST_METHOD = XPATH__CERT_DIGEST + "/xades111:DigestMethod";
		XPATH__DIGEST_VALUE = "./xades111:DigestValue";
		XPATH__CERT_DIGEST_DIGEST_VALUE = XPATH__CERT_DIGEST + "/xades111:DigestValue";

		XPATH_SIGNATURE_TIMESTAMP = XPATH_UNSIGNED_SIGNATURE_PROPERTIES + "/xades111:" + XMLE_SIGNATURE_TIME_STAMP;
		XPATH_COMPLETE_CERTIFICATE_REFS = XPATH_UNSIGNED_SIGNATURE_PROPERTIES + "/xades111:CompleteCertificateRefs";
		XPATH_COMPLETE_REVOCATION_REFS = XPATH_UNSIGNED_SIGNATURE_PROPERTIES + "/xades111:CompleteRevocationRefs";
		XPATH_OCSP_REFS = XPATH_COMPLETE_REVOCATION_REFS + "/xades111:OCSPRefs";
		XPATH_SIG_AND_REFS_TIMESTAMP = XPATH_UNSIGNED_SIGNATURE_PROPERTIES + "/xades111:" + XMLE_SIG_AND_REFS_TIME_STAMP;
		XPATH_SIG_AND_REFS_TIMESTAMP_V2 = XPATH_UNSIGNED_SIGNATURE_PROPERTIES + "/xades111:" + XMLE_SIG_AND_REFS_TIME_STAMP_V2;
		XPATH_CERTIFICATE_VALUES = XPATH_UNSIGNED_SIGNATURE_PROPERTIES + XPATH_CV;
		XPATH_REVOCATION_VALUES = XPATH_UNSIGNED_SIGNATURE_PROPERTIES + XPATH_REV_VALUES;
		XPATH_TIME_STAMP_VALIDATION_DATA = XPATH_UNSIGNED_SIGNATURE_PROPERTIES + "/xades141:TimeStampValidationData";
		XPATH_COUNTER_SIGNATURE = XPATH_UNSIGNED_SIGNATURE_PROPERTIES + "/xades111:CounterSignature";
		XPATH_ARCHIVE_TIMESTAMP = XPATH_UNSIGNED_SIGNATURE_PROPERTIES + "/xades111:" + XMLE_ARCHIVE_TIME_STAMP;
		XPATH_ARCHIVE_TIMESTAMP_141 = XPATH_UNSIGNED_SIGNATURE_PROPERTIES + "/xades141:" + XMLE_ARCHIVE_TIME_STAMP;
		XPATH_REVOCATION_CRL_REFS = XPATH_COMPLETE_REVOCATION_REFS + "/xades111:CRLRefs";

		XPATH_ENCAPSULATED_X509_CERTIFICATE = XPATH_CERTIFICATE_VALUES + XPATH_EX509C;
		XPATH_TSVD_ENCAPSULATED_X509_CERTIFICATE = XPATH_TIME_STAMP_VALIDATION_DATA + XPATH_CV + XPATH_EX509C;

		XPATH_TSVD_ENCAPSULATED_CRL_VALUES = XPATH_TIME_STAMP_VALIDATION_DATA + XPATH_REV_VALUES + XPATH_CRLV + XPATH_ECRLV;
		XPATH_TSVD_ENCAPSULATED_OCSP_VALUE = XPATH_TIME_STAMP_VALIDATION_DATA + XPATH_REV_VALUES + XPATH_OCSPV + XPATH_EOCSPV;

		XPATH_ENCAPSULATED_CRL_VALUES = XPATH_REVOCATION_VALUES + XPATH_CRLV;
		XPATH_ENCAPSULATED_OCSP_VALUES = XPATH_REVOCATION_VALUES + XPATH_OCSPV;

		XPATH_CRL_VALUES_ENCAPSULATED_CRL = XPATH_ENCAPSULATED_CRL_VALUES + XPATH_ECRLV;
		XPATH_OCSP_VALUES_ENCAPSULATED_OCSP = XPATH_ENCAPSULATED_OCSP_VALUES + XPATH_EOCSPV;

		// For qualifying properties reference
		XPATH___UNSIGNED_PROPERTIES = "./xades111:UnsignedProperties";
		XPATH___UNSIGNED_SIGNATURE_PROPERTIES = XPATH___UNSIGNED_PROPERTIES + "/xades111:UnsignedSignatureProperties";
	}

	@Override
	public boolean canUseThisXPathQueryHolder(final String namespace) {
		return XAdESNamespaces.XAdES111.equals(namespace);
	}
}
