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
package eu.europa.esig.dss;

import java.io.Serializable;

/**
 * This class hold all XPath queries schema-dependent. It was created to cope with old signatures bases on http://uri.etsi.org/01903/v1.1.1.
 *
 *
 *
 *
 *
 */
public class XPathQueryHolder implements Serializable {

	public static final String XMLE_SIGNATURE = "Signature";
	public static final String XMLE_ALGORITHM = "Algorithm";

	public static final String XMLE_KEYINFO = "KeyInfo";
	public static final String XMLE_X509DATA = "X509Data";
	public static final String XMLE_X509CERTIFICATE = "X509Certificate";

	public static final String XMLE_TRANSFORM = "Transform";
	public static final String XMLE_CITY = "City";
	public static final String XMLE_STATE_OR_PROVINCE = "StateOrProvince";

	public static final String XMLE_POSTAL_CODE = "PostalCode";
	public static final String XMLE_COUNTRY_NAME = "CountryName";
	public static final String XMLE_QUALIFYING_PROPERTIES = "QualifyingProperties";

	public static final String XMLE_UNSIGNED_PROPERTIES = "UnsignedProperties";
	public static final String XMLE_UNSIGNED_SIGNATURE_PROPERTIES = "UnsignedSignatureProperties";
	public static final String XMLE_ARCHIVE_TIME_STAMP = "ArchiveTimeStamp";
	public static final String XMLE_ARCHIVE_TIME_STAMP_V2 = "ArchiveTimeStampV2";
	public static final String XMLE_SIGNATURE_TIME_STAMP = "SignatureTimeStamp";
	public static final String XMLE_REFS_ONLY_TIME_STAMP = "RefsOnlyTimeStamp";
	public static final String XMLE_SIG_AND_REFS_TIME_STAMP = "SigAndRefsTimeStamp";

	public String XADES_SIGNED_PROPERTIES = "http://uri.etsi.org/01903#SignedProperties";

	public String XADES_COUNTERSIGNED_SIGNATURE = "http://uri.etsi.org/01903#CountersignedSignature";

	public String XPATH_CV = "/xades:CertificateValues";
	public String XPATH_EX509C = "/xades:EncapsulatedX509Certificate";
	public String XPATH_ECRLV = "/xades:CRLValues/xades:EncapsulatedCRLValue";
	public String XPATH_EOCSPV = "/xades:OCSPValues/xades:EncapsulatedOCSPValue";
	public String XPATH_OCSPREF = "/xades:OCSPRef";
	public String XPATH__OCSPREF = "." + XPATH_OCSPREF;

	public final String XPATH__SIGNATURE = "./ds:Signature";
	public final String XPATH_SIGNED_INFO = "./ds:SignedInfo";
	public final String XPATH_SIGNATURE_METHOD = XPATH_SIGNED_INFO + "/ds:SignatureMethod";
	public final String XPATH_SIGNATURE_VALUE = "./ds:SignatureValue";
	public final String XPATH_REFERENCE = XPATH_SIGNED_INFO + "/ds:Reference";
	public final String XPATH_KEY_INFO = "./ds:KeyInfo";
	public final String XPATH_X509_DATA = XPATH_KEY_INFO + "/ds:X509Data";
	public final String XPATH__ALL_DATA_OBJECTS_TIMESTAMP = "xades:AllDataObjectsTimeStamp";
	public final String XPATH__INDIVIDUAL_DATA_OBJECTS_TIMESTAMP = "xades:IndividualDataObjectsTimeStamp";

	public final String XPATH_KEY_INFO_X509_CERTIFICATE = XPATH_X509_DATA + "/ds:X509Certificate";

	public final static String XPATH_OBJECT = "./ds:Object";
	public String XPATH_QUALIFYING_PROPERTIES = XPATH_OBJECT + "/xades:QualifyingProperties";
	public String XPATH__QUALIFYING_PROPERTIES = "./xades:QualifyingProperties";
	/**
	 * This query is used to determinate {@code XPathQueryHolder} tu use if function of the namespace of QualifyingProperties.
	 * public final String XPATH_QUALIFYING_PROPERTIES_NAMESPACE = "namespace-uri(./ds:Signature/ds:Object/*[local-name()='QualifyingProperties'])";
	 * This is not used anymore. See
	 */

	public String XPATH__QUALIFYING_PROPERTIES_SIGNED_PROPERTIES = XPATH__QUALIFYING_PROPERTIES + "/xades:SignedProperties";

	public String XPATH_SIGNED_PROPERTIES = XPATH_QUALIFYING_PROPERTIES + "/xades:SignedProperties";
	public String XPATH_SIGNED_SIGNATURE_PROPERTIES = XPATH_SIGNED_PROPERTIES + "/xades:SignedSignatureProperties";
	public String XPATH_SIGNED_DATA_OBJECT_PROPERTIES = XPATH_SIGNED_PROPERTIES + "/xades:SignedDataObjectProperties";
	public String XPATH_ALL_DATA_OBJECTS_TIMESTAMP = XPATH_SIGNED_DATA_OBJECT_PROPERTIES + "/" + XPATH__ALL_DATA_OBJECTS_TIMESTAMP;
	public String XPATH_INDIVIDUAL_DATA_OBJECTS_TIMESTAMP = XPATH_SIGNED_DATA_OBJECT_PROPERTIES + "/" + XPATH__INDIVIDUAL_DATA_OBJECTS_TIMESTAMP;
	public String XPATH_SIGNING_TIME = XPATH_SIGNED_SIGNATURE_PROPERTIES + "/xades:SigningTime";
	public String XPATH_SIGNING_CERTIFICATE_CERT = XPATH_SIGNED_SIGNATURE_PROPERTIES + "/xades:SigningCertificate/xades:Cert";
	public String XPATH_CERT_DIGEST = XPATH_SIGNING_CERTIFICATE_CERT + "/xades:CertDigest";
	public String XPATH_SIGNATURE_POLICY_IDENTIFIER = XPATH_SIGNED_SIGNATURE_PROPERTIES + "/xades:SignaturePolicyIdentifier";
	public String XPATH_CLAIMED_ROLE = XPATH_SIGNED_SIGNATURE_PROPERTIES + "/xades:SignerRole/xades:ClaimedRoles/xades:ClaimedRole";
	public String XPATH_CERTIFIED_ROLE = XPATH_SIGNED_SIGNATURE_PROPERTIES + "/xades:SignerRole/xades:CertifiedRoles/xades:CertifiedRole/EncapsulatedX509Certificate";
	public String XPATH_PRODUCTION_PLACE = XPATH_SIGNED_SIGNATURE_PROPERTIES + "/xades:SignatureProductionPlace";
	public String XPATH__SIGNATURE_POLICY_IMPLIED = "./xades:SignaturePolicyImplied";
	public String XPATH__POLICY_ID = "./xades:SignaturePolicyId/xades:SigPolicyId/xades:Identifier";
	public String XPATH__POLICY_DIGEST_METHOD = "./xades:SignaturePolicyId/xades:SigPolicyHash/ds:DigestMethod/@Algorithm";
	public String XPATH__POLICY_DIGEST_VALUE = "./xades:SignaturePolicyId/xades:SigPolicyHash/ds:DigestValue";
	public String XPATH__INCLUDE = "./xades:Include";

	public String XPATH__X509_ISSUER_NAME = "./xades:IssuerSerial/ds:X509IssuerName";
	public String XPATH__X509_SERIAL_NUMBER = "./xades:IssuerSerial/ds:X509SerialNumber";
	public String XPATH__CERT_DIGEST = "./xades:CertDigest";
	public String XPATH__DIGEST_METHOD = "./ds:DigestMethod";
	public String XPATH__CERT_DIGEST_DIGEST_METHOD = XPATH__CERT_DIGEST + "/ds:DigestMethod";
	public String XPATH__DIGEST_VALUE = "./ds:DigestValue";
	public String XPATH__CERT_DIGEST_DIGEST_VALUE = XPATH__CERT_DIGEST + "/ds:DigestValue";

	public String XPATH_UNSIGNED_PROPERTIES = XPATH_QUALIFYING_PROPERTIES + "/xades:UnsignedProperties";
	public String XPATH_UNSIGNED_SIGNATURE_PROPERTIES = XPATH_UNSIGNED_PROPERTIES + "/xades:UnsignedSignatureProperties";
	public String XPATH_SIGNATURE_TIMESTAMP = XPATH_UNSIGNED_SIGNATURE_PROPERTIES + "/xades:" + XMLE_SIGNATURE_TIME_STAMP;
	public String XPATH_COMPLETE_CERTIFICATE_REFS = XPATH_UNSIGNED_SIGNATURE_PROPERTIES + "/xades:CompleteCertificateRefs";
	public String XPATH_COMPLETE_REVOCATION_REFS = XPATH_UNSIGNED_SIGNATURE_PROPERTIES + "/xades:CompleteRevocationRefs";
	public String XPATH_OCSP_REFS = XPATH_COMPLETE_REVOCATION_REFS + "/xades:OCSPRefs";
	public String XPATH_SIG_AND_REFS_TIMESTAMP = XPATH_UNSIGNED_SIGNATURE_PROPERTIES + "/xades:" + XMLE_SIG_AND_REFS_TIME_STAMP;
	public String XPATH_CERTIFICATE_VALUES = XPATH_UNSIGNED_SIGNATURE_PROPERTIES + XPATH_CV;
	public String XPATH_REVOCATION_VALUES = XPATH_UNSIGNED_SIGNATURE_PROPERTIES + "/xades:RevocationValues";
	public String XPATH_TIME_STAMP_VALIDATION_DATA = XPATH_UNSIGNED_SIGNATURE_PROPERTIES + "/xades141:TimeStampValidationData";
	public String XPATH_COUNTER_SIGNATURE = XPATH_UNSIGNED_SIGNATURE_PROPERTIES + "/xades:CounterSignature";
	public String XPATH_ARCHIVE_TIMESTAMP = XPATH_UNSIGNED_SIGNATURE_PROPERTIES + "/xades:" + XMLE_ARCHIVE_TIME_STAMP;
	public String XPATH_ARCHIVE_TIMESTAMP_141 = XPATH_UNSIGNED_SIGNATURE_PROPERTIES + "/xades141:" + XMLE_ARCHIVE_TIME_STAMP;
	public String XPATH_ARCHIVE_TIMESTAMP_V2 = XPATH_UNSIGNED_SIGNATURE_PROPERTIES + "/xades141:" + XMLE_ARCHIVE_TIME_STAMP_V2;
	public String XPATH_REVOCATION_CRL_REFS = XPATH_COMPLETE_REVOCATION_REFS + "/xades:CRLRefs";

	public final String XPATH__DIGEST_METHOD_ALGORITHM = "./ds:DigestMethod/@Algorithm";

	public String XPATH__CRL_REF = "./xades:CRLRef";
	public String XPATH__COMPLETE_CERTIFICATE_REFS__CERT_DIGEST = "./xades:CertRefs/xades:Cert/xades:CertDigest";
	public String XPATH__DAAV_DIGEST_METHOD = "./xades:DigestAlgAndValue/ds:DigestMethod";
	public String XPATH__DAAV_DIGEST_VALUE = "./xades:DigestAlgAndValue/ds:DigestValue";
	public final String XPATH__CANONICALIZATION_METHOD = "./ds:CanonicalizationMethod";
	public String XPATH__ENCAPSULATED_TIMESTAMP = "./xades:EncapsulatedTimeStamp";

	public String XPATH_ENCAPSULATED_X509_CERTIFICATE = XPATH_CERTIFICATE_VALUES + XPATH_EX509C;
	public String XPATH_TSVD_ENCAPSULATED_X509_CERTIFICATE = XPATH_TIME_STAMP_VALIDATION_DATA + XPATH_CV + XPATH_EX509C;

	public String XPATH_TSVD_ENCAPSULATED_CRL_VALUE = XPATH_TIME_STAMP_VALIDATION_DATA + XPATH_ECRLV;
	public String XPATH_TSVD_ENCAPSULATED_OCSP_VALUE = XPATH_TIME_STAMP_VALIDATION_DATA + XPATH_EOCSPV;

	public String XPATH_CERT_REFS = XPATH_COMPLETE_CERTIFICATE_REFS + "/xades:CertRefs";

	public String XPATH_ENCAPSULATED_CRL_VALUE = XPATH_REVOCATION_VALUES + XPATH_ECRLV;
	public String XPATH_ENCAPSULATED_OCSP_VALUE = XPATH_REVOCATION_VALUES + XPATH_EOCSPV;

	// Level -B
	public String XPATH_COUNT_SIGNED_SIGNATURE_PROPERTIES = "count(" + XPATH_SIGNED_SIGNATURE_PROPERTIES + ")";
	// Level -T
	public final String XPATH_COUNT_SIGNATURE_TIMESTAMP = "count(" + XPATH_SIGNATURE_TIMESTAMP + ")";
	// Level -C
	public final String XPATH_COUNT_COMPLETE_CERTIFICATE_REFS = "count(" + XPATH_COMPLETE_CERTIFICATE_REFS + ")";
	public final String XPATH_COUNT_COMPLETE_REVOCATION_REFS = "count(" + XPATH_COMPLETE_REVOCATION_REFS + ")";
	// Level -X
	public final String XPATH_COUNT_SIG_AND_REFS_TIMESTAMP = "count(" + XPATH_SIG_AND_REFS_TIMESTAMP + ")";
	// Level -XL -LT
	public final String XPATH_COUNT_CERTIFICATE_VALUES = "count(" + XPATH_CERTIFICATE_VALUES + ")";
	public final String XPATH_COUNT_REVOCATION_VALUES = "count(" + XPATH_REVOCATION_VALUES + ")";
	// Level -A -LTA
	public final String XPATH_COUNT_ARCHIVE_TIMESTAMP = "count(" + XPATH_ARCHIVE_TIMESTAMP + ")";
	public final String XPATH_COUNT_ARCHIVE_TIMESTAMP_141 = "count(" + XPATH_ARCHIVE_TIMESTAMP_141 + ")";
	public final String XPATH_COUNT_ARCHIVE_TIMESTAMP_V2 = "count(" + XPATH_ARCHIVE_TIMESTAMP_V2 + ")";

	/**
	 * This method returns true if this implementation is able to deal with a specific namespace.
	 *
	 * @param namespace
	 * @return
	 */
	public boolean canUseThisXPathQueryHolder(final String namespace) {

		boolean canUse = XAdESNamespaces.XAdES.equals(namespace);
		return canUse;
	}
}
