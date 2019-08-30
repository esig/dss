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
package eu.europa.esig.dss.xades;

import java.io.Serializable;

import eu.europa.esig.dss.XAdESNamespaces;

/**
 * This class hold all XPath queries schema-dependent. It was created to cope with old signatures bases on http://uri.etsi.org/01903/v1.1.1.
 *
 */
@SuppressWarnings("serial")
public class XPathQueryHolder implements Serializable {

	public static final String XMLE_ARCHIVE_TIME_STAMP = "ArchiveTimeStamp";
	public static final String XMLE_SIGNATURE_TIME_STAMP = "SignatureTimeStamp";

	public final String XPATH__ALL_DATA_OBJECTS_TIMESTAMP = "xades:AllDataObjectsTimeStamp";
	public final String XPATH__INDIVIDUAL_DATA_OBJECTS_TIMESTAMP = "xades:IndividualDataObjectsTimeStamp";
	public final String XPATH__COMMITMENT_TYPE_INDICATION = "xades:CommitmentTypeIndication";
	
	public static final String XPATH_OBJECT = "./ds:Object";

	public String XPATH_QUALIFYING_PROPERTIES = XPATH_OBJECT + "/xades:QualifyingProperties";
	public String XPATH__QUALIFYING_PROPERTIES = "./xades:QualifyingProperties";
	/**
	 * This query is used to determinate {@code XPathQueryHolder} tu use if function of the namespace of QualifyingProperties. public final String
	 * XPATH_QUALIFYING_PROPERTIES_NAMESPACE = "namespace-uri(./ds:Signature/ds:Object/*[local-name()='QualifyingProperties'])"; This is not used anymore. See
	 */

	public String XPATH__QUALIFYING_PROPERTIES_SIGNED_PROPERTIES = XPATH__QUALIFYING_PROPERTIES + "/xades:SignedProperties";

	public String XPATH_SIGNED_PROPERTIES = XPATH_QUALIFYING_PROPERTIES + "/xades:SignedProperties";
	public String XPATH_SIGNED_SIGNATURE_PROPERTIES = XPATH_SIGNED_PROPERTIES + "/xades:SignedSignatureProperties";
	public String XPATH_SIGNED_DATA_OBJECT_PROPERTIES = XPATH_SIGNED_PROPERTIES + "/xades:SignedDataObjectProperties";
	public String XPATH_ALL_DATA_OBJECTS_TIMESTAMP = XPATH_SIGNED_DATA_OBJECT_PROPERTIES + "/" + XPATH__ALL_DATA_OBJECTS_TIMESTAMP;

	public String XPATH_INDIVIDUAL_DATA_OBJECTS_TIMESTAMP = XPATH_SIGNED_DATA_OBJECT_PROPERTIES + "/" + XPATH__INDIVIDUAL_DATA_OBJECTS_TIMESTAMP;
	public String XPATH_SIGNING_TIME = XPATH_SIGNED_SIGNATURE_PROPERTIES + "/xades:SigningTime";
	public String XPATH_SIGNING_CERTIFICATE_CERT = XPATH_SIGNED_SIGNATURE_PROPERTIES + "/xades:SigningCertificate/xades:Cert";
	public String XPATH_SIGNING_CERTIFICATE_CERT_V2 = XPATH_SIGNED_SIGNATURE_PROPERTIES + "/xades:SigningCertificateV2/xades:Cert";
	public String XPATH_SIGNATURE_POLICY_IDENTIFIER = XPATH_SIGNED_SIGNATURE_PROPERTIES + "/xades:SignaturePolicyIdentifier";
	public String XPATH_CLAIMED_ROLE = XPATH_SIGNED_SIGNATURE_PROPERTIES + "/xades:SignerRole/xades:ClaimedRoles/xades:ClaimedRole";
	public String XPATH_CLAIMED_ROLE_V2 = XPATH_SIGNED_SIGNATURE_PROPERTIES + "/xades:SignerRoleV2/xades:ClaimedRoles/xades:ClaimedRole";
	public String XPATH_CERTIFIED_ROLE = XPATH_SIGNED_SIGNATURE_PROPERTIES
			+ "/xades:SignerRole/xades:CertifiedRoles/xades:CertifiedRole/EncapsulatedX509Certificate";
	public String XPATH_CERTIFIED_ROLE_V2 = XPATH_SIGNED_SIGNATURE_PROPERTIES
			+ "/xades:SignerRoleV2/xades:CertifiedRolesV2/xades:CertifiedRole/EncapsulatedX509Certificate";
	public String XPATH__SIGNATURE_POLICY_IMPLIED = "./xades:SignaturePolicyImplied";
	public String XPATH__INCLUDE = "./xades:Include";

	public String XPATH_COMMITMENT_IDENTIFICATION = XPATH_SIGNED_DATA_OBJECT_PROPERTIES + "/" + XPATH__COMMITMENT_TYPE_INDICATION;
	public String XPATH_COMITMENT_IDENTIFIERS = "./xades:CommitmentTypeId/xades:Identifier";

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
	
	public String XPATH__ENCAPSULATED_TIMESTAMP = "./xades:EncapsulatedTimeStamp";

	/**
	 * This method returns true if this implementation is able to deal with a specific namespace.
	 *
	 * @param namespace
	 * @return
	 */
	public boolean canUseThisXPathQueryHolder(final String namespace) {
		return XAdESNamespaces.getXAdESDefaultNamespace().equals(namespace);
	}
}
