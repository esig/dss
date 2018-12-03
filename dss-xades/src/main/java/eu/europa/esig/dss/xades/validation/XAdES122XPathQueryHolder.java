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
public class XAdES122XPathQueryHolder extends XPathQueryHolder {

	public XAdES122XPathQueryHolder() {

		XADES_SIGNED_PROPERTIES = "http://uri.etsi.org/01903/v1.2.2#SignedProperties";

		XPATH_QUALIFYING_PROPERTIES = XPATH_OBJECT + "/xades122:QualifyingProperties";
		XPATH__QUALIFYING_PROPERTIES = "./xades122:QualifyingProperties";

		XPATH__QUALIFYING_PROPERTIES_SIGNED_PROPERTIES = XPATH__QUALIFYING_PROPERTIES + "/xades122:SignedProperties";

		XPATH_SIGNED_PROPERTIES = XPATH_QUALIFYING_PROPERTIES + "/xades122:SignedProperties";
		XPATH_SIGNED_SIGNATURE_PROPERTIES = XPATH_SIGNED_PROPERTIES + "/xades122:SignedSignatureProperties";
		XPATH_SIGNING_TIME = XPATH_SIGNED_SIGNATURE_PROPERTIES + "/xades122:SigningTime";
		XPATH_SIGNING_CERTIFICATE_CERT = XPATH_SIGNED_SIGNATURE_PROPERTIES + "/xades122:SigningCertificate/xades122:Cert";
		XPATH_SIGNATURE_POLICY_IDENTIFIER = XPATH_SIGNED_SIGNATURE_PROPERTIES + "/xades122:SignaturePolicyIdentifier";
		XPATH__SIGNATURE_POLICY_IMPLIED = "./xades122:SignaturePolicyImplied";

		XPATH_QUALIFYING_PROPERTIES = XPATH_OBJECT + "/xades122:QualifyingProperties";
		XPATH_UNSIGNED_PROPERTIES = XPATH_QUALIFYING_PROPERTIES + "/xades122:UnsignedProperties";
		XPATH_UNSIGNED_SIGNATURE_PROPERTIES = XPATH_UNSIGNED_PROPERTIES + "/xades122:UnsignedSignatureProperties";
		XPATH_SIGNATURE_TIMESTAMP = XPATH_UNSIGNED_SIGNATURE_PROPERTIES + "/xades122:SignatureTimeStamp";

		XPATH__ENCAPSULATED_TIMESTAMP = "./xades122:EncapsulatedTimeStamp";

		XPATH_ALL_DATA_OBJECTS_TIMESTAMP = XPATH_SIGNED_PROPERTIES + "/xades122:SignedDataObjectProperties/xades122:AllDataObjectsTimeStamp";

		XPATH__X509_ISSUER_NAME = "./xades122:IssuerSerial/ds:X509IssuerName";
		XPATH__X509_SERIAL_NUMBER = "./xades122:IssuerSerial/ds:X509SerialNumber";
		XPATH__CERT_DIGEST = "./xades122:CertDigest";
		XPATH__DIGEST_METHOD = "./ds:DigestMethod";
		XPATH__CERT_DIGEST_DIGEST_METHOD = "./xades122:CertDigest/ds:DigestMethod";
		XPATH__CERT_DIGEST_DIGEST_VALUE = "./xades122:CertDigest/ds:DigestValue";

	}

	@Override
	public boolean canUseThisXPathQueryHolder(final String namespace) {
		return XAdESNamespaces.XAdES122.equals(namespace);
	}
}
