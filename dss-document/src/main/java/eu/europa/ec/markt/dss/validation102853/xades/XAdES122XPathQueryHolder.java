package eu.europa.ec.markt.dss.validation102853.xades;

import eu.europa.ec.markt.dss.XAdESNamespaces;

/**
 * TODO
 * <p/>
 * <p> DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
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

		// Level -B
		XPATH_COUNT_SIGNED_SIGNATURE_PROPERTIES = "count(" + XPATH_SIGNED_SIGNATURE_PROPERTIES + ")";
	}

	@Override
	public boolean canUseThisXPathQueryHolder(final String namespace) {

		boolean canUse = XAdESNamespaces.XAdES122.equals(namespace);
		return canUse;
	}
}
