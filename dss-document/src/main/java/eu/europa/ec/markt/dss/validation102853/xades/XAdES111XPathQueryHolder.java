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
public class XAdES111XPathQueryHolder extends XPathQueryHolder {

	public XAdES111XPathQueryHolder() {

		XADES_SIGNED_PROPERTIES = "http://uri.etsi.org/01903/v1.1.1#SignedProperties";

		XPATH_QUALIFYING_PROPERTIES = XPATH_OBJECT + "/xades111:QualifyingProperties";
		XPATH__QUALIFYING_PROPERTIES = "./xades111:QualifyingProperties";

		XPATH__QUALIFYING_PROPERTIES_SIGNED_PROPERTIES = XPATH__QUALIFYING_PROPERTIES + "/xades111:SignedProperties";

		XPATH_SIGNED_PROPERTIES = XPATH_QUALIFYING_PROPERTIES + "/xades111:SignedProperties";
		XPATH_SIGNED_SIGNATURE_PROPERTIES = XPATH_SIGNED_PROPERTIES + "/xades111:SignedSignatureProperties";
		XPATH_SIGNING_TIME = XPATH_SIGNED_SIGNATURE_PROPERTIES + "/xades111:SigningTime";
		XPATH_SIGNING_CERTIFICATE_CERT = XPATH_SIGNED_SIGNATURE_PROPERTIES + "/xades111:SigningCertificate/xades111:Cert";
		XPATH_SIGNATURE_POLICY_IDENTIFIER = XPATH_SIGNED_SIGNATURE_PROPERTIES + "/xades111:SignaturePolicyIdentifier";
		XPATH__SIGNATURE_POLICY_IMPLIED = "./xades111:SignaturePolicyImplied";

		XPATH_QUALIFYING_PROPERTIES = XPATH_OBJECT + "/xades111:QualifyingProperties";
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

		// Level -B
		XPATH_COUNT_SIGNED_SIGNATURE_PROPERTIES = "count(" + XPATH_SIGNED_SIGNATURE_PROPERTIES + ")";
	}

	@Override
	public boolean canUseThisXPathQueryHolder(final String namespace) {

		boolean canUse = XAdESNamespaces.XAdES111.equals(namespace);
		return canUse;
	}
}
