package eu.europa.esig.dss;

public enum CertificateRefLocation {

	/**
	 * The certificate reference was embedded in the signature 'attribute-certificate-references' attribute (used in CAdES and XAdES)
	 */
	ATTRIBUTE_CERTIFICATE_REFS,

	/**
	 * The certificate reference was embedded in the signature 'complete-certificate-references' attribute (used in CAdES and XAdES)
	 */
	COMPLETE_CERTIFICATE_REFS,

	/**
	 * The certificate reference was embedded in the signature 'signing-certificate' attribute (used in CAdES and XAdES)
	 */
	SIGNING_CERTIFICATE,

}
