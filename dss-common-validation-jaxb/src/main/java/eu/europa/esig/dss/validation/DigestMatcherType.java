package eu.europa.esig.dss.validation;

public enum DigestMatcherType {

	/* XAdES */
	REFERENCE, OBJECT, MANIFEST, SIGNED_PROPERTIES,

	/* CAdES */
	MESSAGE_DIGEST,

	/* Timestamp */
	MESSAGE_IMPRINT

}
