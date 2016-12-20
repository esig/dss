package eu.europa.esig.dss.cades;

import eu.europa.esig.dss.AbstractSignatureParameters;

public class CAdESSignatureParameters extends AbstractSignatureParameters {

	private String contentHintsType;
	private String contentHintsDescription;

	private String contentIdentifierPrefix;
	private String contentIdentifierSuffix;

	public String getContentHintsType() {
		return contentHintsType;
	}

	public void setContentHintsType(String contentHintsType) {
		this.contentHintsType = contentHintsType;
	}

	public String getContentHintsDescription() {
		return contentHintsDescription;
	}

	public void setContentHintsDescription(String contentHintsDescription) {
		this.contentHintsDescription = contentHintsDescription;
	}

	/**
	 * THIS VALUE WILL BE SET AUTOMATICALLY IF LEFT BLANK
	 *
	 * ETSI TS 101 733 V2.2.1 (2013-04)
	 *
	 * 5.10.2 content-identifier Attribute
	 * The content-identifier attribute provides an identifier for the signed content, for use when a reference may be
	 * later required to that content; for example, in the content-reference attribute in other signed data sent later.
	 * The
	 * content-identifier shall be a signed attribute.
	 * content-identifier attribute type values for the ES have an ASN.1 type ContentIdentifier, as defined in
	 * ESS (RFC 2634 [5]).
	 *
	 * The minimal content-identifier attribute should contain a concatenation of user-specific identification
	 * information (such as a user name or public keying material identification information), a GeneralizedTime string,
	 * and a random number.
	 *
	 * @return
	 */
	public String getContentIdentifierSuffix() {
		return contentIdentifierSuffix;
	}

	/**
	 * @param contentIdentifierSuffix
	 * @see #getContentIdentifierSuffix()
	 */
	public void setContentIdentifierSuffix(String contentIdentifierSuffix) {
		this.contentIdentifierSuffix = contentIdentifierSuffix;
	}

	/**
	 * ETSI TS 101 733 V2.2.1 (2013-04)
	 *
	 * 5.10.2 content-identifier Attribute
	 * The content-identifier attribute provides an identifier for the signed content, for use when a reference may be
	 * later required to that content; for example, in the content-reference attribute in other signed data sent later.
	 * The
	 * content-identifier shall be a signed attribute.
	 * content-identifier attribute type values for the ES have an ASN.1 type ContentIdentifier, as defined in
	 * ESS (RFC 2634 [5]).
	 *
	 * The minimal content-identifier attribute should contain a concatenation of user-specific identification
	 * information (such as a user name or public keying material identification information), a GeneralizedTime string,
	 * and a random number.
	 *
	 * @return
	 */
	public String getContentIdentifierPrefix() {
		return contentIdentifierPrefix;
	}

	/**
	 * @param contentIdentifierPrefix
	 * @see #getContentIdentifierPrefix()
	 */
	public void setContentIdentifierPrefix(String contentIdentifierPrefix) {
		this.contentIdentifierPrefix = contentIdentifierPrefix;
	}

}
