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
package eu.europa.esig.dss.cades;

import eu.europa.esig.dss.AbstractSignatureParameters;

public class CAdESSignatureParameters extends AbstractSignatureParameters {

	private boolean en319122 = true;

	private String contentHintsType;
	private String contentHintsDescription;

	private String contentIdentifierPrefix;
	private String contentIdentifierSuffix;

	public boolean isEn319122() {
		return en319122;
	}

	public void setEn319122(boolean en319122) {
		this.en319122 = en319122;
	}

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
