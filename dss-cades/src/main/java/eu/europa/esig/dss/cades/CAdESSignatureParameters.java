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

import eu.europa.esig.dss.signature.AbstractSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESTimestampParameters;

/**
 * Defines SignatureParameters to deal with CAdES signature creation/extension
 */
public class CAdESSignatureParameters extends AbstractSignatureParameters<CAdESTimestampParameters> {

	private static final long serialVersionUID = 9035260907528290973L;

	/** Defines if the signature shall be created according to ETSI EN 319 122 */
	private boolean en319122 = true;

	/** Content Hints type */
	private String contentHintsType;

	/** Content Hints description */
	private String contentHintsDescription;

	/** Content identifier prefix */
	private String contentIdentifierPrefix;

	/** Content identifier suffix */
	private String contentIdentifierSuffix;

	/** Defines if a parallel signature should be created when a CMS signature is provided as a signed document */
	private boolean parallelSignature = true;

	/**
	 * Default constructor instantiating object with null values
	 */
	public CAdESSignatureParameters() {
		// empty
	}

	/**
	 * Returns if the signature shall be created according to ETSI EN 319 122
	 *
	 * @return TRUE if the signature shall be created according to ETSI EN 319 122, otherwise as an old format
	 */
	public boolean isEn319122() {
		return en319122;
	}

	/**
	 * Sets if the signature shall be created according to ETSI EN 319 122,
	 * otherwise will be created with respect to the old standard
	 *
	 * Default: true
	 *
	 * @param en319122 if the signature shall be created according to ETSI EN 319 122
	 */
	public void setEn319122(boolean en319122) {
		this.en319122 = en319122;
	}

	/**
	 * Gets content hints type
	 *
	 * @return {@link String}
	 */
	public String getContentHintsType() {
		return contentHintsType;
	}

	/**
	 * Sets content hints type
	 *
	 * @param contentHintsType {@link String}
	 */
	public void setContentHintsType(String contentHintsType) {
		this.contentHintsType = contentHintsType;
	}

	/**
	 * Gets content hints description
	 *
	 * @return {@link String}
	 */
	public String getContentHintsDescription() {
		return contentHintsDescription;
	}

	/**
	 * Sets content hints description
	 *
	 * @param contentHintsDescription {@link String}
	 */
	public void setContentHintsDescription(String contentHintsDescription) {
		this.contentHintsDescription = contentHintsDescription;
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
	 * @return {@link String}
	 */
	public String getContentIdentifierSuffix() {
		return contentIdentifierSuffix;
	}

	/**
	 * Sets content identifier suffix.
	 *
	 * NOTE: THIS VALUE WILL BE SET AUTOMATICALLY IF LEFT BLANK
	 *
	 * @param contentIdentifierSuffix {@link String}
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
	 * @return {@link String}
	 */
	public String getContentIdentifierPrefix() {
		return contentIdentifierPrefix;
	}

	/**
	 * Sets content identifier prefix
	 *
	 * @param contentIdentifierPrefix {@link String}
	 * @see #getContentIdentifierPrefix()
	 */
	public void setContentIdentifierPrefix(String contentIdentifierPrefix) {
		this.contentIdentifierPrefix = contentIdentifierPrefix;
	}

	/**
	 * Returns whether a parallel signature should be created when an original document is
	 * represented by a CMSSignedData (i.e. another CMS signature document)
	 *
	 * @return whether a parallel signing is expected
	 */
	public boolean isParallelSignature() {
		return parallelSignature;
	}

	/**
	 * Sets whether a parallel signature should be created in case the provided documentToSign is represented
	 * by a CMSSignedData (i.e. another CMS signature document).
	 * When enabled, the created produced document will be build based on the original CMSSignedData content,
	 * and the new signature will be included inside the CMSSignedData as a parallel signature, next to existing signatures.
	 * When disabled, the new signature will cover the binaries of the original CMSSignedData,
	 * as in case of a not-signed original document. This allows creation of nested CMS signatures.
	 * When a non CMSSignedData document is provided, the parameter does not impact the processing.
	 * Default : TRUE (creates a parallel signature, when applicable)
	 *
	 * @param parallelSignature whether a parallel signature should be created in case the provided documentToSign
	 *                          is represented by a CMSSignedData
	 */
	public void setParallelSignature(boolean parallelSignature) {
		this.parallelSignature = parallelSignature;
	}

	@Override
	public CAdESTimestampParameters getContentTimestampParameters() {
		if (contentTimestampParameters == null) {
			contentTimestampParameters = new CAdESTimestampParameters();
		}
		return contentTimestampParameters;
	}

	@Override
	public CAdESTimestampParameters getSignatureTimestampParameters() {
		if (signatureTimestampParameters == null) {
			signatureTimestampParameters = new CAdESTimestampParameters();
		}
		return signatureTimestampParameters;
	}

	@Override
	public CAdESTimestampParameters getArchiveTimestampParameters() {
		if (archiveTimestampParameters == null) {
			archiveTimestampParameters = new CAdESTimestampParameters();
		}
		return archiveTimestampParameters;
	}

}
