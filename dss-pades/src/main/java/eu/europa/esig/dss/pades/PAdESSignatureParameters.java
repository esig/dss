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
package eu.europa.esig.dss.pades;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESTimestampParameters;
import eu.europa.esig.dss.enumerations.CertificationPermission;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.pdf.PAdESConstants;

import java.util.Date;
import java.util.TimeZone;

/**
 * Parameters to create/extend a PAdES signature
 */
public class PAdESSignatureParameters extends CAdESSignatureParameters implements PAdESCommonParameters {

	private static final long serialVersionUID = -1632557456487796227L;

	/** The signature creation reason */
	private String reason;

	/** The contact info */
	private String contactInfo;

	/** The signer's location */
	private String location;

	/**
	 * Defines the preserved space for a signature context
	 *
	 * Default : 9472 (default value in pdfbox)
	 */
	private int signatureSize = 9472;

	/**
	 * This attribute allows to override the used Filter for a Signature.
	 * 
	 * Default value is Adobe.PPKLite
	 */
	private String signatureFilter = PAdESConstants.SIGNATURE_DEFAULT_FILTER;

	/**
	 * This attribute allows to override the used subFilter for a Signature.
	 * 
	 * Default value is ETSI.CAdES.detached
	 */
	private String signatureSubFilter = PAdESConstants.SIGNATURE_DEFAULT_SUBFILTER;

	/**
	 * This attribute allows to explicitly specify the SignerName (name for the Signature).
	 * The person or authority signing the document.
	 */
	private String signerName;

	/**
	 * This attribute is used to create visible signature in PAdES form
	 */
	private SignatureImageParameters signatureImageParameters;

	/**
	 * This attribute allows to create a "certification signature". That allows to remove permission(s) in case of
	 * future change(s).
	 */
	private CertificationPermission permission;
	
	/**
	 * Password used to encrypt a PDF
	 */
	private String passwordProtection;

	/**
	 * The time-zone used for signature creation
	 *
	 * Default: TimeZone.getDefault()
	 */
	private TimeZone signingTimeZone = TimeZone.getDefault();

	@Override
	public void setSignatureLevel(SignatureLevel signatureLevel) {
		if (signatureLevel == null || SignatureForm.PAdES != signatureLevel.getSignatureForm()) {
			throw new IllegalArgumentException("Only PAdES form is allowed !");
		}
		super.setSignatureLevel(signatureLevel);
	}

	/**
	 * Gets the reason
	 *
	 * @return {@link String}
	 */
	public String getReason() {
		return this.reason;
	}

	/**
	 * Sets the reason
	 *
	 * @param reason
	 *            {@link String} the reason to set
	 */
	public void setReason(final String reason) {
		this.reason = reason;
	}

	/**
	 * Gets the contactInfo
	 *
	 * @return {@link String}
	 */
	public String getContactInfo() {
		return this.contactInfo;
	}

	/**
	 * Sets the contactInfo
	 *
	 * @param contactInfo
	 *            {@link String}
	 */
	public void setContactInfo(final String contactInfo) {
		this.contactInfo = contactInfo;
	}

	@Override
	public String getFilter() {
		return signatureFilter;
	}

	/**
	 * Sets the filter
	 *
	 * @param signatureFilter {@link String}
	 */
	public void setFilter(String signatureFilter) {
		this.signatureFilter = signatureFilter;
	}

	@Override
	public String getSubFilter() {
		return signatureSubFilter;
	}

	/**
	 * Sets the sub filter
	 *
	 * @param signatureSubFilter {@link String}
	 */
	public void setSubFilter(String signatureSubFilter) {
		this.signatureSubFilter = signatureSubFilter;
	}

	/**
	 * Returns the Signer Name
	 *
	 * @return {@link String}
	 */
	public String getSignerName() {
		return signerName;
	}

	/**
	 * Sets the name of the signed
	 *
	 * @param signerName {@link String}
	 */
	public void setSignerName(final String signerName) {
		this.signerName = signerName;
	}

	@Override
	public SignatureImageParameters getImageParameters() {
		if (signatureImageParameters == null) {
			signatureImageParameters = new SignatureImageParameters();
		}
		return signatureImageParameters;
	}

	/**
	 * Sets the {@code SignatureImageParameters} for a visual signature creation
	 *
	 * @param signatureImageParameters {@link SignatureImageParameters}
	 */
	public void setImageParameters(SignatureImageParameters signatureImageParameters) {
		this.signatureImageParameters = signatureImageParameters;
	}

	/**
	 * Gets location
	 * 
	 * @return {@link String}
	 */
	public String getLocation() {
		return this.location;
	}

	/**
	 * Sets location (The CPU host name or physical location of the signing)
	 * 
	 * @param location {@link String}
	 */
	public void setLocation(String location) {
		this.location = location;
	}

	/**
	 * The id/name of the signature field which should be signed
	 * 
	 * Deprecated. Use {@code getImageParameters().getFieldParameters().setFieldId(signatureFieldId)}
	 * 
	 * @param signatureFieldId {@link String} id of a signature field to be used
	 */
	@Deprecated
	public void setSignatureFieldId(String signatureFieldId) {
		getImageParameters().getFieldParameters().setFieldId(signatureFieldId);
	}

	@Override
	public int getContentSize() {
		return this.signatureSize;
	}

	/**
	 * This setter allows to reserve more than the default size for a signature (9472bytes)
	 *
	 * @param signatureSize /Contents parameter reserved space
	 */
	public void setContentSize(int signatureSize) {
		this.signatureSize = signatureSize;
	}

	/**
	 * Gets the permission for the PDF document modification
	 *
	 * @return {@link CertificationPermission}
	 */
	public CertificationPermission getPermission() {
		return permission;
	}

	/**
	 * Sets the permission for the PDF document modification
	 *
	 * @param permission {@link CertificationPermission}
	 */
	public void setPermission(CertificationPermission permission) {
		this.permission = permission;
	}

	@Override
	public String getPasswordProtection() {
		return passwordProtection;
	}

	/**
	 * Sets a password string
	 * 
	 * @param passwordProtection {@link String} password to set
	 */
	public void setPasswordProtection(String passwordProtection) {
		this.passwordProtection = passwordProtection;
	}

	@Override
	public Date getSigningDate() {
		return bLevel().getSigningDate();
	}

	/**
	 * Sets a TimeZone to use for signature creation.
	 * Will be used to define a signingTime within a PDF entry with key /M.
	 *
	 * Default: TimeZone.getDefault()
	 *
	 * @param signingTimeZone {@link TimeZone}
	 */
	public void setSigningTimeZone(TimeZone signingTimeZone) {
		this.signingTimeZone = signingTimeZone;
	}

	/**
	 * Returns a time-zone used to define the signing time
	 *
	 * @return {@link TimeZone}
	 */
	public TimeZone getSigningTimeZone() {
		return signingTimeZone;
	}

	@Override
	public PAdESTimestampParameters getContentTimestampParameters() {
		if (contentTimestampParameters == null) {
			contentTimestampParameters = new PAdESTimestampParameters();
		}
		return (PAdESTimestampParameters) contentTimestampParameters;
	}
	
	@Override
	public void setContentTimestampParameters(CAdESTimestampParameters contentTimestampParameters) {
		if (contentTimestampParameters instanceof PAdESTimestampParameters) {
			this.contentTimestampParameters = contentTimestampParameters;
		} else {
			this.contentTimestampParameters = new PAdESTimestampParameters(contentTimestampParameters);
		}
	}

	@Override
	public PAdESTimestampParameters getSignatureTimestampParameters() {
		if (signatureTimestampParameters == null) {
			signatureTimestampParameters = new PAdESTimestampParameters();
		}
		return (PAdESTimestampParameters) signatureTimestampParameters;
	}
	
	@Override
	public void setSignatureTimestampParameters(CAdESTimestampParameters signatureTimestampParameters) {
		if (signatureTimestampParameters instanceof PAdESTimestampParameters) {
			this.signatureTimestampParameters = signatureTimestampParameters;
		} else {
			this.signatureTimestampParameters = new PAdESTimestampParameters(signatureTimestampParameters);
		}
	}

	@Override
	public PAdESTimestampParameters getArchiveTimestampParameters() {
		if (archiveTimestampParameters == null) {
			archiveTimestampParameters = new PAdESTimestampParameters();
		}
		return (PAdESTimestampParameters) archiveTimestampParameters;
	}
	
	@Override
	public void setArchiveTimestampParameters(CAdESTimestampParameters archiveTimestampParameters) {
		if (archiveTimestampParameters instanceof PAdESTimestampParameters) {
			this.archiveTimestampParameters = archiveTimestampParameters;
		} else {
			this.archiveTimestampParameters = new PAdESTimestampParameters(archiveTimestampParameters);
		}
	}

}
