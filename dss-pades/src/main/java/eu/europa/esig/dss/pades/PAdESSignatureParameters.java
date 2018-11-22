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

import eu.europa.esig.dss.SignatureForm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.pdf.PAdESConstants;

public class PAdESSignatureParameters extends CAdESSignatureParameters {

	private static final long serialVersionUID = -1632557456487796227L;

	private String reason;
	private String contactInfo;
	private String location;
	private String signatureFieldId;

	private int signatureSize = 9472; // default value in pdfbox

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
	 * This attribute allows to explicitly specify the name for a Signature.
	 * The person or authority signing the document.
	 */
	private String signatureName;

	/**
	 * This attribute is used to create visible signature in PAdES form
	 */
	private SignatureImageParameters signatureImageParameters;

	/**
	 * This attribute allows to override the used Filter for a Timestamp.
	 * 
	 * Default value is Adobe.PPKLite
	 */
	private String timestampFilter = PAdESConstants.TIMESTAMP_DEFAULT_FILTER;

	/**
	 * This attribute allows to override the used subFilter for a Timestamp.
	 * 
	 * Default value is ETSI.RFC3161
	 */
	private String timestampSubFilter = PAdESConstants.TIMESTAMP_DEFAULT_SUBFILTER;

	private SignatureImageParameters timestampImageParameters;

	/**
	 * This attribute allows to create a "certification signature". That allows to remove permission(s) in case of
	 * future change(s).
	 */
	private CertificationPermission permission;

	@Override
	public void setSignatureLevel(SignatureLevel signatureLevel) {
		if (signatureLevel == null || SignatureForm.PAdES != signatureLevel.getSignatureForm()) {
			throw new IllegalArgumentException("Only PAdES form is allowed !");
		}
		super.setSignatureLevel(signatureLevel);
	}

	/**
	 * @return the reason
	 */
	public String getReason() {
		return this.reason;
	}

	/**
	 * @param reason
	 *            the reason to set
	 */
	public void setReason(final String reason) {
		this.reason = reason;
	}

	/**
	 * @return the contactInfo
	 */
	public String getContactInfo() {
		return this.contactInfo;
	}

	/**
	 * @param contactInfo
	 *            the contactInfo to set
	 */
	public void setContactInfo(final String contactInfo) {
		this.contactInfo = contactInfo;
	}

	public String getSignatureFilter() {
		return signatureFilter;
	}

	public void setSignatureFilter(String signatureFilter) {
		this.signatureFilter = signatureFilter;
	}

	public String getSignatureSubFilter() {
		return signatureSubFilter;
	}

	public void setSignatureSubFilter(String signatureSubFilter) {
		this.signatureSubFilter = signatureSubFilter;
	}

	public String getSignatureName() {
		return signatureName;
	}

	public void setSignatureName(final String signatureName) {
		this.signatureName = signatureName;
	}

	public SignatureImageParameters getSignatureImageParameters() {
		return this.signatureImageParameters;
	}

	public void setSignatureImageParameters(SignatureImageParameters signatureImageParameters) {
		this.signatureImageParameters = signatureImageParameters;
	}

	public String getTimestampFilter() {
		return timestampFilter;
	}

	public void setTimestampFilter(String timestampFilter) {
		this.timestampFilter = timestampFilter;
	}

	public String getTimestampSubFilter() {
		return timestampSubFilter;
	}

	public void setTimestampSubFilter(String timestampSubFilter) {
		this.timestampSubFilter = timestampSubFilter;
	}

	public SignatureImageParameters getTimestampImageParameters() {
		return this.timestampImageParameters;
	}

	public void setTimestampImageParameters(SignatureImageParameters timestampImageParameters) {
		this.timestampImageParameters = timestampImageParameters;
	}

	public String getLocation() {
		return this.location;
	}

	public void setLocation(String location) {
		this.location = location;
	}

	public String getSignatureFieldId() {
		return this.signatureFieldId;
	}

	/**
	 * The id/name of the signature field which should be signed
	 * 
	 * @param signatureFieldId
	 */
	public void setSignatureFieldId(String signatureFieldId) {
		this.signatureFieldId = signatureFieldId;
	}

	public int getSignatureSize() {
		return this.signatureSize;
	}

	/**
	 * This setter allows to reserve more than the default size for a signature (9472bytes)
	 */
	public void setSignatureSize(int signatureSize) {
		this.signatureSize = signatureSize;
	}

	public CertificationPermission getPermission() {
		return permission;
	}

	public void setPermission(CertificationPermission permission) {
		this.permission = permission;
	}

}
