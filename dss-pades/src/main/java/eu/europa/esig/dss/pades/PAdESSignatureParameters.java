package eu.europa.esig.dss.pades;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;

public class PAdESSignatureParameters extends CAdESSignatureParameters {

	private String reason;
	private String contactInfo;
	private String location;

	private int signatureSize = 9472; // default value in pdfbox

	/**
	 * This attribute is used to create visible signature in PAdES form
	 */
	private SignatureImageParameters imageParameters;

	/**
	 * @return the reason (used by PAdES)
	 */
	public String getReason() {
		return reason;
	}

	/**
	 * @param reason
	 *            the reason to set (used by PAdES)
	 */
	public void setReason(final String reason) {
		this.reason = reason;
	}

	/**
	 * @return the contactInfo (used by PAdES)
	 */
	public String getContactInfo() {
		return contactInfo;
	}

	/**
	 * @param contactInfo
	 *            the contactInfo to set (used by PAdES)
	 */
	public void setContactInfo(final String contactInfo) {
		this.contactInfo = contactInfo;
	}

	public SignatureImageParameters getImageParameters() {
		return imageParameters;
	}

	public void setImageParameters(SignatureImageParameters imageParameters) {
		this.imageParameters = imageParameters;
	}

	public String getLocation() {
		return location;
	}

	public void setLocation(String location) {
		this.location = location;
	}

	public int getSignatureSize() {
		return signatureSize;
	}

	/**
	 * This setter allows to reserve more than the default size for a signature (9472bytes)
	 */
	public void setSignatureSize(int signatureSize) {
		this.signatureSize = signatureSize;
	}

}
