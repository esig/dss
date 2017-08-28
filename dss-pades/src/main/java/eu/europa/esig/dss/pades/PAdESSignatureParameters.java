package eu.europa.esig.dss.pades;

import eu.europa.esig.dss.SignatureForm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;

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
	private String signatureFilter;

	/**
	 * This attribute allows to override the used subFilter for a Signature.
	 * 
	 * Default value is ETSI.CAdES.detached
	 */
	private String signatureSubFilter;

	/**
	 * This attribute is used to create visible signature in PAdES form
	 */
	private SignatureImageParameters signatureImageParameters;

	/**
	 * This attribute allows to override the used Filter for a Timestamp.
	 * 
	 * Default value is Adobe.PPKLite
	 */
	private String timestampFilter;

	/**
	 * This attribute allows to override the used subFilter for a Timestamp.
	 * 
	 * Default value is ETSI.RFC3161
	 */
	private String timestampSubFilter;

	private SignatureImageParameters timestampImageParameters;

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

}