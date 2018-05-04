package eu.europa.esig.dss.pades;

/**
 * This enumeration is used to set the allowed level of permission for PDF modifications.
 * 
 * Refers to ISO 32000 DocMDP chapter
 */
public enum CertificationPermission {

	/**
	 * Any change to the document shall invalidate the signature
	 */
	NO_CHANGE_PERMITTED(1),

	/**
	 * Allowed changes are : form filling, signing, page templating. Other changes shall invalidate the signature
	 */
	MINIMAL_CHANGES_PERMITTED(2),

	/**
	 * All changes are allowed like signing, page creation/deletion,...
	 */
	ALL_CHANGES_PERMITTED(3);

	private final int code;

	private CertificationPermission(int code) {
		this.code = code;
	}

	public int getCode() {
		return code;
	}

}
