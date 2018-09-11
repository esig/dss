package eu.europa.esig.dss.pades;

/**
 * This enumeration is used to set the allowed level of permission for PDF modifications.
 * 
 * Refers to ISO 32000 DocMDP chapter
 */
public enum CertificationPermission {

	/**
	 * No changes to the document are permitted; any change to the document shall invalidate the signature.
	 */
	NO_CHANGE_PERMITTED(1),

	/**
	 * Permitted changes shall be filling in forms, instantiating page templates, and signing; other changes shall
	 * invalidate the signature.
	 */
	MINIMAL_CHANGES_PERMITTED(2),

	/**
	 * Permitted changes are the same as for 2, as well as annotation creation, deletion, and modification; other
	 * changes shall invalidate the signature.
	 */
	CHANGES_PERMITTED(3);

	private final int code;

	CertificationPermission(int code) {
		this.code = code;
	}

	public int getCode() {
		return code;
	}

}
