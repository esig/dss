package eu.europa.esig.dss.jades;

/**
 * Defines JSON headers for a JWS Signature (RFC 7515)
 */
public final class JWSConstants {
	
	private JWSConstants() {
	}

	/** The signed document */
	public static final String PAYLOAD = "payload";

	/** Array of signatures */
	public static final String SIGNATURES = "signatures";

	/** The signed properties */
	public static final String PROTECTED = "protected";

	/** The unsigned properties */
	public static final String HEADER = "header";

	/** The container for a SignatureValue */
	public static final String SIGNATURE = "signature";

}
