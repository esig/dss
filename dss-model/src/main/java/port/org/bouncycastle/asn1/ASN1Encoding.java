package port.org.bouncycastle.asn1;

/**
 * Supported encoding formats.
 */
public interface ASN1Encoding {

	/**
	 * DER - distinguished encoding rules.
	 */
	String DER = "DER";

	/**
	 * DL - definite length encoding.
	 */
	String DL = "DL";

	/**
	 * BER - basic encoding rules.
	 */
	String BER = "BER";

}
