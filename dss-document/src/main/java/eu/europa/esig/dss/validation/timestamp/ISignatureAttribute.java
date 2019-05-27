package eu.europa.esig.dss.validation.timestamp;

/**
 * Defines a child of "signed-signature-properties" or "unsigned-signature-properties" element
 */
public interface ISignatureAttribute {

	/**
	 * Returns name of the object
	 * @return {@link String} name
	 */
	String getName();
	
}
