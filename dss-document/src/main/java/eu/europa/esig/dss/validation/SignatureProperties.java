package eu.europa.esig.dss.validation;

import java.util.List;

/**
 * Defined a "signed-signature-element" or "unsigned-signature-element" of a signature
 */
public interface SignatureProperties<UnsignedAttribute extends ISignatureAttribute> {
	
	/**
	 * Checks if "unsigned-signature-properties" exists and can be processed
	 * @return TRUE if the element exists, FALSE otherwise
	 */
	boolean isExist();
	
	/**
	 * Returns a list of children contained in the element
	 * @return list of {@link ISignatureAttribute}s
	 */
	List<UnsignedAttribute> getAttributes();

}
