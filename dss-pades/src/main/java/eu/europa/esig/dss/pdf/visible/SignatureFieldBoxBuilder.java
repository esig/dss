package eu.europa.esig.dss.pdf.visible;

import java.io.IOException;

/**
 * Interface to build a {@code SignatureFieldBox}
 * The interface is used for a SignatureField position validation on a signature/timestamp/empty field creation
 *
 */
public interface SignatureFieldBoxBuilder {
	
	/**
	 * Builds a {@code SignatureFieldBox}, defining signature field position and dimension
	 * 
	 * @return {@link SignatureFieldBox}
	 * @throws IOException if an exception occurs
	 */
	SignatureFieldBox buildSignatureFieldBox() throws IOException;

}
