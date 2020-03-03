package eu.europa.esig.dss.pdf;

import java.io.Closeable;
import java.io.IOException;
import java.util.List;
import java.util.Map;

import eu.europa.esig.dss.validation.PdfSignatureDictionary;

public interface PdfDocumentReader extends Closeable {
	
	/**
	 * Loads the last DSS dictionary from the document if exists
	 * NOTE: can return null if DSS dictionary is not present
	 * 
	 * @return {@link PdfDssDict}
	 */
	PdfDssDict getDSSDictionary();
	
	/**
	 * Extracts PdfSignatureSictionaries present in the signature
	 * 
	 * @return a map between {@link PdfSignatureDictionary} and related field names
	 * @throws IOException if an exception occurs
	 */
	Map<PdfSignatureDictionary, List<String>> extractSigDictionaries() throws IOException;
	
	/**
	 * Checks if a signature for the given PDF Signature Sictionary covers the whole document
	 * 
	 * @param signatureDictionary {@link PdfSignatureDictionary} to check the result for
	 * @return TRUE if the signature covers the whole document, false otherwise
	 */
	boolean isSignatureCoversWholeDocument(PdfSignatureDictionary signatureDictionary);

}
