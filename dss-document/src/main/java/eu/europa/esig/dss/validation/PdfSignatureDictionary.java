package eu.europa.esig.dss.validation;

import java.util.Date;
import java.util.List;

/**
 * Contains PDF signature dictionary information
 * 
 */
public interface PdfSignatureDictionary {

	int[] getSignatureByteRange();
	
	/**
	 * Returns a list of signature field names
	 * 
	 * @return list of {@link String}s
	 */
	List<String> getSigFieldNames();

	String getSignerName();

	String getLocation();

	String getContactInfo();

	String getReason();
	
	String getType();

	String getFilter();

	String getSubFilter();

	Date getSigningDate();

}
