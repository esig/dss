package eu.europa.esig.dss.validation;

import java.util.Date;

/**
 * Contains PDF signature dictionary information
 * 
 */
public interface PdfSignatureDictionary {

	int[] getSignatureByteRange();

	String getSignerName();

	String getLocation();

	String getContactInfo();

	String getReason();
	
	String getType();

	String getFilter();

	String getSubFilter();
	
	byte[] getContents();

	Date getSigningDate();

}
