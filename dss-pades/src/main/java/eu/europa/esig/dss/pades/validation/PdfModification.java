package eu.europa.esig.dss.pades.validation;

/**
 * This interface contains information about the occurred modifications in a PDF
 *
 */
public interface PdfModification {
	
	/**
	 * Returns a page where the modification occurs
	 * 
	 * @return page number
	 */
	int getPage();

}
