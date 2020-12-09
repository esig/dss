package eu.europa.esig.dss.pdf;

import eu.europa.esig.dss.pades.validation.PdfModification;

/**
 * The default PDF Modification object
 */
public class PdfModificationImpl implements PdfModification {

	/** Defines page of the found modification */
	private final int page;

	/**
	 * Default constructor
	 *
	 * @param page the modified page
	 */
	public PdfModificationImpl(int page) {
		this.page = page;
	}

	@Override
	public int getPage() {
		return page;
	}

}
