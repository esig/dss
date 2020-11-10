package eu.europa.esig.dss.pdf;

import eu.europa.esig.dss.pades.validation.PdfModification;

public class PdfModificationImpl implements PdfModification {
	
	private final int page;
	
	public PdfModificationImpl(int page) {
		this.page = page;
	}

	@Override
	public int getPage() {
		return page;
	}

}
