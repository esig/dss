package eu.europa.esig.dss.pdf.openpdf;

import eu.europa.esig.dss.pdf.PdfMemoryUsageSetting;

/**
 * IText memory usage setting
 */
public class ITextPdfMemoryUsageSetting {

	/**
	 * Load options
	 */
	public enum Mode {
		FULL, PARTIAL
	}

	private Mode mode;

	public ITextPdfMemoryUsageSetting(Mode mode) {
		this.mode = mode;
	}

	/**
	 * 
	 * @return Load option {@link Mode}
	 */
	public Mode getMode() {
		return mode;
	}

	/**
	 * It converts generic {@link PdfMemoryUsageSetting} to IText domain
	 * 
	 * @param pdfMemoryUsageSetting
	 * @return {@link ITextPdfMemoryUsageSetting}
	 */
	public static ITextPdfMemoryUsageSetting map(PdfMemoryUsageSetting pdfMemoryUsageSetting) {
		Mode mode = PdfMemoryUsageSetting.Mode.MEMORY.equals(pdfMemoryUsageSetting.getMode()) ? Mode.FULL : Mode.PARTIAL;
		return new ITextPdfMemoryUsageSetting(mode);
	}
}
