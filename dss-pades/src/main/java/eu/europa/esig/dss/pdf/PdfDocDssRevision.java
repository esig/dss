package eu.europa.esig.dss.pdf;

import java.util.List;
import java.util.Objects;

import eu.europa.esig.dss.validation.PdfRevision;
import eu.europa.esig.dss.validation.PdfSignatureDictionary;

/**
 * This class represents an LT-level PDF revision containing a DSS dictionary
 *
 */
public class PdfDocDssRevision implements PdfRevision {
	
	private final PdfDssDict dssDictionary;
	
	public PdfDocDssRevision(PdfDssDict dssDictionary) {
		Objects.requireNonNull(dssDictionary, "The dssDictionary cannot be null!");
		this.dssDictionary = dssDictionary;
	}

	/**
	 * Returns DSS dictionary
	 * 
	 * @return {@link PdfDssDict}
	 */
	public PdfDssDict getDssDictionary() {
		return dssDictionary;
	}

	@Override
	public PdfSignatureDictionary getPdfSigDictInfo() {
		// not applicable for DSS revision
		return null;
	}

	@Override
	public List<String> getFieldNames() {
		// not applicable for DSS revision
		return null;
	}

}
