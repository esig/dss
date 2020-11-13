package eu.europa.esig.dss.asic.common.signature;

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.utils.Utils;

public abstract class AbstractASiCDataToSignHelperBuilder {

	private static final String ZIP_ENTRY_DETACHED_FILE = "detached-file";
	
	/**
	 * Checks if the document names are defined and adds them if needed
	 * 
	 * @param documents a list of {@link DSSDocument}
	 */
	protected void assertDocumentNamesDefined(List<DSSDocument> documents) {
		List<DSSDocument> unnamedDocuments = getDocumentsWithoutNames(documents);
		if (unnamedDocuments.size() == 1) {
			DSSDocument dssDocument = unnamedDocuments.iterator().next();
			dssDocument.setName(ZIP_ENTRY_DETACHED_FILE);
		} else {
			for (int ii = 0; ii < unnamedDocuments.size(); ii++) {
				DSSDocument dssDocument = unnamedDocuments.get(ii);
				dssDocument.setName(ZIP_ENTRY_DETACHED_FILE + "-" + ii);
			}
		}
	}
	
	private List<DSSDocument> getDocumentsWithoutNames(List<DSSDocument> documents) {
		List<DSSDocument> result = new ArrayList<>();
		for (DSSDocument document : documents) {
			if (Utils.isStringBlank(document.getName())) {
				result.add(document);
			}
		}
		return result;
	}

}
