package eu.europa.esig.dss.asic;

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.DSSDocument;

public final class OpenDocumentSupportUtils {

	private static final String EXTERNAL_DATA = "external-data/";

	private OpenDocumentSupportUtils() {
	}

	/**
	 * ODF 1.2 ch 3.16
	 * 
	 * An OpenDocument document that is stored in a package may have one or more
	 * digital signatures applied to the package.
	 * 
	 * Document signatures shall be stored in a file called
	 * META-INF/documentsignatures.xml in the package as described in section 3.5 of
	 * the OpenDocument specification part 3. Document signatures shall contain a
	 * {@code <ds:Reference>} element for each file within the package, with the
	 * exception that {@code <ds:Reference>} elements for the
	 * META-INF/documentsignatures.xml file containing the signature, and any files
	 * contained in the package whose relative path starts with "external-data/"
	 * should be omitted.
	 * 
	 * @return the list of covered documents
	 */
	public static List<DSSDocument> getOpenDocumentCoverage(ASiCExtractResult extractResult) {
		List<DSSDocument> docs = new ArrayList<DSSDocument>();
		docs.add(extractResult.getMimeTypeDocument());
		docs.addAll(extractResult.getSignedDocuments());
		docs.addAll(extractResult.getManifestDocuments());
		docs.addAll(extractResult.getArchiveManifestDocuments());
		docs.addAll(extractResult.getTimestampDocuments());
		docs.addAll(extractResult.getUnsupportedDocuments());

		List<DSSDocument> result = new ArrayList<>();
		for (DSSDocument doc : docs) {
			if (!doc.getName().startsWith(EXTERNAL_DATA)) {
				result.add(doc);
			}
		}

		return result;
	}
}
