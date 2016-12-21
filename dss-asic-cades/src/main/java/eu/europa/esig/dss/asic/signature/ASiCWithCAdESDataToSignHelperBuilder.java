package eu.europa.esig.dss.asic.signature;

import java.util.List;

import eu.europa.esig.dss.BLevelParameters;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.asic.ASiCExtractResult;
import eu.europa.esig.dss.asic.ASiCUtils;
import eu.europa.esig.dss.asic.ASiCWithCAdESContainerExtractor;
import eu.europa.esig.dss.asic.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.signature.asice.DataToSignASiCEWithCAdESFromArchive;
import eu.europa.esig.dss.asic.signature.asice.DataToSignASiCEWithCAdESFromFiles;
import eu.europa.esig.dss.asic.signature.asics.DataToSignASiCSWithCAdESFromArchive;
import eu.europa.esig.dss.asic.signature.asics.DataToSignASiCSWithCAdESFromFiles;

public class ASiCWithCAdESDataToSignHelperBuilder {

	private ASiCWithCAdESDataToSignHelperBuilder() {
	}

	public static GetDataToSignASiCWithCAdESHelper getGetDataToSignHelper(List<DSSDocument> documents, ASiCWithCAdESSignatureParameters parameters) {

		BLevelParameters bLevel = parameters.bLevel();
		boolean asice = ASiCUtils.isASiCE(parameters.aSiC());
		boolean archive = ASiCUtils.isArchive(documents);

		if (archive) {
			DSSDocument archiveDoc = documents.get(0);
			if (!ASiCUtils.isArchiveContainsCorrectSignatureExtension(archiveDoc, ".p7s")) {
				throw new UnsupportedOperationException("Container type doesn't match");
			}

			ASiCWithCAdESContainerExtractor extractor = new ASiCWithCAdESContainerExtractor(archiveDoc);
			ASiCExtractResult extract = extractor.extract();
			if (asice) {
				return new DataToSignASiCEWithCAdESFromArchive(extract.getSignedDocuments(), extract.getSignatureDocuments(), extract.getManifestDocuments(),
						parameters);
			} else {
				return new DataToSignASiCSWithCAdESFromArchive(extract.getSignatureDocuments(), extract.getSignedDocuments(), parameters.aSiC());
			}
		} else {
			if (asice) {
				return new DataToSignASiCEWithCAdESFromFiles(documents, parameters);
			} else {
				return new DataToSignASiCSWithCAdESFromFiles(documents, bLevel.getSigningDate(), parameters.aSiC());
			}
		}
	}

}
