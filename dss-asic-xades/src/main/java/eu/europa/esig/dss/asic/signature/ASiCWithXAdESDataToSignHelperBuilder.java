package eu.europa.esig.dss.asic.signature;

import java.util.List;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.asic.ASiCExtractResult;
import eu.europa.esig.dss.asic.ASiCUtils;
import eu.europa.esig.dss.asic.ASiCWithXAdESContainerExtractor;
import eu.europa.esig.dss.asic.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.signature.asice.DataToSignASiCEWithXAdESFromArchive;
import eu.europa.esig.dss.asic.signature.asice.DataToSignASiCEWithXAdESFromFiles;
import eu.europa.esig.dss.asic.signature.asics.DataToSignASiCSWithXAdESFromArchive;
import eu.europa.esig.dss.asic.signature.asics.DataToSignASiCSWithXAdESFromFiles;

public class ASiCWithXAdESDataToSignHelperBuilder {

	public static GetDataToSignASiCWithXAdESHelper getGetDataToSignHelper(List<DSSDocument> documents, ASiCWithXAdESSignatureParameters parameters) {

		boolean asice = ASiCUtils.isASiCE(parameters.aSiC());
		boolean archive = ASiCUtils.isArchive(documents);

		if (archive) {
			ASiCWithXAdESContainerExtractor extractor = new ASiCWithXAdESContainerExtractor(documents.get(0));
			ASiCExtractResult extract = extractor.extract();
			if (asice) {
				return new DataToSignASiCEWithXAdESFromArchive(extract.getSignedDocuments(), extract.getSignatureDocuments(), extract.getManifestDocuments(),
						parameters.aSiC());
			} else {
				return new DataToSignASiCSWithXAdESFromArchive(extract.getSignatureDocuments(), extract.getSignedDocuments(), parameters.aSiC());
			}
		} else {
			if (asice) {
				return new DataToSignASiCEWithXAdESFromFiles(documents, parameters.aSiC());
			} else {
				return new DataToSignASiCSWithXAdESFromFiles(documents, parameters.aSiC());
			}
		}
	}
}
