package eu.europa.esig.dss.asic.signature;

import java.util.List;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.asic.ASiCExtractResult;
import eu.europa.esig.dss.asic.ASiCUtils;
import eu.europa.esig.dss.asic.ASiCWithCAdESContainerExtractor;
import eu.europa.esig.dss.asic.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.GetDataToSignHelper;
import eu.europa.esig.dss.asic.signature.asice.DataToSignASiCEWithCAdESFromArchive;
import eu.europa.esig.dss.asic.signature.asice.DataToSignASiCEWithCAdESFromFiles;
import eu.europa.esig.dss.asic.signature.asics.DataToSignASiCSWithCAdESFromArchive;
import eu.europa.esig.dss.asic.signature.asics.DataToSignASiCSWithCAdESFromFiles;

public class ASiCWithCAdESDataToSignHelperBuilder {

	public static GetDataToSignHelper getGetDataToSignHelper(List<DSSDocument> documents, ASiCWithCAdESSignatureParameters parameters) {

		boolean asice = ASiCUtils.isASiCE(parameters.aSiC());
		boolean archive = ASiCUtils.isArchive(documents);

		if (archive) {
			ASiCWithCAdESContainerExtractor extractor = new ASiCWithCAdESContainerExtractor(documents.get(0));
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
				return new DataToSignASiCSWithCAdESFromFiles(documents, parameters.aSiC());
			}
		}
	}

}
