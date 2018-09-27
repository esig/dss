package eu.europa.esig.dss.asic.signature.asice;

import java.util.List;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.asic.ASiCParameters;
import eu.europa.esig.dss.asic.ASiCUtils;
import eu.europa.esig.dss.asic.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.utils.Utils;

public abstract class AbstractDataToSignASiCEWithCAdES {

	private static final String META_INF = "META-INF/";
	private static final String ZIP_ENTRY_ASICE_METAINF_CADES_SIGNATURE = META_INF + "signature001.p7s";

	protected DSSDocument getASiCManifest(List<DSSDocument> documents, List<DSSDocument> signatures, List<DSSDocument> manifests,
			ASiCWithCAdESSignatureParameters parameters) {
		ASiCEWithCAdESManifestBuilder manifestBuilder = new ASiCEWithCAdESManifestBuilder(documents, parameters.getDigestAlgorithm(),
				getSignatureFileName(parameters.aSiC(), signatures));

		return DomUtils.createDssDocumentFromDomDocument(manifestBuilder.build(), getASiCManifestFilename(manifests));
	}

	protected String getSignatureFileName(final ASiCParameters asicParameters, List<DSSDocument> existingSignatures) {
		if (Utils.isStringNotBlank(asicParameters.getSignatureFileName())) {
			return META_INF + asicParameters.getSignatureFileName();
		}

		int num = Utils.collectionSize(existingSignatures) + 1;
		return ZIP_ENTRY_ASICE_METAINF_CADES_SIGNATURE.replace("001", ASiCUtils.getPadNumber(num));
	}

	private String getASiCManifestFilename(List<DSSDocument> existingManifests) {
		String suffix = Utils.isCollectionEmpty(existingManifests) ? Utils.EMPTY_STRING : String.valueOf(existingManifests.size());
		return META_INF + "ASiCManifest" + suffix + ".xml";
	}

}
