package eu.europa.esig.dss.asic.signature.asice;

import java.io.ByteArrayOutputStream;
import java.util.List;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.asic.ASiCParameters;
import eu.europa.esig.dss.asic.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.utils.Utils;

public abstract class AbstractDataToSignASiCEWithCAdES {

	private static final String META_INF = "META-INF/";
	private static final String ZIP_ENTRY_ASICE_METAINF_CADES_SIGNATURE = META_INF + "signature001.p7s";

	protected DSSDocument getASiCManifest(List<DSSDocument> documents, List<DSSDocument> signatures, List<DSSDocument> manifests,
			ASiCWithCAdESSignatureParameters parameters) {
		ASiCEWithCAdESManifestBuilder manifestBuilder = new ASiCEWithCAdESManifestBuilder(documents, parameters.getDigestAlgorithm(),
				getSignatureFileName(parameters.aSiC(), signatures));

		DSSDocument manifest = null;
		ByteArrayOutputStream baos = null;
		try {
			baos = new ByteArrayOutputStream();
			DomUtils.writeDocumentTo(manifestBuilder.build(), baos);
			String name = getASiCManifestFilename(manifests);
			manifest = new InMemoryDocument(baos.toByteArray(), name, MimeType.XML);
		} finally {
			Utils.closeQuietly(baos);
		}
		return manifest;
	}

	protected String getSignatureFileName(final ASiCParameters asicParameters, List<DSSDocument> existingSignatures) {
		if (Utils.isStringNotBlank(asicParameters.getSignatureFileName())) {
			return META_INF + asicParameters.getSignatureFileName();
		}
		if (Utils.isCollectionNotEmpty(existingSignatures)) {
			return ZIP_ENTRY_ASICE_METAINF_CADES_SIGNATURE.replace("001", getSignatureNumber(existingSignatures));
		} else {
			return ZIP_ENTRY_ASICE_METAINF_CADES_SIGNATURE;
		}
	}

	private String getSignatureNumber(List<DSSDocument> existingSignatures) {
		int signatureNumbre = existingSignatures.size() + 1;
		String sigNumberStr = String.valueOf(signatureNumbre);
		String zeroPad = "000";
		return zeroPad.substring(sigNumberStr.length()) + sigNumberStr; // 2 -> 002
	}

	private String getASiCManifestFilename(List<DSSDocument> existingManifests) {
		String suffix = Utils.isCollectionEmpty(existingManifests) ? Utils.EMPTY_STRING : String.valueOf(existingManifests.size());
		return META_INF + "ASiCManifest" + suffix + ".xml";
	}

}
