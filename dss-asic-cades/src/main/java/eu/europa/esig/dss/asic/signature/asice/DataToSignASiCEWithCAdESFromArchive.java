package eu.europa.esig.dss.asic.signature.asice;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.asic.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.signature.GetDataToSignASiCWithCAdESHelper;

public class DataToSignASiCEWithCAdESFromArchive extends AbstractDataToSignASiCEWithCAdES implements GetDataToSignASiCWithCAdESHelper {

	private final List<DSSDocument> signedDocuments;
	private final List<DSSDocument> existingSignatures;
	private final List<DSSDocument> existingManifests;
	private final ASiCWithCAdESSignatureParameters parameters;

	private DSSDocument toBeSigned;

	public DataToSignASiCEWithCAdESFromArchive(List<DSSDocument> signedDocuments, List<DSSDocument> existingSignatures, List<DSSDocument> existingManifests,
			ASiCWithCAdESSignatureParameters parameters) {
		this.signedDocuments = signedDocuments;
		this.existingSignatures = existingSignatures;
		this.existingManifests = existingManifests;
		this.parameters = parameters;
	}

	@Override
	public String getSignatureFilename() {
		return getSignatureFileName(parameters.aSiC(), existingSignatures);
	}

	@Override
	public DSSDocument getToBeSigned() {
		if (toBeSigned == null) {
			toBeSigned = getASiCManifest(signedDocuments, existingSignatures, existingManifests, parameters);
		}
		return toBeSigned;
	}

	@Override
	public List<DSSDocument> getDetachedContents() {
		return Collections.emptyList();
	}

	@Override
	public List<DSSDocument> getSignedDocuments() {
		return signedDocuments;
	}

	@Override
	public List<DSSDocument> getManifestFiles() {
		List<DSSDocument> manifests = new ArrayList<DSSDocument>(existingManifests);
		manifests.add(getToBeSigned());
		return manifests;
	}

	@Override
	public List<DSSDocument> getSignatures() {
		return existingSignatures;
	}

}
