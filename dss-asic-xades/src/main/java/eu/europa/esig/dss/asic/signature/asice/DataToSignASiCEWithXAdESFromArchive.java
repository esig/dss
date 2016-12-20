package eu.europa.esig.dss.asic.signature.asice;

import java.util.List;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.asic.ASiCParameters;
import eu.europa.esig.dss.asic.signature.GetDataToSignASiCWithXAdESHelper;

public class DataToSignASiCEWithXAdESFromArchive extends AbstractDataToSignASiCEWithXAdES implements GetDataToSignASiCWithXAdESHelper {

	private final List<DSSDocument> signedDocuments;
	private final List<DSSDocument> existingSignatures;
	private final List<DSSDocument> existingManifests;
	private final ASiCParameters asicParameters;

	public DataToSignASiCEWithXAdESFromArchive(List<DSSDocument> signedDocuments, List<DSSDocument> existingSignatures, List<DSSDocument> existingManifests,
			ASiCParameters asicParameters) {
		this.signedDocuments = signedDocuments;
		this.existingSignatures = existingSignatures;
		this.existingManifests = existingManifests;
		this.asicParameters = asicParameters;
	}

	@Override
	public String getSignatureFilename() {
		return getSignatureFileName(asicParameters, existingSignatures);
	}

	@Override
	public List<DSSDocument> getToBeSigned() {
		return signedDocuments;
	}

	@Override
	public DSSDocument getExistingSignature() {
		return null;
	}

	@Override
	public List<DSSDocument> getSignedDocuments() {
		return signedDocuments;
	}

	@Override
	public List<DSSDocument> getManifestFiles() {
		return existingManifests;
	}

	@Override
	public List<DSSDocument> getSignatures() {
		return existingSignatures;
	}

}
