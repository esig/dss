package eu.europa.esig.dss.asic.signature.asice;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.asic.ASiCParameters;
import eu.europa.esig.dss.asic.signature.GetDataToSignASiCWithXAdESHelper;

public class DataToSignASiCEWithXAdESFromFiles extends AbstractDataToSignASiCEWithXAdES implements GetDataToSignASiCWithXAdESHelper {

	private final List<DSSDocument> filesToBeSigned;
	private final ASiCParameters asicParameters;

	public DataToSignASiCEWithXAdESFromFiles(List<DSSDocument> filesToBeSigned, ASiCParameters asicParameters) {
		this.filesToBeSigned = filesToBeSigned;
		this.asicParameters = asicParameters;
	}

	@Override
	public List<DSSDocument> getToBeSigned() {
		return filesToBeSigned;
	}

	@Override
	public String getSignatureFilename() {
		return getSignatureFileName(asicParameters, Collections.<DSSDocument> emptyList());
	}

	@Override
	public List<DSSDocument> getSignedDocuments() {
		return filesToBeSigned;
	}

	@Override
	public DSSDocument getExistingSignature() {
		return null;
	}

	@Override
	public List<DSSDocument> getManifestFiles() {
		return Arrays.asList(getASiCManifest(filesToBeSigned));
	}

	@Override
	public List<DSSDocument> getSignatures() {
		// new container
		return new ArrayList<DSSDocument>();
	}

}
