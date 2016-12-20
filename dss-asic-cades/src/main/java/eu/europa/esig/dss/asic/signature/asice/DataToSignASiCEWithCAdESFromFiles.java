package eu.europa.esig.dss.asic.signature.asice;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.asic.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.signature.GetDataToSignASiCWithCAdESHelper;

public class DataToSignASiCEWithCAdESFromFiles extends AbstractDataToSignASiCEWithCAdES implements GetDataToSignASiCWithCAdESHelper {

	private final List<DSSDocument> filesToBeSigned;
	private final ASiCWithCAdESSignatureParameters parameters;

	private DSSDocument toBeSigned;

	public DataToSignASiCEWithCAdESFromFiles(List<DSSDocument> filesToBeSigned, ASiCWithCAdESSignatureParameters parameters) {
		this.filesToBeSigned = filesToBeSigned;
		this.parameters = parameters;
	}

	@Override
	public DSSDocument getToBeSigned() {
		if (toBeSigned == null) {
			toBeSigned = getASiCManifest(filesToBeSigned, Collections.<DSSDocument> emptyList(), Collections.<DSSDocument> emptyList(), parameters);
		}
		return toBeSigned;
	}

	@Override
	public List<DSSDocument> getDetachedContents() {
		return Collections.emptyList();
	}

	@Override
	public String getSignatureFilename() {
		return getSignatureFileName(parameters.aSiC(), Collections.<DSSDocument> emptyList());
	}

	@Override
	public List<DSSDocument> getSignedDocuments() {
		return filesToBeSigned;
	}

	@Override
	public List<DSSDocument> getManifestFiles() {
		return Arrays.asList(getToBeSigned());
	}

	@Override
	public List<DSSDocument> getSignatures() {
		return new ArrayList<DSSDocument>();
	}

}
