package eu.europa.esig.dss.asic.signature.asics;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.asic.ASiCParameters;
import eu.europa.esig.dss.asic.signature.GetDataToSignASiCWithCAdESHelper;
import eu.europa.esig.dss.utils.Utils;

public class DataToSignASiCSWithCAdESFromFiles extends AbstractGetDataToSignASiCSWithCAdES implements GetDataToSignASiCWithCAdESHelper {

	private final List<DSSDocument> filesToBeSigned;
	private final Date signingDate;
	private final ASiCParameters asicParameters;

	private List<DSSDocument> signedDocuments;

	public DataToSignASiCSWithCAdESFromFiles(List<DSSDocument> filesToBeSigned, Date signingDate, ASiCParameters asicParameters) {
		this.filesToBeSigned = filesToBeSigned;
		this.signingDate = signingDate;
		this.asicParameters = asicParameters;
	}

	@Override
	public String getSignatureFilename() {
		return getSignatureFileName(asicParameters);
	}

	@Override
	public DSSDocument getToBeSigned() {
		return getSignedDocuments().get(0);
	}

	@Override
	public List<DSSDocument> getDetachedContents() {
		return Collections.emptyList();
	}

	@Override
	public List<DSSDocument> getSignedDocuments() {
		if (signedDocuments == null) {
			if (Utils.collectionSize(filesToBeSigned) > 1) {
				signedDocuments = Arrays.asList(createPackageZip(filesToBeSigned, signingDate));
			} else {
				signedDocuments = new ArrayList<DSSDocument>(filesToBeSigned);
			}
		}
		return signedDocuments;
	}

	@Override
	public List<DSSDocument> getManifestFiles() {
		// No manifest file in ASiC-S
		return Collections.emptyList();
	}

	@Override
	public List<DSSDocument> getSignatures() {
		// new container
		return new ArrayList<DSSDocument>();
	}

}
