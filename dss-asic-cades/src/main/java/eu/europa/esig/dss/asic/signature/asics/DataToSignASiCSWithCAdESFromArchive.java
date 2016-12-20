package eu.europa.esig.dss.asic.signature.asics;

import java.util.Collections;
import java.util.List;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.asic.ASiCParameters;
import eu.europa.esig.dss.asic.signature.GetDataToSignASiCWithCAdESHelper;
import eu.europa.esig.dss.utils.Utils;

public class DataToSignASiCSWithCAdESFromArchive extends AbstractGetDataToSignASiCSWithCAdES implements GetDataToSignASiCWithCAdESHelper {

	private final List<DSSDocument> embeddedSignatures;
	private final List<DSSDocument> embeddedSignedFiles;
	private final ASiCParameters asicParameters;

	public DataToSignASiCSWithCAdESFromArchive(List<DSSDocument> embeddedSignatures, List<DSSDocument> embeddedSignedFiles, ASiCParameters asicParameters) {
		this.embeddedSignatures = embeddedSignatures;
		this.embeddedSignedFiles = embeddedSignedFiles;
		this.asicParameters = asicParameters;
	}

	@Override
	public String getSignatureFilename() {
		return getSignatureFileName(asicParameters);
	}

	@Override
	public DSSDocument getToBeSigned() {
		int nbEmbeddedSignatures = Utils.collectionSize(embeddedSignatures);
		if (nbEmbeddedSignatures != 1) {
			throw new DSSException("Unable to select the embedded signature (nb found:" + nbEmbeddedSignatures + ")");
		}
		return embeddedSignatures.get(0);
	}

	@Override
	public List<DSSDocument> getDetachedContents() {
		return getSignedDocuments();
	}

	@Override
	public List<DSSDocument> getSignedDocuments() {
		int nbSignedFiles = Utils.collectionSize(embeddedSignedFiles);
		if (nbSignedFiles != 1) {
			throw new DSSException("Unable to select the document to be signed (nb found:" + nbSignedFiles + ")");
		}
		return embeddedSignedFiles;
	}

	@Override
	public List<DSSDocument> getManifestFiles() {
		// No manifest file in ASiC-S
		return Collections.emptyList();
	}

	@Override
	public List<DSSDocument> getSignatures() {
		return embeddedSignatures;
	}

}
