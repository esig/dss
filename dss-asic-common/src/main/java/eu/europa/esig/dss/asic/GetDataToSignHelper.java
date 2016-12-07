package eu.europa.esig.dss.asic;

import java.util.List;

import eu.europa.esig.dss.DSSDocument;

public interface GetDataToSignHelper {

	String getSignatureFilename();

	DSSDocument getToBeSigned();

	List<DSSDocument> getDetachedContents();

	DSSDocument getExistingSignature();

	List<DSSDocument> getSignedDocuments();

	List<DSSDocument> getSignatures();

	List<DSSDocument> getManifestFiles();

}
