package eu.europa.esig.dss.asic.signature;

import java.util.List;

import eu.europa.esig.dss.DSSDocument;

public interface GetDataToSignHelper {

	String getSignatureFilename();

	List<DSSDocument> getSignedDocuments();

	List<DSSDocument> getSignatures();

	List<DSSDocument> getManifestFiles();

}
