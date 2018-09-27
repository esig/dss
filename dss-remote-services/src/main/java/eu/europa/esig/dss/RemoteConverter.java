package eu.europa.esig.dss;

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.utils.Utils;

public class RemoteConverter {

	private RemoteConverter() {
	}

	public static DSSDocument toDSSDocument(RemoteDocument remoteDocument) {
		if (remoteDocument.getDigestAlgorithm() != null) {
			DigestDocument digestDocument = new DigestDocument();
			digestDocument.addDigest(remoteDocument.getDigestAlgorithm(), Utils.toBase64(remoteDocument.getBytes()));
			digestDocument.setName(remoteDocument.getName());
			digestDocument.setMimeType(remoteDocument.getMimeType());
			return digestDocument;
		} else {
			return new InMemoryDocument(remoteDocument.getBytes(), remoteDocument.getName(), remoteDocument.getMimeType());
		}
	}

	public static List<RemoteDocument> toRemoteDocuments(List<DSSDocument> originalDocuments) {
		List<RemoteDocument> results = new ArrayList<RemoteDocument>();
		for (DSSDocument originalDocument : originalDocuments) {
			results.add(toRemoteDocument(originalDocument));
		}
		return results;
	}

	public static RemoteDocument toRemoteDocument(DSSDocument originalDocument) {
		return new RemoteDocument(DSSUtils.toByteArray(originalDocument), originalDocument.getMimeType(), originalDocument.getName());
	}

}
