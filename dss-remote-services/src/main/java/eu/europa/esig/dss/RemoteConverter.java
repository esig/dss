package eu.europa.esig.dss;

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

}
