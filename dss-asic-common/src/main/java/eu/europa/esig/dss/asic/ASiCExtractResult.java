package eu.europa.esig.dss.asic;

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.DSSDocument;

public class ASiCExtractResult {

	private DSSDocument mimeTypeDocument;
	private List<DSSDocument> signatureDocuments = new ArrayList<DSSDocument>();
	private List<DSSDocument> manifestDocuments = new ArrayList<DSSDocument>();
	private List<DSSDocument> otherDocuments = new ArrayList<DSSDocument>();

	public DSSDocument getMimeTypeDocument() {
		return mimeTypeDocument;
	}

	public void setMimeTypeDocument(DSSDocument mimeTypeDocument) {
		this.mimeTypeDocument = mimeTypeDocument;
	}

	public List<DSSDocument> getSignatureDocuments() {
		return signatureDocuments;
	}

	public void setSignatureDocuments(List<DSSDocument> signatureDocuments) {
		this.signatureDocuments = signatureDocuments;
	}

	public List<DSSDocument> getManifestDocuments() {
		return manifestDocuments;
	}

	public void setManifestDocuments(List<DSSDocument> manifestDocuments) {
		this.manifestDocuments = manifestDocuments;
	}

	public List<DSSDocument> getOtherDocuments() {
		return otherDocuments;
	}

	public void setOtherDocuments(List<DSSDocument> otherDocuments) {
		this.otherDocuments = otherDocuments;
	}

}
