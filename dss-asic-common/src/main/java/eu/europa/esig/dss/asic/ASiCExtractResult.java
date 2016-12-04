package eu.europa.esig.dss.asic;

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.DSSDocument;

public class ASiCExtractResult {

	private String zipComment;
	private DSSDocument mimeTypeDocument;
	private List<DSSDocument> signatureDocuments = new ArrayList<DSSDocument>();
	private List<DSSDocument> manifestDocuments = new ArrayList<DSSDocument>();
	private List<DSSDocument> signedDocuments = new ArrayList<DSSDocument>();
	private List<DSSDocument> unsupportedDocuments = new ArrayList<DSSDocument>();

	public String getZipComment() {
		return zipComment;
	}

	public void setZipComment(String zipComment) {
		this.zipComment = zipComment;
	}

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

	public List<DSSDocument> getSignedDocuments() {
		return signedDocuments;
	}

	public void setSignedDocuments(List<DSSDocument> signedDocuments) {
		this.signedDocuments = signedDocuments;
	}

	public List<DSSDocument> getUnsupportedDocuments() {
		return unsupportedDocuments;
	}

	public void setUnsupportedDocuments(List<DSSDocument> unsupportedDocuments) {
		this.unsupportedDocuments = unsupportedDocuments;
	}

}
