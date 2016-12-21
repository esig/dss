package eu.europa.esig.dss.validation;

import java.util.List;

import eu.europa.esig.dss.ASiCContainerType;

public class ContainerInfo {

	private ASiCContainerType containerType;
	private String zipComment;
	private boolean mimeTypeFilePresent;
	private String mimeTypeContent;

	private List<String> signedDocumentFilenames;
	private List<ManifestFile> manifestFiles;

	public ASiCContainerType getContainerType() {
		return containerType;
	}

	public void setContainerType(ASiCContainerType containerType) {
		this.containerType = containerType;
	}

	public String getZipComment() {
		return zipComment;
	}

	public void setZipComment(String zipComment) {
		this.zipComment = zipComment;
	}

	public boolean isMimeTypeFilePresent() {
		return mimeTypeFilePresent;
	}

	public void setMimeTypeFilePresent(boolean mimeTypeFilePresent) {
		this.mimeTypeFilePresent = mimeTypeFilePresent;
	}

	public String getMimeTypeContent() {
		return mimeTypeContent;
	}

	public void setMimeTypeContent(String mimeTypeContent) {
		this.mimeTypeContent = mimeTypeContent;
	}

	public List<String> getSignedDocumentFilenames() {
		return signedDocumentFilenames;
	}

	public void setSignedDocumentFilenames(List<String> signedDocumentFilenames) {
		this.signedDocumentFilenames = signedDocumentFilenames;
	}

	public List<ManifestFile> getManifestFiles() {
		return manifestFiles;
	}

	public void setManifestFiles(List<ManifestFile> manifestFiles) {
		this.manifestFiles = manifestFiles;
	}

}
