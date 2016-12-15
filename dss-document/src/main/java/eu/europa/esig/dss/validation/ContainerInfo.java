package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.ASiCContainerType;

public class ContainerInfo {

	private ASiCContainerType containerType;
	private String zipComment;
	private boolean mimeTypeFilePresent;
	private String mimeTypeContent;

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

}
