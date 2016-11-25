package eu.europa.esig.dss.asic.validation;

public class ContainerAnalysis {

	private boolean zipFile;
	private boolean mimetypeFilePresent;
	private int nbSignatureFiles;
	private int nbManifestFiles;
	private int nbDataFiles;
	private String zipComment;

	public boolean isZipFile() {
		return zipFile;
	}

	public void setZipFile(boolean zipFile) {
		this.zipFile = zipFile;
	}

	public boolean isMimetypeFilePresent() {
		return mimetypeFilePresent;
	}

	public void setMimetypeFilePresent(boolean mimetypeFilePresent) {
		this.mimetypeFilePresent = mimetypeFilePresent;
	}

	public int getNbSignatureFiles() {
		return nbSignatureFiles;
	}

	public void setNbSignatureFiles(int nbSignatureFiles) {
		this.nbSignatureFiles = nbSignatureFiles;
	}

	public int getNbManifestFiles() {
		return nbManifestFiles;
	}

	public void setNbManifestFiles(int nbManifestFiles) {
		this.nbManifestFiles = nbManifestFiles;
	}

	public int getNbDataFiles() {
		return nbDataFiles;
	}

	public void setNbDataFiles(int nbDataFiles) {
		this.nbDataFiles = nbDataFiles;
	}

	public String getZipComment() {
		return zipComment;
	}

	public void setZipComment(String zipComment) {
		this.zipComment = zipComment;
	}

}
