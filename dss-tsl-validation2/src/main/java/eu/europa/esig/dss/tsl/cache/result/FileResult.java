package eu.europa.esig.dss.tsl.cache.result;

import java.util.Objects;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;

public class FileResult implements CachedResult {
	
	private static final DigestAlgorithm DEFAULT_DIGEST_ALGORITHM = DigestAlgorithm.SHA256;

	/**
	 * The file
	 */
	private final DSSDocument file;
	
	/**
	 * Base64 encoded digest of the file
	 */
	private String digest;
	
	/**
	 * The default constructor
	 * @param file {@link DSSDocument}
	 */
	FileResult(DSSDocument file) {
		Objects.requireNonNull(file, "file parameter cannot be null!");
		this.file = file;
	}
	
	/**
	 * Returns the stored file
	 * @return {@link DSSDocument}
	 */
	public DSSDocument getFile() {
		return file;
	}
	
	/**
	 * Returns string base64 digest of the file
	 * @return {@link String} base64 digest
	 */
	public String getBase64Digest() {
		return digest;
	}
	
	/**
	 * Sets base64 Digest for the file
	 * @param digest {@link String} base64 digest
	 */
	public void setBase64Digest(String digest) {
		this.digest = digest;
	}
	
}
