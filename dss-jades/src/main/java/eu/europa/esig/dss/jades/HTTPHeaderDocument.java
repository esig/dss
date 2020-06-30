package eu.europa.esig.dss.jades;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.MimeType;

/**
 * The class represents an HTTP Header to be signed
 * See ETSI TS 119 182-1 "5.2.8.2 Mechanism HttpHeaders"
 * 
 * The class shall be used only for JAdES detached {@code SigDMechanism.HTTP_HEADERS} mechanism
 *
 */
@SuppressWarnings("serial")
public class HTTPHeaderDocument implements DSSDocument {
	
	private final String name;
	private final String value;
	
	/** The default constructor */
	public HTTPHeaderDocument(final String name, final String value) {
		this.name = name;
		this.value = value;
	}

	/**
	 * Returns a String name (key) of the HTTP Header
	 */
	@Override
	public String getName() {
		return name;
	}

	/**
	 * Returns a String value of the HTTP Header
	 * 
	 * @return {@link String} value
	 */
	public String getValue() {
		return value;
	}

	@Override
	public InputStream openStream() {
		throw new DSSException("The openStream() method is not supported for HTTPHeaderDocument.");
	}

	@Override
	public void writeTo(OutputStream stream) throws IOException {
		throw new DSSException("The writeTo(stream) method is not supported for HTTPHeaderDocument.");
	}

	@Override
	public void setName(String name) {
		throw new DSSException("The setName(name) method is not supported for HTTPHeaderDocument.");
	}

	@Override
	public String getAbsolutePath() {
		// not applicable
		return null;
	}

	@Override
	public MimeType getMimeType() {
		// not applicable
		return null;
	}

	@Override
	public void setMimeType(MimeType mimeType) {
		throw new DSSException("The setMimeType(mimeType) method is not supported for HTTPHeaderDocument.");
	}

	@Override
	public void save(String filePath) throws IOException {
		throw new DSSException("The save(filePath) method is not supported for HTTPHeaderDocument.");
	}

	@Override
	public String getDigest(DigestAlgorithm digestAlgorithm) {
		throw new DSSException("The getDigest(digestAlgorithm) method is not supported for HTTPHeaderDocument.");
	}

}
