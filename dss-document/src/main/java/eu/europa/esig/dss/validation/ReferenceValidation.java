package eu.europa.esig.dss.validation;

import java.io.Serializable;

import eu.europa.esig.dss.Digest;

/**
 * This class is used to store individual reference validations.
 * 
 * For XAdES, that means reference tag(s) validation
 * 
 * For CAdES, that means message-digest validation
 *
 */
public class ReferenceValidation implements Serializable {

	private static final long serialVersionUID = 1L;

	private DigestMatcherType type;

	/* The pointed reference is found */
	private boolean found;
	/* The pointed reference is intact */
	private boolean intact;
	/* The embed digest value */
	private Digest digest;

	/* For XAdES : reference name/id */
	private String name;

	public DigestMatcherType getType() {
		return type;
	}

	public void setType(DigestMatcherType type) {
		this.type = type;
	}

	public boolean isFound() {
		return found;
	}

	public void setFound(boolean found) {
		this.found = found;
	}

	public boolean isIntact() {
		return intact;
	}

	public void setIntact(boolean intact) {
		this.intact = intact;
	}

	public Digest getDigest() {
		return digest;
	}

	public void setDigest(Digest digest) {
		this.digest = digest;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

}