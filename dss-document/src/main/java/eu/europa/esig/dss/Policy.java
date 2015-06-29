package eu.europa.esig.dss;

import java.io.Serializable;

/**
 * This class allows to define the signature policy.
 */
public class Policy implements Serializable {

	private String id;

	private String description;

	private DigestAlgorithm digestAlgorithm;

	private byte[] digestValue;

	private String spuri;

	public Policy() {
	}

	/**
	 * Get the signature policy (EPES)
	 *
	 * @return
	 */
	public String getId() {
		return id;
	}

	/**
	 * Set the signature policy (EPES)
	 *
	 * @param id
	 */
	public void setId(final String id) {
		this.id = id;
	}

	/**
	 * Get the signature policy description
	 *
	 * @return the signature policy description
	 */
	public String getDescription() {
		return description;
	}

	/**
	 * Set the signature policy description
	 *
	 * @param description
	 */
	public void setDescription(String description) {
		this.description = description;
	}

	/**
	 * Return the hash algorithm for the signature policy
	 *
	 * @return
	 */
	public DigestAlgorithm getDigestAlgorithm() {
		return digestAlgorithm;
	}

	/**
	 * Set the hash algorithm for the explicit signature policy
	 *
	 * @param digestAlgorithm
	 */
	public void setDigestAlgorithm(final DigestAlgorithm digestAlgorithm) {
		this.digestAlgorithm = digestAlgorithm;
	}

	/**
	 * Get the hash value of the explicit signature policy
	 *
	 * @return
	 */
	public byte[] getDigestValue() {
		return digestValue;
	}

	/**
	 * Set the hash value of implicit signature policy
	 *
	 * @param digestValue
	 */
	public void setDigestValue(final byte[] digestValue) {
		this.digestValue = digestValue;
	}

	/**
	 * Get the SP URI (signature policy URI)
	 * @return the signature policy URI
	 */
	public String getSpuri() {
		return spuri;
	}

	/**
	 * Set the SP URI (signature policy URI)
	 * @param spuri
	 */
	public void setSpuri(String spuri) {
		this.spuri = spuri;
	}

}