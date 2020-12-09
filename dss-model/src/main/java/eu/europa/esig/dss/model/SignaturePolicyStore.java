package eu.europa.esig.dss.model;

/**
 * Represents the SignaturePolicyStore
 */
public class SignaturePolicyStore {

	/**
	 * Optional ID
	 */
	private String id;
	
	/**
	 * The SPDocSpecification element shall identify the technical specification
	 * that defines the syntax used for producing the signature policy document.
	 */
	private SpDocSpecification spDocSpecification;

	/**
	 * The SignaturePolicyDocument element shall contain the base-64 encoded
	 * signature policy.
	 */
	private DSSDocument signaturePolicyContent;

	/**
	 * Get Id (optional)
	 * 
	 * @return {@link String}
	 */
	public String getId() {
		return id;
	}

	/**
	 * Set Id (optional)
	 * 
	 * @param id {@link String}
	 */
	public void setId(String id) {
		this.id = id;
	}
	
	/**
	 * Get {@code SpDocSpecification} content
	 * 
	 * @return {@link SpDocSpecification}
	 */
	public SpDocSpecification getSpDocSpecification() {
		return spDocSpecification;
	}

	/**
	 * Set {@code SpDocSpecification}
	 * 
	 * @param spDocSpecification {@link SpDocSpecification}
	 */
	public void setSpDocSpecification(SpDocSpecification spDocSpecification) {
		this.spDocSpecification = spDocSpecification;
	}

	/**
	 * Get policy store content
	 * 
	 * @return {@link DSSDocument}
	 */
	public DSSDocument getSignaturePolicyContent() {
		return signaturePolicyContent;
	}

	/**
	 * Set policy store content
	 * 
	 * @param signaturePolicyContent {@link DSSDocument}
	 */
	public void setSignaturePolicyContent(DSSDocument signaturePolicyContent) {
		this.signaturePolicyContent = signaturePolicyContent;
	}

}
