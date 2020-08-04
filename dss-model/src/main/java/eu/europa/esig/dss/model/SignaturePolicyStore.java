package eu.europa.esig.dss.model;

public class SignaturePolicyStore {

	/*
	 * Optional ID
	 */
	private String id;

	/*
	 * The SPDocSpecification element shall identify the technical specification
	 * that defines the syntax used for producing the signature policy document.
	 */
	private SpDocSpecification spDocSpecification;

	/*
	 * The SignaturePolicyDocument element shall contain the base-64 encoded
	 * signature policy.
	 */
	private DSSDocument signaturePolicyContent;

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public SpDocSpecification getSpDocSpecification() {
		return spDocSpecification;
	}

	public void setSpDocSpecification(SpDocSpecification spDocSpecification) {
		this.spDocSpecification = spDocSpecification;
	}

	public DSSDocument getSignaturePolicyContent() {
		return signaturePolicyContent;
	}

	public void setSignaturePolicyContent(DSSDocument signaturePolicyContent) {
		this.signaturePolicyContent = signaturePolicyContent;
	}

}
