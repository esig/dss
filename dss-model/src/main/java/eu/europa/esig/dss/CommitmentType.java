package eu.europa.esig.dss;

/**
 * Defined in ETSI TS 119 172-1 Annex B
 */
public enum CommitmentType {

	/**
	 * It indicates that the signer recognizes to have created, approved and sent the signed data.
	 */
	ProofOfOrigin("http://uri.etsi.org/01903/v1.2.2#ProofOfOrigin", "1.2.840.113549.1.9.16.6.1"),

	/**
	 * It indicates that signer recognizes to have received the content of the signed data.
	 */
	ProofOfReceipt("http://uri.etsi.org/01903/v1.2.2#ProofOfReceipt", "1.2.840.113549.1.9.16.6.2"),

	/**
	 * It indicates that the TSP providing that indication has delivered a signed data in a local store accessible to
	 * the recipient of the signed data.
	 */
	ProofOfDelivery("http://uri.etsi.org/01903/v1.2.2#ProofOfDelivery", "1.2.840.113549.1.9.16.6.3"),

	/**
	 * It indicates that the entity providing that indication has sent the signed data (but not necessarily created it).
	 */
	ProofOfSender("http://uri.etsi.org/01903/v1.2.2#ProofOfSender", "1.2.840.113549.1.9.16.6.4"),

	/**
	 * It indicates that the signer has approved the content of the signed data.
	 */
	ProofOfApproval("http://uri.etsi.org/01903/v1.2.2#ProofOfApproval", "1.2.840.113549.1.9.16.6.5"),

	/**
	 * It indicates that the signer has created the signed data (but not necessarily approved, nor sent it).
	 */
	ProofOfCreation("http://uri.etsi.org/01903/v1.2.2#ProofOfCreation", "1.2.840.113549.1.9.16.6.6");

	/**
	 * XML URI (XAdES)
	 */
	private final String uri;

	/**
	 * Object Identifier (CAdES)
	 */
	private final String oid;

	CommitmentType(String uri, String oid) {
		this.uri = uri;
		this.oid = oid;
	}

	public String getUri() {
		return uri;
	}

	public String getOid() {
		return oid;
	}

}
