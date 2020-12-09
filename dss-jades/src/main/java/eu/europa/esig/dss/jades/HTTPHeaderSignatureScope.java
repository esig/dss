package eu.europa.esig.dss.jades;

import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.validation.scope.SignatureScope;

/**
 * The signature scope used to define the signed payload with HTTPHeader SigD Mechanism
 */
public class HTTPHeaderSignatureScope extends SignatureScope {

	/**
	 * The default constructor
	 *
	 * @param digest {@link Digest} of the computed JWS Payload
	 */
	public HTTPHeaderSignatureScope(Digest digest) {
		this("HttpHeaders payload", digest);
	}

	/**
	 * Constructor with document name
	 *
	 * @param name {@link String} document name
	 * @param digest {@link Digest} of the document
	 */
	protected HTTPHeaderSignatureScope(String name, Digest digest) {
		super(name, digest);
	}

	@Override
	public String getDescription() {
		return "Payload value digest";
	}

	@Override
	public SignatureScopeType getType() {
		return SignatureScopeType.FULL;
	}

}
