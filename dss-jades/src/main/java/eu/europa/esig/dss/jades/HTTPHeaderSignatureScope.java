package eu.europa.esig.dss.jades;

import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.validation.scope.SignatureScope;

public class HTTPHeaderSignatureScope extends SignatureScope {

	public HTTPHeaderSignatureScope(Digest digest) {
		this("HttpHeaders payload", digest);
	}
	
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
