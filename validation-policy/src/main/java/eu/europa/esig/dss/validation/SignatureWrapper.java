package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.jaxb.diagnostic.XmlBasicSignatureType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificateChainType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignature;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSigningCertificateType;

public class SignatureWrapper extends AsbtractTokenProxy {

	private final XmlSignature signature;

	public SignatureWrapper(XmlSignature signature) {
		this.signature =signature;
	}

	@Override
	protected XmlBasicSignatureType getCurrentBasicSignature() {
		return signature.getBasicSignature();
	}

	@Override
	protected XmlCertificateChainType getCurrentCertificateChain() {
		return signature.getCertificateChain();
	}

	@Override
	protected XmlSigningCertificateType getCurrentSigningCertificate() {
		return signature.getSigningCertificate();
	}

	@Override
	public String getId() {
		return signature.getId();
	}

}
