package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.jaxb.diagnostic.XmlBasicSignatureType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificateChainType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSigningCertificateType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTimestampType;

public class TimestampWrapper extends AsbtractTokenProxy {

	private final XmlTimestampType timestamp;

	public TimestampWrapper(XmlTimestampType timestamp) {
		this.timestamp = timestamp;
	}

	@Override
	protected XmlBasicSignatureType getCurrentBasicSignature() {
		return timestamp.getBasicSignature();
	}

	@Override
	protected XmlCertificateChainType getCurrentCertificateChain() {
		return timestamp.getCertificateChain();
	}

	@Override
	protected XmlSigningCertificateType getCurrentSigningCertificate() {
		return timestamp.getSigningCertificate();
	}

	@Override
	public String getId() {
		return timestamp.getId();
	}

}
