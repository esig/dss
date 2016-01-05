package eu.europa.esig.dss.validation;

import java.util.Date;

import org.apache.commons.lang.NotImplementedException;

import eu.europa.esig.dss.jaxb.diagnostic.XmlBasicSignatureType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificateChainType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlRevocationType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSigningCertificateType;

public class RevocationWrapper extends AbstractTokenProxy {

	private final XmlRevocationType revocation;

	public RevocationWrapper(XmlRevocationType revocation) {
		this.revocation = revocation;
	}

	@Override
	public String getId() {
		throw new NotImplementedException();
	}

	@Override
	protected XmlBasicSignatureType getCurrentBasicSignature() {
		return revocation.getBasicSignature();
	}

	@Override
	protected XmlCertificateChainType getCurrentCertificateChain() {
		return revocation.getCertificateChain();
	}

	@Override
	protected XmlSigningCertificateType getCurrentSigningCertificate() {
		return revocation.getSigningCertificate();
	}

	public Date getIssuingTime() {
		return revocation.getIssuingTime();
	}

	public boolean isStatus() {
		return revocation.isStatus();
	}

	public Date getNextUpdate() {
		return revocation.getNextUpdate();
	}

	public String getReason() {
		return revocation.getReason();
	}

	public Date getDateTime() {
		return revocation.getDateTime();
	}

	public String getSource() {
		return revocation.getSource();
	}

}
