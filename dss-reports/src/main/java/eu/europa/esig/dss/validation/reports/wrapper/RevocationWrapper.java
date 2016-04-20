package eu.europa.esig.dss.validation.reports.wrapper;

import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.jaxb.diagnostic.XmlBasicSignatureType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificateChainType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlDigestAlgAndValueType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlRevocationType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSigningCertificateType;

public class RevocationWrapper extends AbstractTokenProxy {

	private final XmlRevocationType revocation;

	public RevocationWrapper(XmlRevocationType revocation) {
		this.revocation = revocation;
	}

	@Override
	public String getId() {
		return revocation.getId();
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

	public Date getProductionDate() {
		return revocation.getProductionDate();
	}

	public boolean isStatus() {
		return revocation.isStatus();
	}

	public boolean isAvailable() {
		return revocation.isAvailable();
	}

	public Date getThisUpdate() {
		return revocation.getThisUpdate();
	}

	public Date getNextUpdate() {
		return revocation.getNextUpdate();
	}

	public String getReason() {
		return revocation.getReason();
	}

	public Date getRevocationDate() {
		return revocation.getRevocationDate();
	}

	public String getSource() {
		return revocation.getSource();
	}

	public List<XmlDigestAlgAndValueType> getDigestAlgAndValue() {
		return revocation.getDigestAlgAndValue();
	}

}
