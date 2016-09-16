package eu.europa.esig.dss.validation.reports.wrapper;

import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.jaxb.diagnostic.XmlBasicSignature;
import eu.europa.esig.dss.jaxb.diagnostic.XmlChainItem;
import eu.europa.esig.dss.jaxb.diagnostic.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.jaxb.diagnostic.XmlRevocation;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSigningCertificate;
import eu.europa.esig.dss.utils.Utils;

public class RevocationWrapper extends AbstractTokenProxy {

	private final XmlRevocation revocation;

	public RevocationWrapper(XmlRevocation revocation) {
		this.revocation = revocation;
	}

	@Override
	public String getId() {
		return revocation.getId();
	}

	@Override
	protected XmlBasicSignature getCurrentBasicSignature() {
		return revocation.getBasicSignature();
	}

	@Override
	protected List<XmlChainItem> getCurrentCertificateChain() {
		return revocation.getCertificateChain();
	}

	@Override
	protected XmlSigningCertificate getCurrentSigningCertificate() {
		return revocation.getSigningCertificate();
	}

	public Date getProductionDate() {
		return revocation.getProductionDate();
	}

	public boolean isStatus() {
		return Utils.isTrue(revocation.isStatus());
	}

	public boolean isAvailable() {
		return Utils.isTrue(revocation.isAvailable());
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

	public Date getExpiredCertsOnCRL() {
		return revocation.getExpiredCertsOnCRL();
	}

	public Date getArchiveCutOff() {
		return revocation.getArchiveCutOff();
	}

	public String getSource() {
		return revocation.getSource();
	}

	public String getOrigin() {
		return revocation.getOrigin();
	}

	public List<XmlDigestAlgoAndValue> getDigestAlgoAndValues() {
		return revocation.getDigestAlgoAndValues();
	}

}
