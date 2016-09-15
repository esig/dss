package eu.europa.esig.dss.validation.reports.wrapper;

import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.jaxb.diagnostic.XmlBasicSignature;
import eu.europa.esig.dss.jaxb.diagnostic.XmlChainItem;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignedObjects;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSigningCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTimestamp;

public class TimestampWrapper extends AbstractTokenProxy {

	private final XmlTimestamp timestamp;

	public TimestampWrapper(XmlTimestamp timestamp) {
		this.timestamp = timestamp;
	}

	@Override
	public String getId() {
		return timestamp.getId();
	}

	@Override
	protected XmlBasicSignature getCurrentBasicSignature() {
		return timestamp.getBasicSignature();
	}

	@Override
	protected List<XmlChainItem> getCurrentCertificateChain() {
		return timestamp.getCertificateChain();
	}

	@Override
	protected XmlSigningCertificate getCurrentSigningCertificate() {
		return timestamp.getSigningCertificate();
	}

	public String getType() {
		return timestamp.getType();
	}

	public Date getProductionTime() {
		return timestamp.getProductionTime();
	}

	public boolean isMessageImprintDataFound() {
		return timestamp.isMessageImprintDataFound();
	}

	public boolean isMessageImprintDataIntact() {
		return timestamp.isMessageImprintDataIntact();
	}

	public String getSignedDataDigestAlgo() {
		return timestamp.getSignedDataDigestAlgo();
	}

	public XmlSignedObjects getSignedObjects() {
		return timestamp.getSignedObjects();
	}

}
