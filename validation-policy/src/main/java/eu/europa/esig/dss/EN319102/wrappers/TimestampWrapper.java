package eu.europa.esig.dss.EN319102.wrappers;

import java.util.Date;

import eu.europa.esig.dss.jaxb.diagnostic.XmlBasicSignatureType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificateChainType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignedObjectsType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSigningCertificateType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTimestampType;

public class TimestampWrapper extends AbstractTokenProxy {

	private final XmlTimestampType timestamp;

	public TimestampWrapper(XmlTimestampType timestamp) {
		this.timestamp = timestamp;
	}

	@Override
	public String getId() {
		return timestamp.getId();
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

	public XmlSignedObjectsType getSignedObjects() {
		return timestamp.getSignedObjects();
	}

}
