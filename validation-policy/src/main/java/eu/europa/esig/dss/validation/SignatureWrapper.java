package eu.europa.esig.dss.validation;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;

import eu.europa.esig.dss.jaxb.diagnostic.XmlBasicSignatureType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificateChainType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignature;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSigningCertificateType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlStructuralValidationType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTimestampType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTimestamps;
import eu.europa.esig.dss.x509.TimestampType;

public class SignatureWrapper extends AsbtractTokenProxy {

	private final XmlSignature signature;

	public SignatureWrapper(XmlSignature signature) {
		this.signature = signature;
	}

	@Override
	public String getId() {
		return signature.getId();
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

	public boolean isStructuralValidationValid() {
		return (signature.getStructuralValidation() != null) && signature.getStructuralValidation().isValid();
	}

	public String getStructuralValidationMessage() {
		XmlStructuralValidationType structuralValidation = signature.getStructuralValidation();
		if (structuralValidation != null) {
			return structuralValidation.getMessage();
		}
		return StringUtils.EMPTY;
	}

	public Date getDateTime() {
		return signature.getDateTime();
	}

	public String getContentType() {
		return signature.getContentType();
	}

	public String getContentHints() {
		return signature.getContentHints();
	}

	public String getContentIdentifier() {
		return signature.getContentIdentifier();
	}

	public String getType() {
		return signature.getType();
	}

	public List<TimestampWrapper> getTimestampList() {
		List<TimestampWrapper> tsps = new ArrayList<TimestampWrapper>();
		XmlTimestamps timestamps = signature.getTimestamps();
		if ((timestamps.getTimestamp() != null) && CollectionUtils.isNotEmpty(timestamps.getTimestamp())) {
			for (XmlTimestampType timestamp : timestamps.getTimestamp()) {
				tsps.add(new TimestampWrapper(timestamp));
			}
		}
		return tsps;
	}

	public List<TimestampWrapper> getTimestampListByType(final TimestampType timestampType) {
		List<TimestampWrapper> result = new ArrayList<TimestampWrapper>();
		List<TimestampWrapper> all = getTimestampList();
		for (TimestampWrapper tsp : all) {
			if (timestampType.name().equals(tsp.getType())) {
				result.add(tsp);
			}
		}
		return result;
	}

}
