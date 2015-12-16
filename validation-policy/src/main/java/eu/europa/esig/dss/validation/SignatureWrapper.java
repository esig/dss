package eu.europa.esig.dss.validation;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;

import eu.europa.esig.dss.jaxb.diagnostic.XmlBasicSignatureType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificateChainType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertifiedRolesType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlClaimedRoles;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCommitmentTypeIndication;
import eu.europa.esig.dss.jaxb.diagnostic.XmlPolicy;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignature;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignatureScopes;
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
		if ((timestamps != null) && CollectionUtils.isNotEmpty(timestamps.getTimestamp())) {
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

	public boolean isSignatureProductionPlacePresent() {
		return signature.getSignatureProductionPlace() != null;
	}

	public String getAddress() {
		return signature.getSignatureProductionPlace().getAddress();
	}

	public String getCity() {
		return signature.getSignatureProductionPlace().getCity();
	}

	public String getCountryName() {
		return signature.getSignatureProductionPlace().getCountryName();
	}

	public String getPostalCode() {
		return signature.getSignatureProductionPlace().getPostalCode();
	}

	public String getStateOrProvince() {
		return signature.getSignatureProductionPlace().getStateOrProvince();
	}

	public String getSignatureFormat() {
		return signature.getSignatureFormat();
	}

	public String getErrorMessage() {
		return signature.getErrorMessage();
	}

	public boolean isSigningCertificateIdentified() {
		XmlSigningCertificateType signingCertificate = signature.getSigningCertificate();
		if (signingCertificate != null) {
			return signingCertificate.isDigestValueMatch() && signingCertificate.isIssuerSerialMatch();
		}
		return false;
	}

	public String getPolicyId() {
		XmlPolicy policy = signature.getPolicy();
		if (policy != null) {
			return policy.getId();
		}
		return StringUtils.EMPTY;
	}

	public boolean isBLevelTechnicallyValid() {
		return (signature.getBasicSignature() != null) && signature.getBasicSignature().isSignatureValid();
	}

	public boolean isThereXLevel() {
		List<TimestampWrapper> timestampLevelX = getTimestampLevelX();
		return CollectionUtils.isNotEmpty(timestampLevelX);
	}

	public boolean isXLevelTechnicallyValid() {
		List<TimestampWrapper> timestamps = getTimestampLevelX();
		return isTimestampValid(timestamps);
	}

	private List<TimestampWrapper> getTimestampLevelX() {
		List<TimestampWrapper> timestamps = getTimestampListByType(TimestampType.VALIDATION_DATA_REFSONLY_TIMESTAMP);
		timestamps.addAll(getTimestampListByType(TimestampType.VALIDATION_DATA_TIMESTAMP));
		return timestamps;
	}

	public boolean isThereALevel() {
		List<TimestampWrapper> timestampList = getArchiveTimestamps();
		return CollectionUtils.isNotEmpty(timestampList);
	}

	public boolean isALevelTechnicallyValid() {
		List<TimestampWrapper> timestampList = getArchiveTimestamps();
		return isTimestampValid(timestampList);
	}

	private List<TimestampWrapper> getArchiveTimestamps() {
		return getTimestampListByType(TimestampType.ARCHIVE_TIMESTAMP);
	}

	public boolean isThereTLevel() {
		List<TimestampWrapper> timestamps = getSignatureTimestamps();
		return CollectionUtils.isNotEmpty(timestamps);
	}

	public boolean isTLevelTechnicallyValid() {
		List<TimestampWrapper> timestampList = getSignatureTimestamps();
		return isTimestampValid(timestampList);
	}

	private List<TimestampWrapper> getSignatureTimestamps() {
		return getTimestampListByType(TimestampType.SIGNATURE_TIMESTAMP);
	}

	private boolean isTimestampValid(List<TimestampWrapper> timestampList) {
		for (final TimestampWrapper timestamp : timestampList) {
			final boolean signatureValid = timestamp.isSignatureValid();
			final boolean messageImprintIntact = timestamp.isMessageImprintDataIntact();
			if (signatureValid && messageImprintIntact) { // TODO correct ?  return true if at least 1 TSP OK
				return true;
			}
		}
		return false;
	}

	public List<String> getTimestampIdsList() {
		List<String> result = new ArrayList<String>();
		List<TimestampWrapper> timestamps = getTimestampList();
		if (CollectionUtils.isNotEmpty(timestamps)) {
			for (TimestampWrapper tsp : timestamps) {
				result.add(tsp.getId());
			}
		}
		return result;
	}

	public String getParentId() {
		return signature.getParentId();
	}

	public XmlSignatureScopes getSignatureScopes() {
		return signature.getSignatureScopes();
	}

	public List<String> getCertifiedRoles() {
		List<String> result = new ArrayList<String>();
		List<XmlCertifiedRolesType> certifiedRoles = signature.getCertifiedRoles();
		if (CollectionUtils.isNotEmpty(certifiedRoles)) {
			for (XmlCertifiedRolesType certifiedRole : certifiedRoles) {
				result.add(certifiedRole.getCertifiedRole());
			}
		}
		return result;
	}

	public List<String> getCommitmentTypeIdentifiers() {
		XmlCommitmentTypeIndication commitmentTypeIndication = signature.getCommitmentTypeIndication();
		if ((commitmentTypeIndication != null) && CollectionUtils.isNotEmpty(commitmentTypeIndication.getIdentifier())) {
			return commitmentTypeIndication.getIdentifier();
		}
		return Collections.emptyList();
	}

	public List<String> getClaimedRoles() {
		XmlClaimedRoles claimedRoles = signature.getClaimedRoles();
		if ((claimedRoles != null) && CollectionUtils.isNotEmpty(claimedRoles.getClaimedRole())) {
			return claimedRoles.getClaimedRole();
		}
		return Collections.emptyList();
	}

	public boolean isPolicyPresent() {
		return signature.getPolicy() != null;
	}

	public String getPolicyProcessingError() {
		XmlPolicy policy = signature.getPolicy();
		if (policy != null) {
			return policy.getProcessingError();
		}
		return StringUtils.EMPTY;
	}

	public boolean getPolicyStatus() {
		XmlPolicy policy = signature.getPolicy();
		if (policy != null) {
			return policy.isStatus();
		}
		return false;
	}

	public String getPolicyNotice() {
		XmlPolicy policy = signature.getPolicy();
		if (policy != null) {
			return policy.getNotice();
		}
		return StringUtils.EMPTY;
	}

	public String getPolicyUrl() {
		XmlPolicy policy = signature.getPolicy();
		if (policy != null) {
			return policy.getUrl();
		}
		return StringUtils.EMPTY;
	}

	public boolean isPolicyAsn1Processable() {
		XmlPolicy policy = signature.getPolicy();
		if (policy != null) {
			return policy.isAsn1Processable();
		}
		return false;
	}

	public boolean isPolicyIdentified() {
		XmlPolicy policy = signature.getPolicy();
		if (policy != null) {
			return policy.isIdentified();
		}
		return false;
	}

	public boolean isPolicyStatus() {
		XmlPolicy policy = signature.getPolicy();
		if (policy != null) {
			return policy.isStatus();
		}
		return false;
	}

}
