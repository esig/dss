package eu.europa.esig.dss.validation.reports.wrapper;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import eu.europa.esig.dss.jaxb.diagnostic.XmlBasicSignature;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertifiedRole;
import eu.europa.esig.dss.jaxb.diagnostic.XmlChainItem;
import eu.europa.esig.dss.jaxb.diagnostic.XmlPolicy;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignature;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignatureScope;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSigningCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlStructuralValidation;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTimestamp;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.TimestampType;

public class SignatureWrapper extends AbstractTokenProxy {

	private final XmlSignature signature;

	public SignatureWrapper(XmlSignature signature) {
		this.signature = signature;
	}

	@Override
	public String getId() {
		return signature.getId();
	}

	@Override
	protected XmlBasicSignature getCurrentBasicSignature() {
		return signature.getBasicSignature();
	}

	@Override
	protected List<XmlChainItem> getCurrentCertificateChain() {
		return signature.getCertificateChain();
	}

	@Override
	protected XmlSigningCertificate getCurrentSigningCertificate() {
		return signature.getSigningCertificate();
	}

	public String getSignatureFilename() {
		return signature.getSignatureFilename();
	}

	public boolean isStructuralValidationValid() {
		return (signature.getStructuralValidation() != null) && signature.getStructuralValidation().isValid();
	}

	public String getStructuralValidationMessage() {
		XmlStructuralValidation structuralValidation = signature.getStructuralValidation();
		if (structuralValidation != null) {
			return structuralValidation.getMessage();
		}
		return Utils.EMPTY_STRING;
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
		List<XmlTimestamp> timestamps = signature.getTimestamps();
		if (Utils.isCollectionNotEmpty(timestamps)) {
			for (XmlTimestamp timestamp : timestamps) {
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

	public Set<TimestampWrapper> getAllTimestampsNotArchival() {
		Set<TimestampWrapper> notArchivalTimestamps = new HashSet<TimestampWrapper>();
		notArchivalTimestamps.addAll(getTimestampListByType(TimestampType.SIGNATURE_TIMESTAMP));
		notArchivalTimestamps.addAll(getTimestampListByType(TimestampType.CONTENT_TIMESTAMP));
		notArchivalTimestamps.addAll(getTimestampListByType(TimestampType.ALL_DATA_OBJECTS_TIMESTAMP));
		notArchivalTimestamps.addAll(getTimestampListByType(TimestampType.INDIVIDUAL_DATA_OBJECTS_TIMESTAMP));
		return notArchivalTimestamps;
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
		XmlSigningCertificate signingCertificate = signature.getSigningCertificate();
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
		return Utils.EMPTY_STRING;
	}

	public boolean isBLevelTechnicallyValid() {
		return (signature.getBasicSignature() != null) && signature.getBasicSignature().isSignatureValid();
	}

	public boolean isThereXLevel() {
		List<TimestampWrapper> timestampLevelX = getTimestampLevelX();
		return Utils.isCollectionNotEmpty(timestampLevelX);
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
		return Utils.isCollectionNotEmpty(timestampList);
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
		return Utils.isCollectionNotEmpty(timestamps);
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
			if (signatureValid && messageImprintIntact) { // TODO correct ?
															// return true if at
															// least 1 TSP OK
				return true;
			}
		}
		return false;
	}

	public List<String> getTimestampIdsList() {
		List<String> result = new ArrayList<String>();
		List<TimestampWrapper> timestamps = getTimestampList();
		if (Utils.isCollectionNotEmpty(timestamps)) {
			for (TimestampWrapper tsp : timestamps) {
				result.add(tsp.getId());
			}
		}
		return result;
	}

	public String getParentId() {
		return signature.getParentId();
	}

	public List<XmlSignatureScope> getSignatureScopes() {
		return signature.getSignatureScopes();
	}

	public List<String> getCertifiedRoles() {
		List<String> result = new ArrayList<String>();
		List<XmlCertifiedRole> certifiedRoles = signature.getCertifiedRoles();
		if (Utils.isCollectionNotEmpty(certifiedRoles)) {
			for (XmlCertifiedRole certifiedRole : certifiedRoles) {
				result.add(certifiedRole.getCertifiedRole());
			}
		}
		return result;
	}

	public List<String> getCommitmentTypeIdentifiers() {
		List<String> commitmentTypeIndications = signature.getCommitmentTypeIndication();
		if (Utils.isCollectionNotEmpty(commitmentTypeIndications)) {
			return commitmentTypeIndications;
		}
		return Collections.emptyList();
	}

	public List<String> getClaimedRoles() {
		List<String> claimedRoles = signature.getClaimedRoles();
		if (Utils.isCollectionNotEmpty(claimedRoles)) {
			return claimedRoles;
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
		return Utils.EMPTY_STRING;
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
		return Utils.EMPTY_STRING;
	}

	public String getPolicyUrl() {
		XmlPolicy policy = signature.getPolicy();
		if (policy != null) {
			return policy.getUrl();
		}
		return Utils.EMPTY_STRING;
	}

	public boolean isPolicyAsn1Processable() {
		XmlPolicy policy = signature.getPolicy();
		if (policy != null) {
			return Utils.isTrue(policy.isAsn1Processable());
		}
		return false;
	}

	public boolean isPolicyIdentified() {
		XmlPolicy policy = signature.getPolicy();
		if (policy != null) {
			return Utils.isTrue(policy.isIdentified());
		}
		return false;
	}

	public boolean isPolicyStatus() {
		XmlPolicy policy = signature.getPolicy();
		if (policy != null) {
			return Utils.isTrue(policy.isStatus());
		}
		return false;
	}

	public String getFormat() {
		return signature.getSignatureFormat();
	}

}
