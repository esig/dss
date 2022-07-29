package eu.europa.esig.dss.spi.tsl;

import eu.europa.esig.dss.enumerations.MRAEquivalenceContext;
import eu.europa.esig.dss.enumerations.MRAStatus;

import java.util.Date;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * This class represents a wrapper for TrustServiceEquivalenceInformation element from MRA scheme
 *
 */
public class ServiceEquivalence {

	/** TrustServiceLegalIdentifier */
	private String legalInfoIdentifier;

	/** TrustServiceEquivalenceStatus */
	private MRAStatus status;

	/** TrustServiceEquivalenceStatusStartingTime */
	private Date startDate;

	/** AdditionalServiceInformation equivalencies */
	private Map<ServiceTypeASi, ServiceTypeASi> typeAsiEquivalence;

	/** TrustServiceTSLStatusEquivalenceList equivalencies */
	private Map<List<String>, List<String>> statusEquivalence;

	/** CertificateContentReferencesEquivalenceList */
	private EnumMap<MRAEquivalenceContext, CertificateContentEquivalence> certificateContentEquivalences;

	/** QualifierEquivalenceList equivalencies */
	private Map<String, String> qualifierEquivalence;

	/**
	 * Default constructor instantiating object with null values
	 */
	public ServiceEquivalence() {
	}

	/**
	 * Gets TrustServiceLegalIdentifier value
	 *
	 * @return {@link String}
	 */
	public String getLegalInfoIdentifier() {
		return legalInfoIdentifier;
	}

	/**
	 * Sets TrustServiceLegalIdentifier value
	 *
	 * @param legalInfoIdentifier {@link String}
	 */
	public void setLegalInfoIdentifier(String legalInfoIdentifier) {
		this.legalInfoIdentifier = legalInfoIdentifier;
	}

	/**
	 * Gets TrustServiceEquivalenceStatus value
	 *
	 * @return {@link MRAStatus}
	 */
	public MRAStatus getStatus() {
		return status;
	}

	/**
	 * Sets TrustServiceEquivalenceStatus value
	 *
	 * @param status {@link MRAStatus}
	 */
	public void setStatus(MRAStatus status) {
		this.status = status;
	}

	/**
	 * Gets TrustServiceEquivalenceStatusStartingTime value
	 *
	 * @return {@link Date}
	 */
	public Date getStartDate() {
		return startDate;
	}

	/**
	 * Sets TrustServiceEquivalenceStatusStartingTime value
	 *
	 * @param startDate {@link Date}
	 */
	public void setStartDate(Date startDate) {
		this.startDate = startDate;
	}

	/**
	 * Gets a map of AdditionalServiceInformation equivalences between pointed and pointing parties
	 *
	 * @return a map between {@link ServiceTypeASi} for pointed and {@link ServiceTypeASi} for pointing parties
	 */
	public Map<ServiceTypeASi, ServiceTypeASi> getTypeAsiEquivalence() {
		return typeAsiEquivalence;
	}

	/**
	 * Sets a map of AdditionalServiceInformation equivalences between pointed and pointing parties
	 *
	 * @param typeAsiEquivalence a map between {@link ServiceTypeASi} for pointed and {@link ServiceTypeASi} for pointing parties
	 */
	public void setTypeAsiEquivalence(Map<ServiceTypeASi, ServiceTypeASi> typeAsiEquivalence) {
		this.typeAsiEquivalence = typeAsiEquivalence;
	}

	/**
	 * Gets a map of TrustServiceTSLStatusEquivalenceList equivalences between pointed and pointing parties
	 *
	 * @return a map between list of {@link String} for pointed and pointing parties
	 */
	public Map<List<String>, List<String>> getStatusEquivalence() {
		return statusEquivalence;
	}

	/**
	 * Sets a map of TrustServiceTSLStatusEquivalenceList equivalences between pointed and pointing parties
	 *
	 * @param statusEquivalence a map between list of {@link String} for pointed and pointing parties
	 */
	public void setStatusEquivalence(Map<List<String>, List<String>> statusEquivalence) {
		this.statusEquivalence = statusEquivalence;
	}

	/**
	 * Gets a map of CertificateContentReferencesEquivalenceList equivalences
	 *
	 * @return a map between {@link MRAEquivalenceContext} type and {@code CertificateContentEquivalence} value
	 */
	public EnumMap<MRAEquivalenceContext, CertificateContentEquivalence> getCertificateContentEquivalences() {
		return certificateContentEquivalences;
	}

	/**
	 * Sets a map of CertificateContentReferencesEquivalenceList equivalences
	 *
	 * @param certificateContentEquivalences a map between {@link MRAEquivalenceContext} type and
	 *                                       {@code CertificateContentEquivalence} value
	 */
	public void setCertificateContentEquivalences(
			EnumMap<MRAEquivalenceContext, CertificateContentEquivalence> certificateContentEquivalences) {
		this.certificateContentEquivalences = certificateContentEquivalences;
	}

	/**
	 * Gets a map of QualifierEquivalenceList equivalences between pointed and pointing parties
	 *
	 * @return a map between {@code String} for pointed and pointing parties
	 */
	public Map<String, String> getQualifierEquivalence() {
		return qualifierEquivalence;
	}

	/**
	 * Sets a map of QualifierEquivalenceList equivalences between pointed and pointing parties
	 *
	 * @param qualifierEquivalence a map between {@code String} for pointed and pointing parties
	 */
	public void setQualifierEquivalence(Map<String, String> qualifierEquivalence) {
		this.qualifierEquivalence = qualifierEquivalence;
	}

}
