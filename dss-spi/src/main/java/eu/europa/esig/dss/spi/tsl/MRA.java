package eu.europa.esig.dss.spi.tsl;

import java.util.List;

/**
 * This object contains information extracted from the MutualRecognitionAgreementInformation element
 * of a Mutual Recognition Agreement schema
 *
 */
public class MRA {

	/** Value of technicalType attribute */
	private String technicalType;

	/** Value of version attribute */
	private String version;

	/** Reference to the legal documentation of the pointing party */
	private String pointingContractingPartyLegislation;

	/** Reference to the legal documentation of the pointed party */
	private String pointedContractingPartyLegislation;

	/** Contains a list of equivalence schemes defined for various Trust Services */
	private List<ServiceEquivalence> serviceEquivalence;

	/**
	 * Default constructor instantiating object with null values
	 */
	public MRA() {
	}

	/**
	 * Gets the technical type attribute value
	 *
	 * @return {@link String}
	 */
	public String getTechnicalType() {
		return technicalType;
	}

	/**
	 * Sets the technical type attribute value
	 *
	 * @param technicalType {@link String}
	 */
	public void setTechnicalType(String technicalType) {
		this.technicalType = technicalType;
	}

	/**
	 * Gets the version attribute value
	 *
	 * @return {@link String}
	 */
	public String getVersion() {
		return version;
	}

	/**
	 * Sets the version attribute value
	 *
	 * @param version {@link String}
	 */
	public void setVersion(String version) {
		this.version = version;
	}

	/**
	 * Gets the value defined within pointingContractingPartyLegislation attribute
	 *
	 * @return {@link String}
	 */
	public String getPointingContractingPartyLegislation() {
		return pointingContractingPartyLegislation;
	}

	/**
	 * Sets the value defined within pointingContractingPartyLegislation attribute
	 *
	 * @param pointingContractingPartyLegislation {@link String}
	 */
	public void setPointingContractingPartyLegislation(String pointingContractingPartyLegislation) {
		this.pointingContractingPartyLegislation = pointingContractingPartyLegislation;
	}

	/**
	 * Gets the value defined within pointedContractingPartyLegislation attribute
	 *
	 * @return {@link String}
	 */
	public String getPointedContractingPartyLegislation() {
		return pointedContractingPartyLegislation;
	}

	/**
	 * Sets the value defined within pointedContractingPartyLegislation attribute
	 *
	 * @param pointedContractingPartyLegislation {@link String}
	 */
	public void setPointedContractingPartyLegislation(String pointedContractingPartyLegislation) {
		this.pointedContractingPartyLegislation = pointedContractingPartyLegislation;
	}

	/**
	 * Gets the list of equivalence mapping between Trust Services
	 *
	 * @return a list of {@link ServiceEquivalence}s
	 */
	public List<ServiceEquivalence> getServiceEquivalence() {
		return serviceEquivalence;
	}

	/**
	 * Sets the list of equivalence mapping between Trust Services
	 *
	 * @param serviceEquivalence a list of {@link ServiceEquivalence}s
	 */
	public void setServiceEquivalence(List<ServiceEquivalence> serviceEquivalence) {
		this.serviceEquivalence = serviceEquivalence;
	}

}
