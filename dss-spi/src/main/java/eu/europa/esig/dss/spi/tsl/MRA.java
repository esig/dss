package eu.europa.esig.dss.spi.tsl;

import java.util.List;

public class MRA {

	private String technicalType;
	private String pointingContractingPartyLegislation;
	private String pointedContractingPartyLegislation;
	private List<ServiceEquivalence> serviceEquivalence;

	public String getTechnicalType() {
		return technicalType;
	}

	public void setTechnicalType(String technicalType) {
		this.technicalType = technicalType;
	}

	public String getPointingContractingPartyLegislation() {
		return pointingContractingPartyLegislation;
	}

	public void setPointingContractingPartyLegislation(String pointingContractingPartyLegislation) {
		this.pointingContractingPartyLegislation = pointingContractingPartyLegislation;
	}

	public String getPointedContractingPartyLegislation() {
		return pointedContractingPartyLegislation;
	}

	public void setPointedContractingPartyLegislation(String pointedContractingPartyLegislation) {
		this.pointedContractingPartyLegislation = pointedContractingPartyLegislation;
	}

	public List<ServiceEquivalence> getServiceEquivalence() {
		return serviceEquivalence;
	}

	public void setServiceEquivalence(List<ServiceEquivalence> serviceEquivalence) {
		this.serviceEquivalence = serviceEquivalence;
	}

}
