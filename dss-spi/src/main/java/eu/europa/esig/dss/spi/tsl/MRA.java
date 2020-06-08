package eu.europa.esig.dss.spi.tsl;

import java.util.List;

public class MRA {

	private String technicalType;
	private String firstContractingPartyLegislation;
	private String secondContractingPartyLegislation;
	private List<ServiceEquivalence> serviceEquivalence;

	public String getTechnicalType() {
		return technicalType;
	}

	public void setTechnicalType(String technicalType) {
		this.technicalType = technicalType;
	}

	public String getFirstContractingPartyLegislation() {
		return firstContractingPartyLegislation;
	}

	public void setFirstContractingPartyLegislation(String firstContractingPartyLegislation) {
		this.firstContractingPartyLegislation = firstContractingPartyLegislation;
	}

	public String getSecondContractingPartyLegislation() {
		return secondContractingPartyLegislation;
	}

	public void setSecondContractingPartyLegislation(String secondContractingPartyLegislation) {
		this.secondContractingPartyLegislation = secondContractingPartyLegislation;
	}

	public List<ServiceEquivalence> getServiceEquivalence() {
		return serviceEquivalence;
	}

	public void setServiceEquivalence(List<ServiceEquivalence> serviceEquivalence) {
		this.serviceEquivalence = serviceEquivalence;
	}

}
