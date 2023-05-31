/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.spi.tsl;

import eu.europa.esig.dss.spi.util.MutableTimeDependentValues;

import java.io.Serializable;
import java.util.List;

/**
 * This object contains information extracted from the MutualRecognitionAgreementInformation element
 * of a Mutual Recognition Agreement schema
 *
 */
public class MRA implements Serializable {

	private static final long serialVersionUID = 6498087340536063280L;

	/** Value of technicalType attribute */
	private String technicalType;

	/** Value of version attribute */
	private String version;

	/** Reference to the legal documentation of the pointing party */
	private String pointingContractingPartyLegislation;

	/** Reference to the legal documentation of the pointed party */
	private String pointedContractingPartyLegislation;

	/** Contains a list of equivalence schemes defined for various Trust Services */
	private List<MutableTimeDependentValues<ServiceEquivalence>> serviceEquivalence;

	/**
	 * Default constructor instantiating object with null values
	 */
	public MRA() {
		// empty
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
	 * @return a list of {@link MutableTimeDependentValues<ServiceEquivalence>}s
	 */
	public List<MutableTimeDependentValues<ServiceEquivalence>> getServiceEquivalence() {
		return serviceEquivalence;
	}

	/**
	 * Sets the list of equivalence mapping between Trust Services
	 *
	 * @param serviceEquivalence a list of {@link MutableTimeDependentValues<ServiceEquivalence>}s
	 */
	public void setServiceEquivalence(List<MutableTimeDependentValues<ServiceEquivalence>> serviceEquivalence) {
		this.serviceEquivalence = serviceEquivalence;
	}

}
