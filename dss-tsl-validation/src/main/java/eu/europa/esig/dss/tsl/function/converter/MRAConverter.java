/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.tsl.function.converter;

import eu.europa.esig.dss.model.tsl.MRA;
import eu.europa.esig.dss.model.tsl.ServiceEquivalence;
import eu.europa.esig.dss.model.timedependent.MutableTimeDependentValues;
import eu.europa.esig.trustedlist.jaxb.mra.MutualRecognitionAgreementInformationType;
import eu.europa.esig.trustedlist.jaxb.mra.TrustServiceEquivalenceInformationType;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

/**
 * This class is used to convert JAXB {@code MutualRecognitionAgreementInformationType} to Java {@code MRA}
 *
 */
public class MRAConverter implements Function<MutualRecognitionAgreementInformationType, MRA> {

	/** The TrustServiceEquivalence converter */
	private TrustServiceEquivalenceConverter converter = new TrustServiceEquivalenceConverter();

	/**
	 * Default constructor
	 */
	public MRAConverter() {
		// empty
	}

	@Override
	public MRA apply(MutualRecognitionAgreementInformationType t) {
		MRA result = new MRA();
		if (t.getTechnicalType() != null) {
			result.setTechnicalType(t.getTechnicalType().toString());
		}
		if (t.getVersion() != null) {
			result.setVersion(t.getVersion().toString());
		}
		result.setPointingContractingPartyLegislation(t.getPointingContractingPartyLegislation());
		result.setPointedContractingPartyLegislation(t.getPointedContractingPartyLegislation());
		List<MutableTimeDependentValues<ServiceEquivalence>> serviceEquivalences = new ArrayList<>();

		List<TrustServiceEquivalenceInformationType> trustServiceEquivalenceInformations = t.getTrustServiceEquivalenceInformation();
		for (TrustServiceEquivalenceInformationType trustServiceEquivalenceInformationType : trustServiceEquivalenceInformations) {
			serviceEquivalences.add(converter.apply(trustServiceEquivalenceInformationType));
		}

		result.setServiceEquivalence(serviceEquivalences);

		return result;
	}

}
