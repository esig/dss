package eu.europa.esig.dss.tsl.function.converter;

import eu.europa.esig.dss.spi.tsl.MRA;
import eu.europa.esig.dss.spi.tsl.ServiceEquivalence;
import eu.europa.esig.trustedlist.jaxb.mra.MutualRecognitionAgreementInformationType;
import eu.europa.esig.trustedlist.jaxb.mra.TrustServiceEquivalenceInformationType;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

public class MRAConverter implements Function<MutualRecognitionAgreementInformationType, MRA> {

	private TrustServiceEquivalenceConverter converter = new TrustServiceEquivalenceConverter();

	@Override
	public MRA apply(MutualRecognitionAgreementInformationType t) {
		MRA result = new MRA();
		result.setTechnicalType(t.getTechnicalType().toString());
		result.setPointingContractingPartyLegislation(t.getPointingContractingPartyLegislation());
		result.setPointedContractingPartyLegislation(t.getPointedContractingPartyLegislation());
		List<ServiceEquivalence> serviceEquivalences = new ArrayList<>();

		List<TrustServiceEquivalenceInformationType> trustServiceEquivalenceInformations = t
				.getTrustServiceEquivalenceInformation();
		for (TrustServiceEquivalenceInformationType trustServiceEquivalenceInformationType : trustServiceEquivalenceInformations) {
			serviceEquivalences.add(converter.apply(trustServiceEquivalenceInformationType));
		}

		result.setServiceEquivalence(serviceEquivalences);

		return result;
	}

}
