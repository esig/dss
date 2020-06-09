package eu.europa.esig.dss.tsl.function.converter;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

import eu.europa.esig.dss.spi.tsl.MRA;
import eu.europa.esig.dss.spi.tsl.ServiceEquivalence;
import eu.europa.esig.trustedlist.jaxb.mra.MutualRecognitionAgreementInformationType;
import eu.europa.esig.trustedlist.jaxb.mra.ServiceEquivalenceInformationType;

public class MRAConverter implements Function<MutualRecognitionAgreementInformationType, MRA> {

	private ServiceEquivalenceConverter converter = new ServiceEquivalenceConverter();

	@Override
	public MRA apply(MutualRecognitionAgreementInformationType t) {
		MRA result = new MRA();
		result.setTechnicalType(t.getTechnicalType().toString());
		result.setPointingContractingPartyLegislation(t.getPointingContractingPartyLegislation());
		result.setPointedContractingPartyLegislation(t.getPointedContractingPartyLegislation());
		List<ServiceEquivalence> serviceEquivalences = new ArrayList<>();

		List<ServiceEquivalenceInformationType> serviceEquivalenceInformation = t.getServiceEquivalenceInformation();
		for (ServiceEquivalenceInformationType serviceEquivalenceInformationType : serviceEquivalenceInformation) {
			serviceEquivalences.add(converter.apply(serviceEquivalenceInformationType));
		}

		result.setServiceEquivalence(serviceEquivalences);

		return result;
	}

}
