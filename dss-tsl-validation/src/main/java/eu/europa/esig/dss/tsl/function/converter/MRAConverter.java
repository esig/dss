package eu.europa.esig.dss.tsl.function.converter;

import eu.europa.esig.dss.spi.tsl.MRA;
import eu.europa.esig.dss.spi.tsl.ServiceEquivalence;
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
