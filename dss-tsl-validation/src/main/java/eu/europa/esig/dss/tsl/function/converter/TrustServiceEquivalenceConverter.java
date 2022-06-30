package eu.europa.esig.dss.tsl.function.converter;

import eu.europa.esig.dss.enumerations.MRAEquivalenceContext;
import eu.europa.esig.dss.spi.tsl.CertificateContentEquivalence;
import eu.europa.esig.dss.spi.tsl.Condition;
import eu.europa.esig.dss.spi.tsl.QCStatementOids;
import eu.europa.esig.dss.spi.tsl.ServiceEquivalence;
import eu.europa.esig.dss.spi.tsl.ServiceTypeASi;
import eu.europa.esig.dss.tsl.dto.condition.CompositeCondition;
import eu.europa.esig.dss.tsl.dto.condition.QCStatementCondition;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.trustedlist.jaxb.ecc.CriteriaListType;
import eu.europa.esig.trustedlist.jaxb.ecc.QualifierType;
import eu.europa.esig.trustedlist.jaxb.mra.CertificateContentReferenceEquivalenceType;
import eu.europa.esig.trustedlist.jaxb.mra.CertificateContentReferencesEquivalenceListType;
import eu.europa.esig.trustedlist.jaxb.mra.QualifierEquivalenceListType;
import eu.europa.esig.trustedlist.jaxb.mra.QualifierEquivalenceType;
import eu.europa.esig.trustedlist.jaxb.mra.TrustServiceEquivalenceInformationType;
import eu.europa.esig.trustedlist.jaxb.mra.TrustServiceTSLQualificationExtensionEquivalenceListType;
import eu.europa.esig.trustedlist.jaxb.mra.TrustServiceTSLStatusEquivalenceListType;
import eu.europa.esig.trustedlist.jaxb.mra.TrustServiceTSLStatusEquivalenceType;
import eu.europa.esig.trustedlist.jaxb.mra.TrustServiceTSLStatusList;
import eu.europa.esig.trustedlist.jaxb.mra.TrustServiceTSLTypeEquivalenceListType;
import eu.europa.esig.trustedlist.jaxb.mra.TrustServiceTSLTypeListType;
import eu.europa.esig.trustedlist.jaxb.mra.TrustServiceTSLTypeType;
import eu.europa.esig.trustedlist.jaxb.tsl.AdditionalServiceInformationType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

public class TrustServiceEquivalenceConverter implements Function<TrustServiceEquivalenceInformationType, ServiceEquivalence> {

	private static final Logger LOG = LoggerFactory.getLogger(TrustServiceEquivalenceConverter.class);

	private CriteriaListTypeConverter criteriaConverter = new CriteriaListTypeConverter();

	@Override
	public ServiceEquivalence apply(TrustServiceEquivalenceInformationType t) {
		ServiceEquivalence result = new ServiceEquivalence();
		result.setLegalInfo(t.getTrustServiceLegalIdentifier());
		result.setStartDate(t.getTrustServiceEquivalenceStatusStartingTime().toGregorianCalendar().getTime());
		result.setStatus(t.getTrustServiceEquivalenceStatus());

		fillTypeASiEquivalence(t, result);
		fillStatusEquivalence(t, result);
		fillCertificateEquivalence(t, result);
		fillQualifierEquivalence(t, result);

		return result;
	}

	private void fillTypeASiEquivalence(TrustServiceEquivalenceInformationType t, ServiceEquivalence result) {
		TrustServiceTSLTypeEquivalenceListType serviceTSLTypeEquivalenceList = t.getTrustServiceTSLTypeEquivalenceList();
		if (serviceTSLTypeEquivalenceList != null) {
			TrustServiceTSLTypeListType expected = serviceTSLTypeEquivalenceList.getTrustServiceTSLTypeListPointedParty();
			TrustServiceTSLTypeListType substitute = serviceTSLTypeEquivalenceList.getTrustServiceTSLTypeListPointingParty();
			List<TrustServiceTSLTypeType> expectedServiceTSLTypes = expected.getTrustServiceTSLType();
			List<TrustServiceTSLTypeType> substituteServiceTSLTypes = substitute.getTrustServiceTSLType();

			Map<ServiceTypeASi, ServiceTypeASi> typeAsiEquivalence = new HashMap<>();

			for (TrustServiceTSLTypeType expectedTypeASI : expectedServiceTSLTypes) {
				ServiceTypeASi staExpected = getServiceTypeASi(expectedTypeASI);
				for (TrustServiceTSLTypeType substituteTypeASI : substituteServiceTSLTypes) {
					ServiceTypeASi staSubstitute = getServiceTypeASi(substituteTypeASI);
					typeAsiEquivalence.put(staExpected, staSubstitute);
				}
			}
			result.setTypeAsiEquivalence(typeAsiEquivalence);
		}
	}

	private ServiceTypeASi getServiceTypeASi(TrustServiceTSLTypeType expectedTypeASI) {
		ServiceTypeASi sta = new ServiceTypeASi();
		sta.setType(expectedTypeASI.getServiceTypeIdentifier());
		AdditionalServiceInformationType additionalServiceInformation = expectedTypeASI.getAdditionalServiceInformation();
		if (additionalServiceInformation != null && additionalServiceInformation.getURI() != null) {
			sta.setAsi(additionalServiceInformation.getURI().getValue());
		}
		return sta;
	}

	private void fillStatusEquivalence(TrustServiceEquivalenceInformationType t, ServiceEquivalence result) {
		TrustServiceTSLStatusEquivalenceListType serviceTSLStatusEquivalenceList = t.getTrustServiceTSLStatusEquivalenceList();

		Map<List<String>, List<String>> statusEquivalenceMap = new HashMap<>();
		TrustServiceTSLStatusEquivalenceType validEquivalences = serviceTSLStatusEquivalenceList.getTrustServiceTSLStatusValidEquivalence();
		extractEquivalences(validEquivalences, statusEquivalenceMap);

		TrustServiceTSLStatusEquivalenceType invalidEquivalences = serviceTSLStatusEquivalenceList.getTrustServiceTSLStatusInvalidEquivalence();
		extractEquivalences(invalidEquivalences, statusEquivalenceMap);

		result.setStatusEquivalence(statusEquivalenceMap);
	}

	private void extractEquivalences(TrustServiceTSLStatusEquivalenceType statusEquivalence, Map<List<String>, List<String>> statusEquivalenceMap) {
		if (statusEquivalence != null) {
			TrustServiceTSLStatusList serviceTSLStatusListExpected = statusEquivalence.getTrustServiceTSLStatusListPointedParty();
			List<String> expected = serviceTSLStatusListExpected.getServiceStatus();

			TrustServiceTSLStatusList serviceTSLStatusListSubstitute = statusEquivalence.getTrustServiceTSLStatusListPointingParty();
			List<String> substitute = serviceTSLStatusListSubstitute.getServiceStatus();

			statusEquivalenceMap.put(expected, substitute);
		}
	}

	private void fillCertificateEquivalence(TrustServiceEquivalenceInformationType t, ServiceEquivalence result) {
		CertificateContentReferencesEquivalenceListType certificateContentEquivalenceList = t.getCertificateContentReferencesEquivalenceList();
		if (certificateContentEquivalenceList != null
				&& Utils.isCollectionNotEmpty(certificateContentEquivalenceList.getCertificateContentReferenceEquivalence())) {

			EnumMap<MRAEquivalenceContext, CertificateContentEquivalence> certificateContentEquivalences = new EnumMap<>(MRAEquivalenceContext.class);
			for (CertificateContentReferenceEquivalenceType certEquiv : certificateContentEquivalenceList.getCertificateContentReferenceEquivalence()) {
				CriteriaListType expected = certEquiv.getCertificateContentDeclarationPointedParty();
				CriteriaListType substitute = certEquiv.getCertificateContentDeclarationPointingParty();
				Condition condition = criteriaConverter.apply(substitute);

				CertificateContentEquivalence equiv = new CertificateContentEquivalence();
				equiv.setCondition(criteriaConverter.apply(expected));
				equiv.setContentReplacement(getQCStatementOids(condition));

				certificateContentEquivalences.put(certEquiv.getCertificateContentReferenceEquivalenceContext(), equiv);
			}
			result.setCertificateContentEquivalences(certificateContentEquivalences);
		}
	}

	private QCStatementOids getQCStatementOids(Condition condition) {
		QCStatementOids result = new QCStatementOids();
		List<String> qcStatementIds = new ArrayList<>();
		List<String> qcTypeIds = new ArrayList<>();

		if (condition instanceof CompositeCondition) {
			CompositeCondition composite = (CompositeCondition) condition;
			switch (composite.getMatchingCriteriaIndicator()) {
				case ALL:
					for (Condition childCondition : composite.getChildren()) {
						QCStatementOids childResult = getQCStatementOids(childCondition);
						for (String childQCStatementId : childResult.getQcStatementIds()) {
							if (!qcStatementIds.contains(childQCStatementId))
								qcStatementIds.add(childQCStatementId);
						}
						for (String childQCTypeId : childResult.getQcTypeIds()) {
							if (!qcTypeIds.contains(childQCTypeId))
								qcTypeIds.add(childQCTypeId);
						}
					}
					break;

				case AT_LEAST_ONE:
					Condition childCondition = composite.getChildren().get(0);
					QCStatementOids childResult = getQCStatementOids(childCondition);
					for (String childQCStatementId : childResult.getQcStatementIds()) {
						if (!qcStatementIds.contains(childQCStatementId))
							qcStatementIds.add(childQCStatementId);
					}
					for (String childQCTypeId : childResult.getQcTypeIds()) {
						if (!qcTypeIds.contains(childQCTypeId))
							qcTypeIds.add(childQCTypeId);
					}
					break;

				case NONE:
					// nothing
					break;

				default:
					LOG.warn("Unsupported assert {}", composite.getMatchingCriteriaIndicator());
			}
		}

		if (condition instanceof QCStatementCondition) {
			QCStatementCondition qcCondition = (QCStatementCondition) condition;

			String oid = qcCondition.getOid();
			if (Utils.isStringNotEmpty(oid)) {
				qcStatementIds.add(oid);
			}
			String type = qcCondition.getType();
			if (Utils.isStringNotEmpty(type)) {
				qcTypeIds.add(type);
			}
		}

		result.setQcStatementIds(qcStatementIds);
		result.setQcTypeIds(qcTypeIds);
		return result;
	}

	private void fillQualifierEquivalence(TrustServiceEquivalenceInformationType t, ServiceEquivalence result) {
		TrustServiceTSLQualificationExtensionEquivalenceListType qualificationExtensionEquivalenceListType = t
				.getTrustServiceTSLQualificationExtensionEquivalenceList();
		if (qualificationExtensionEquivalenceListType != null
				&& Utils.isCollectionNotEmpty(qualificationExtensionEquivalenceListType.getQualifierEquivalenceList())) {

			Map<String, String> qualifierEquivalenceMap = new HashMap<>();
			for (QualifierEquivalenceListType qualifierEquivalenceList : qualificationExtensionEquivalenceListType.getQualifierEquivalenceList()) {

				List<QualifierEquivalenceType> qualifierEquivalence = qualifierEquivalenceList.getQualifierEquivalence();
				for (QualifierEquivalenceType qualifierEquivalenceType : qualifierEquivalence) {
					QualifierType qualifierExpected = qualifierEquivalenceType.getQualifierPointedParty();
					QualifierType qualifierSubstitute = qualifierEquivalenceType.getQualifierPointingParty();
					qualifierEquivalenceMap.put(qualifierExpected.getUri(), qualifierSubstitute.getUri());
				}
			}
			result.setQualifierEquivalence(qualifierEquivalenceMap);
		}
	}

}
