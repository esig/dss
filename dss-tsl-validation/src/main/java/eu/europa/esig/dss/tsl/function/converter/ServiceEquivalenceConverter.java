package eu.europa.esig.dss.tsl.function.converter;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import eu.europa.esig.dss.spi.tsl.Condition;
import eu.europa.esig.dss.spi.tsl.QCStatementOids;
import eu.europa.esig.dss.spi.tsl.ServiceEquivalence;
import eu.europa.esig.dss.spi.tsl.ServiceTypeASi;
import eu.europa.esig.dss.tsl.dto.condition.CompositeCondition;
import eu.europa.esig.dss.tsl.dto.condition.QCStatementCondition;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.trustedlist.jaxb.ecc.CriteriaListType;
import eu.europa.esig.trustedlist.jaxb.ecc.QualifierType;
import eu.europa.esig.trustedlist.jaxb.mra.CertificateContentEquivalenceListType;
import eu.europa.esig.trustedlist.jaxb.mra.CertificateContentEquivalenceType;
import eu.europa.esig.trustedlist.jaxb.mra.QualifierEquivalenceListType;
import eu.europa.esig.trustedlist.jaxb.mra.QualifierEquivalenceType;
import eu.europa.esig.trustedlist.jaxb.mra.ServiceEquivalenceInformationType;
import eu.europa.esig.trustedlist.jaxb.mra.ServiceTSLQualificationExtensionEquivalenceListType;
import eu.europa.esig.trustedlist.jaxb.mra.ServiceTSLStatusEquivalenceListType;
import eu.europa.esig.trustedlist.jaxb.mra.ServiceTSLStatusEquivalenceType;
import eu.europa.esig.trustedlist.jaxb.mra.ServiceTSLStatusList;
import eu.europa.esig.trustedlist.jaxb.mra.ServiceTSLTypeEquivalenceListType;
import eu.europa.esig.trustedlist.jaxb.mra.ServiceTSLTypeListType;
import eu.europa.esig.trustedlist.jaxb.mra.ServiceTSLTypeType;
import eu.europa.esig.trustedlist.jaxb.tsl.AdditionalServiceInformationType;

public class ServiceEquivalenceConverter implements Function<ServiceEquivalenceInformationType, ServiceEquivalence> {

	private CriteriaListTypeConverter criteriaConverter = new CriteriaListTypeConverter();

	@Override
	public ServiceEquivalence apply(ServiceEquivalenceInformationType t) {
		ServiceEquivalence result = new ServiceEquivalence();
		result.setLegalInfo(t.getServiceLegalInformation());
		result.setStartDate(t.getServiceEquivalenceStatusStartingTime().toGregorianCalendar().getTime());
		result.setStatus(t.getServiceEquivalenceStatus());

		fillTypeASiEquivalence(t, result);
		fillStatusEquivalence(t, result);
		fillCertificateEquivalence(t, result);
		fillQualifierEquivalence(t, result);

		return result;
	}

	private void fillTypeASiEquivalence(ServiceEquivalenceInformationType t, ServiceEquivalence result) {
		ServiceTSLTypeEquivalenceListType serviceTSLTypeEquivalenceList = t.getServiceTSLTypeEquivalenceList();
		if (serviceTSLTypeEquivalenceList != null) {
			ServiceTSLTypeListType expected = serviceTSLTypeEquivalenceList.getServiceTSLTypeListExpected();
			ServiceTSLTypeListType substitute = serviceTSLTypeEquivalenceList.getServiceTSLTypeListSubstitute();
			List<ServiceTSLTypeType> expectedServiceTSLTypes = expected.getServiceTSLType();
			List<ServiceTSLTypeType> subtituteServiceTSLTypes = substitute.getServiceTSLType();

			Map<ServiceTypeASi, ServiceTypeASi> typeAsiEquivalence = new HashMap<>();

			for (ServiceTSLTypeType expectedTypeASI : expectedServiceTSLTypes) {
				ServiceTypeASi staExpected = getServiceTypeASi(expectedTypeASI);
				for (ServiceTSLTypeType subtituteTypeASI : subtituteServiceTSLTypes) {
					ServiceTypeASi staSubtitute = getServiceTypeASi(subtituteTypeASI);
					typeAsiEquivalence.put(staExpected, staSubtitute);
				}
			}
			result.setTypeAsiEquivalence(typeAsiEquivalence);
		}
	}

	private ServiceTypeASi getServiceTypeASi(ServiceTSLTypeType expectedTypeASI) {
		ServiceTypeASi sta = new ServiceTypeASi();
		sta.setType(expectedTypeASI.getServiceTypeIdentifier());
		AdditionalServiceInformationType additionalServiceInformation = expectedTypeASI
				.getAdditionalServiceInformation();
		if (additionalServiceInformation != null && additionalServiceInformation.getURI() != null) {
			sta.setAsi(additionalServiceInformation.getURI().getValue());
		}
		return sta;
	}

	private void fillStatusEquivalence(ServiceEquivalenceInformationType t, ServiceEquivalence result) {
		ServiceTSLStatusEquivalenceListType serviceTSLStatusEquivalenceList = t.getServiceTSLStatusEquivalenceList();
		if (serviceTSLStatusEquivalenceList != null
				&& Utils.isCollectionNotEmpty(serviceTSLStatusEquivalenceList.getServiceTSLStatusEquivalence())) {

			Map<List<String>, List<String>> statusEquivalenceMap = new HashMap<>();
			for (ServiceTSLStatusEquivalenceType statusEquivalence : serviceTSLStatusEquivalenceList
					.getServiceTSLStatusEquivalence()) {

				ServiceTSLStatusList serviceTSLStatusListExpected = statusEquivalence.getServiceTSLStatusListExpected();
				List<String> expected = serviceTSLStatusListExpected.getServiceStatus();

				ServiceTSLStatusList serviceTSLStatusListSubstitute = statusEquivalence
						.getServiceTSLStatusListSubstitute();
				List<String> substitute = serviceTSLStatusListSubstitute.getServiceStatus();

				statusEquivalenceMap.put(expected, substitute);
			}
			result.setStatusEquivalence(statusEquivalenceMap);
		}
	}

	private void fillCertificateEquivalence(ServiceEquivalenceInformationType t, ServiceEquivalence result) {
		CertificateContentEquivalenceListType certificateContentEquivalenceList = t
				.getCertificateContentEquivalenceList();
		if (certificateContentEquivalenceList != null
				&& Utils.isCollectionNotEmpty(certificateContentEquivalenceList.getCertificateContentEquivalence())) {

			Map<Condition, QCStatementOids> certContentMap = new HashMap<>();
			for (CertificateContentEquivalenceType certEquiv : certificateContentEquivalenceList
					.getCertificateContentEquivalence()) {
				CriteriaListType expected = certEquiv.getCertificateContentExpected();
				CriteriaListType subtitute = certEquiv.getCertificateContentSubstitute();
				Condition condition = criteriaConverter.apply(subtitute);
				certContentMap.put(criteriaConverter.apply(expected), getQCStatementOids(condition));
			}
			result.setCertificateContentEquivalence(certContentMap);
		}
	}

	private QCStatementOids getQCStatementOids(Condition condition) {
		QCStatementOids result = new QCStatementOids();
		List<String> qcStatementIds = new ArrayList<>();
		List<String> qcTypeIds = new ArrayList<>();

		CompositeCondition composite = (CompositeCondition) condition;
		CompositeCondition compositeChildren = (CompositeCondition) composite.getChildren().get(0);
		for (Condition childCondition : compositeChildren.getChildren()) {
			if (childCondition instanceof QCStatementCondition) {
				QCStatementCondition qcCondition = (QCStatementCondition) childCondition;

				String oid = qcCondition.getOid();
				if (Utils.isStringNotEmpty(oid)) {
					qcStatementIds.add(oid);
				}
				String type = qcCondition.getType();
				if (Utils.isStringNotEmpty(type)) {
					qcTypeIds.add(type);
				}
			}

		}

		result.setQcStatementIds(qcStatementIds);
		result.setQcTypeIds(qcTypeIds);
		return result;
	}

	private void fillQualifierEquivalence(ServiceEquivalenceInformationType t, ServiceEquivalence result) {
		ServiceTSLQualificationExtensionEquivalenceListType qualificationExtensionEquivalenceListType = t
				.getServiceTSLQualificationExtensionEquivalenceList();
		if (qualificationExtensionEquivalenceListType != null && Utils
				.isCollectionNotEmpty(qualificationExtensionEquivalenceListType.getQualifierEquivalenceList())) {

			Map<String, String> qualifierEquivalenceMap = new HashMap<>();
			for (QualifierEquivalenceListType qualifierEquivalenceList : qualificationExtensionEquivalenceListType
					.getQualifierEquivalenceList()) {

				List<QualifierEquivalenceType> qualifierEquivalence = qualifierEquivalenceList
						.getQualifierEquivalence();
				for (QualifierEquivalenceType qualifierEquivalenceType : qualifierEquivalence) {
					QualifierType qualifierExpected = qualifierEquivalenceType.getQualifierExpected();
					QualifierType qualifierSubstitute = qualifierEquivalenceType.getQualifierSubstitute();
					qualifierEquivalenceMap.put(qualifierExpected.getUri(), qualifierSubstitute.getUri());
				}
			}
			result.setQualifierEquivalence(qualifierEquivalenceMap);
		}
	}

}
