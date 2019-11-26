package eu.europa.esig.dss.tsl.function.converter;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.function.Function;

import javax.xml.bind.JAXBElement;
import javax.xml.datatype.XMLGregorianCalendar;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.tsl.Condition;
import eu.europa.esig.dss.spi.tsl.ConditionForQualifiers;
import eu.europa.esig.dss.spi.tsl.TrustService;
import eu.europa.esig.dss.spi.tsl.TrustService.TrustServiceBuilder;
import eu.europa.esig.dss.spi.tsl.TrustServiceStatusAndInformationExtensions;
import eu.europa.esig.dss.spi.tsl.TrustServiceStatusAndInformationExtensions.TrustServiceStatusAndInformationExtensionsBuilder;
import eu.europa.esig.dss.spi.util.MutableTimeDependentValues;
import eu.europa.esig.dss.spi.util.TimeDependentValues;
import eu.europa.esig.dss.tsl.dto.condition.CertSubjectDNAttributeCondition;
import eu.europa.esig.dss.tsl.dto.condition.CompositeCondition;
import eu.europa.esig.dss.tsl.dto.condition.ExtendedKeyUsageCondition;
import eu.europa.esig.dss.tsl.dto.condition.KeyUsageCondition;
import eu.europa.esig.dss.tsl.dto.condition.PolicyIdCondition;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.trustedlist.enums.Assert;
import eu.europa.esig.trustedlist.jaxb.ecc.CriteriaListType;
import eu.europa.esig.trustedlist.jaxb.ecc.KeyUsageBitType;
import eu.europa.esig.trustedlist.jaxb.ecc.KeyUsageType;
import eu.europa.esig.trustedlist.jaxb.ecc.PoliciesListType;
import eu.europa.esig.trustedlist.jaxb.ecc.QualificationElementType;
import eu.europa.esig.trustedlist.jaxb.ecc.QualificationsType;
import eu.europa.esig.trustedlist.jaxb.ecc.QualifierType;
import eu.europa.esig.trustedlist.jaxb.ecc.QualifiersType;
import eu.europa.esig.trustedlist.jaxb.tsl.AdditionalServiceInformationType;
import eu.europa.esig.trustedlist.jaxb.tsl.AttributedNonEmptyURIType;
import eu.europa.esig.trustedlist.jaxb.tsl.DigitalIdentityListType;
import eu.europa.esig.trustedlist.jaxb.tsl.ExtensionType;
import eu.europa.esig.trustedlist.jaxb.tsl.ExtensionsListType;
import eu.europa.esig.trustedlist.jaxb.tsl.NonEmptyMultiLangURIType;
import eu.europa.esig.trustedlist.jaxb.tsl.ServiceHistoryInstanceType;
import eu.europa.esig.trustedlist.jaxb.tsl.ServiceSupplyPointsType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPServiceInformationType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPServiceType;
import eu.europa.esig.trustedlist.jaxb.tslx.CertSubjectDNAttributeType;
import eu.europa.esig.trustedlist.jaxb.tslx.ExtendedKeyUsageType;
import eu.europa.esig.xades.jaxb.xades132.IdentifierType;
import eu.europa.esig.xades.jaxb.xades132.ObjectIdentifierType;

public class TrustServiceConverter implements Function<TSPServiceType, TrustService> {

	@Override
	public TrustService apply(TSPServiceType original) {
		TrustServiceBuilder trustServiceBuilder = new TrustService.TrustServiceBuilder();
		return trustServiceBuilder
				.setCertificates(extractCertificates(original.getServiceInformation()))
				.setStatusAndInformationExtensions(extractStatusAndHistory(original))
				.build();
	}

	private List<CertificateToken> extractCertificates(TSPServiceInformationType serviceInformation) {
		DigitalIdentityListTypeConverter converter = new DigitalIdentityListTypeConverter();
		DigitalIdentityListType serviceDigitalIdentityList = serviceInformation.getServiceDigitalIdentity();
		return Collections.unmodifiableList(converter.apply(serviceDigitalIdentityList));
	}

	private TimeDependentValues<TrustServiceStatusAndInformationExtensions> extractStatusAndHistory(TSPServiceType original) {
		MutableTimeDependentValues<TrustServiceStatusAndInformationExtensions> statusHistoryList = new MutableTimeDependentValues<TrustServiceStatusAndInformationExtensions>();

		TSPServiceInformationType serviceInfo = original.getServiceInformation();

		InternationalNamesTypeConverter converter = new InternationalNamesTypeConverter();

		TrustServiceStatusAndInformationExtensionsBuilder statusBuilder = new TrustServiceStatusAndInformationExtensions.TrustServiceStatusAndInformationExtensionsBuilder();
		statusBuilder.setNames(converter.apply(serviceInfo.getServiceName()));
		statusBuilder.setType(serviceInfo.getServiceTypeIdentifier());
		statusBuilder.setStatus(serviceInfo.getServiceStatus());
		statusBuilder.setServiceSupplyPoints(getServiceSupplyPoints(serviceInfo.getServiceSupplyPoints()));

		parseExtensionsList(serviceInfo.getServiceInformationExtensions(), statusBuilder);

		Date nextEndDate = convertToDate(serviceInfo.getStatusStartingTime());
		statusBuilder.setStartDate(nextEndDate);
		statusHistoryList.addOldest(statusBuilder.build());

		if (original.getServiceHistory() != null && Utils.isCollectionNotEmpty(original.getServiceHistory().getServiceHistoryInstance())) {
			for (ServiceHistoryInstanceType serviceHistory : original.getServiceHistory().getServiceHistoryInstance()) {
				TrustServiceStatusAndInformationExtensionsBuilder statusHistoryBuilder = 
						new TrustServiceStatusAndInformationExtensions.TrustServiceStatusAndInformationExtensionsBuilder();
				statusHistoryBuilder.setNames(converter.apply(serviceHistory.getServiceName()));
				statusHistoryBuilder.setType(serviceHistory.getServiceTypeIdentifier());
				statusHistoryBuilder.setStatus(serviceHistory.getServiceStatus());

				parseExtensionsList(serviceHistory.getServiceInformationExtensions(), statusHistoryBuilder);

				statusHistoryBuilder.setEndDate(nextEndDate);
				nextEndDate = convertToDate(serviceHistory.getStatusStartingTime());
				statusHistoryBuilder.setStartDate(nextEndDate);
				statusHistoryList.addOldest(statusHistoryBuilder.build());
			}
		}

		return statusHistoryList;
	}

	private void parseExtensionsList(ExtensionsListType serviceInformationExtensions, TrustServiceStatusAndInformationExtensionsBuilder statusBuilder) {
		if (serviceInformationExtensions != null) {
			statusBuilder.setConditionsForQualifiers(extractConditionsForQualifiers(serviceInformationExtensions.getExtension()));
			statusBuilder.setAdditionalServiceInfoUris(extractAdditionalServiceInfoUris(serviceInformationExtensions.getExtension()));
			statusBuilder.setExpiredCertsRevocationInfo(extractExpiredCertsRevocationInfo(serviceInformationExtensions.getExtension()));
		}
	}

	@SuppressWarnings("rawtypes")
	private List<ConditionForQualifiers> extractConditionsForQualifiers(List<ExtensionType> extensions) {
		List<ConditionForQualifiers> conditionsForQualifiers = new ArrayList<ConditionForQualifiers>();
		for (ExtensionType extensionType : extensions) {
			List<Object> content = extensionType.getContent();
			if (Utils.isCollectionNotEmpty(content)) {
				for (Object object : content) {
					if (object instanceof JAXBElement) {
						JAXBElement jaxbElement = (JAXBElement) object;
						Object objectValue = jaxbElement.getValue();
						if (objectValue instanceof QualificationsType) {
							QualificationsType qt = (QualificationsType) jaxbElement.getValue();
							if ((qt != null) && Utils.isCollectionNotEmpty(qt.getQualificationElement())) {
								for (QualificationElementType qualificationElement : qt.getQualificationElement()) {
									List<String> qualifiers = extractQualifiers(qualificationElement);
									Condition condition = getCondition(qualificationElement.getCriteriaList());
									if (Utils.isCollectionNotEmpty(qualifiers) && (condition != null)) {
										conditionsForQualifiers.add(new ConditionForQualifiers(condition, Collections.unmodifiableList(qualifiers)));
									}
								}
							}
						}
					}
				}
			}
		}
		return conditionsForQualifiers;
	}

	@SuppressWarnings("rawtypes")
	private List<String> extractAdditionalServiceInfoUris(List<ExtensionType> extensions) {
		List<String> additionalServiceInfos = new ArrayList<String>();
		for (ExtensionType extensionType : extensions) {
			List<Object> content = extensionType.getContent();
			if (Utils.isCollectionNotEmpty(content)) {
				for (Object object : content) {
					if (object instanceof JAXBElement) {
						JAXBElement jaxbElement = (JAXBElement) object;
						Object objectValue = jaxbElement.getValue();
						if (objectValue instanceof AdditionalServiceInformationType) {
							AdditionalServiceInformationType additionalServiceInfo = (AdditionalServiceInformationType) objectValue;
							NonEmptyMultiLangURIType uri = additionalServiceInfo.getURI();
							if (uri != null && Utils.isStringNotBlank(uri.getValue())) {
								additionalServiceInfos.add(uri.getValue());
							}
						}
					}
				}
			}
		}
		return additionalServiceInfos;
	}

	@SuppressWarnings("rawtypes")
	private Date extractExpiredCertsRevocationInfo(List<ExtensionType> extensions) {
		for (ExtensionType extensionType : extensions) {
			List<Object> content = extensionType.getContent();
			if (Utils.isCollectionNotEmpty(content)) {
				for (Object object : content) {
					if (object instanceof JAXBElement) {
						JAXBElement jaxbElement = (JAXBElement) object;
						// TODO check tag name
						Object objectValue = jaxbElement.getValue();
						if (objectValue instanceof XMLGregorianCalendar) {
							return convertToDate((XMLGregorianCalendar) objectValue);
						}
					}
				}
			}
		}
		return null;
	}

	private Date convertToDate(XMLGregorianCalendar gregorianCalendar) {
		return gregorianCalendar.toGregorianCalendar().getTime();
	}

	private List<String> extractQualifiers(QualificationElementType qualificationElement) {
		List<String> qualifiers = new ArrayList<String>();
		QualifiersType qualifiersType = qualificationElement.getQualifiers();
		if ((qualifiersType != null) && Utils.isCollectionNotEmpty(qualifiersType.getQualifier())) {
			for (QualifierType qualitierType : qualifiersType.getQualifier()) {
				qualifiers.add(qualitierType.getUri());
			}
		}
		return qualifiers;
	}

	protected Condition getCondition(CriteriaListType criteriaList) {
		Assert matchingCriteriaIndicator = criteriaList.getAssert();
		CompositeCondition condition = new CompositeCondition(matchingCriteriaIndicator);

		addKeyUsageConditionsIfPresent(criteriaList.getKeyUsage(), condition);
		addPolicyIdConditionsIfPresent(criteriaList.getPolicySet(), condition);
		addOtherCriteriaListConditionsIfPresent(criteriaList.getOtherCriteriaList(), condition);
		addCriteriaListConditionsIfPresent(criteriaList.getCriteriaList(), condition);

		return condition;
	}

	/**
	 * ETSI TS 119 612 V1.1.1 / 5.5.9.2.2.3
	 * 
	 * @param otherCriteriaList
	 * @param condition
	 */
	@SuppressWarnings("rawtypes")
	private void addOtherCriteriaListConditionsIfPresent(eu.europa.esig.xades.jaxb.xades132.AnyType otherCriteriaList, CompositeCondition condition) {
		if (otherCriteriaList != null && Utils.isCollectionNotEmpty(otherCriteriaList.getContent())) {
			for (Object content : otherCriteriaList.getContent()) {
				if (content instanceof JAXBElement) {
					JAXBElement jaxbElement = (JAXBElement) content;
					Object objectValue = jaxbElement.getValue();
					if (objectValue instanceof CertSubjectDNAttributeType) {
						CertSubjectDNAttributeType certSubDNAttr = (CertSubjectDNAttributeType) objectValue;
						condition.addChild(new CertSubjectDNAttributeCondition(extractOids(certSubDNAttr.getAttributeOID())));
					} else if (objectValue instanceof ExtendedKeyUsageType) {
						ExtendedKeyUsageType extendedKeyUsage = (ExtendedKeyUsageType) objectValue;
						condition.addChild(new ExtendedKeyUsageCondition(extractOids(extendedKeyUsage.getKeyPurposeId())));
					} else {
						throw new DSSException("Unsupported OtherCriteriaList");
					}
				}
			}
		}
	}

	private List<String> extractOids(List<ObjectIdentifierType> oits) {
		List<String> oids = new ArrayList<String>();
		if (Utils.isCollectionNotEmpty(oits)) {
			for (ObjectIdentifierType objectIdentifierType : oits) {
				oids.add(objectIdentifierType.getIdentifier().getValue());
			}
		}
		return oids;
	}

	private void addPolicyIdConditionsIfPresent(List<PoliciesListType> policySet, CompositeCondition criteriaCondition) {
		if (Utils.isCollectionNotEmpty(policySet)) {
			for (PoliciesListType policiesListType : policySet) {
				CompositeCondition condition = new CompositeCondition();
				for (ObjectIdentifierType oidType : policiesListType.getPolicyIdentifier()) {
					IdentifierType identifier = oidType.getIdentifier();
					String id = identifier.getValue();

					// ES TSL : <ns4:Identifier
					// Qualifier="OIDAsURN">urn:oid:1.3.6.1.4.1.36035.1.3.1</ns4:Identifier>
					if (id.indexOf(':') >= 0) {
						id = id.substring(id.lastIndexOf(':') + 1);
					}

					condition.addChild(new PolicyIdCondition(id));
				}
				criteriaCondition.addChild(condition);
			}
		}
	}

	private void addKeyUsageConditionsIfPresent(List<KeyUsageType> keyUsages, CompositeCondition criteriaCondition) {
		if (Utils.isCollectionNotEmpty(keyUsages)) {
			for (KeyUsageType keyUsageType : keyUsages) {
				CompositeCondition condition = new CompositeCondition();
				for (KeyUsageBitType keyUsageBit : keyUsageType.getKeyUsageBit()) {
					condition.addChild(new KeyUsageCondition(keyUsageBit.getName(), keyUsageBit.isValue()));
				}
				criteriaCondition.addChild(condition);
			}
		}
	}

	private void addCriteriaListConditionsIfPresent(List<CriteriaListType> criteriaList, CompositeCondition condition) {
		if (Utils.isCollectionNotEmpty(criteriaList)) {
			for (CriteriaListType criteriaListType : criteriaList) {
				condition.addChild(getCondition(criteriaListType));
			}
		}
	}

	private List<String> getServiceSupplyPoints(ServiceSupplyPointsType serviceSupplyPoints) {
		List<String> result = new ArrayList<String>();
		if (serviceSupplyPoints != null && Utils.isCollectionNotEmpty(serviceSupplyPoints.getServiceSupplyPoint())) {
			for (AttributedNonEmptyURIType nonEmptyURI : serviceSupplyPoints.getServiceSupplyPoint()) {
				result.add(nonEmptyURI.getValue());
			}
		}
		return result;
	}

}
