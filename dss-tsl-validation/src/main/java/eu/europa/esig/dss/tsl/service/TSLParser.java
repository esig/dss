package eu.europa.esig.dss.tsl.service;

import java.io.InputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

import javax.security.auth.x500.X500Principal;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.datatype.XMLGregorianCalendar;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.tsl.CompositeCondition;
import eu.europa.esig.dss.tsl.Condition;
import eu.europa.esig.dss.tsl.CriteriaListCondition;
import eu.europa.esig.dss.tsl.KeyUsageCondition;
import eu.europa.esig.dss.tsl.MatchingCriteriaIndicator;
import eu.europa.esig.dss.tsl.PolicyIdCondition;
import eu.europa.esig.dss.tsl.TSLConditionsForQualifiers;
import eu.europa.esig.dss.tsl.TSLParserResult;
import eu.europa.esig.dss.tsl.TSLPointer;
import eu.europa.esig.dss.tsl.TSLService;
import eu.europa.esig.dss.tsl.TSLServiceExtension;
import eu.europa.esig.dss.tsl.TSLServiceProvider;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.jaxb.ecc.CriteriaListType;
import eu.europa.esig.jaxb.ecc.KeyUsageBitType;
import eu.europa.esig.jaxb.ecc.KeyUsageType;
import eu.europa.esig.jaxb.ecc.PoliciesListType;
import eu.europa.esig.jaxb.ecc.QualificationElementType;
import eu.europa.esig.jaxb.ecc.QualificationsType;
import eu.europa.esig.jaxb.ecc.QualifierType;
import eu.europa.esig.jaxb.ecc.QualifiersType;
import eu.europa.esig.jaxb.tsl.AnyType;
import eu.europa.esig.jaxb.tsl.DigitalIdentityListType;
import eu.europa.esig.jaxb.tsl.DigitalIdentityType;
import eu.europa.esig.jaxb.tsl.ExtensionType;
import eu.europa.esig.jaxb.tsl.ExtensionsListType;
import eu.europa.esig.jaxb.tsl.InternationalNamesType;
import eu.europa.esig.jaxb.tsl.MultiLangNormStringType;
import eu.europa.esig.jaxb.tsl.NextUpdateType;
import eu.europa.esig.jaxb.tsl.NonEmptyMultiLangURIType;
import eu.europa.esig.jaxb.tsl.NonEmptyURIListType;
import eu.europa.esig.jaxb.tsl.ObjectFactory;
import eu.europa.esig.jaxb.tsl.OtherTSLPointerType;
import eu.europa.esig.jaxb.tsl.PostalAddressType;
import eu.europa.esig.jaxb.tsl.ServiceHistoryInstanceType;
import eu.europa.esig.jaxb.tsl.ServiceHistoryType;
import eu.europa.esig.jaxb.tsl.TSPInformationType;
import eu.europa.esig.jaxb.tsl.TSPServiceInformationType;
import eu.europa.esig.jaxb.tsl.TSPServiceType;
import eu.europa.esig.jaxb.tsl.TSPServicesListType;
import eu.europa.esig.jaxb.tsl.TSPType;
import eu.europa.esig.jaxb.tsl.TrustServiceProviderListType;
import eu.europa.esig.jaxb.tsl.TrustStatusListType;
import eu.europa.esig.jaxb.xades.IdentifierType;
import eu.europa.esig.jaxb.xades.ObjectIdentifierType;

public class TSLParser implements Callable<TSLParserResult> {

	private static final Logger logger = LoggerFactory.getLogger(TSLParser.class);

	private static final String TSL_MIME_TYPE = "application/vnd.etsi.tsl+xml";

	private static final JAXBContext jaxbContext;

	private InputStream inputStream;

	static {
		try {
			jaxbContext = JAXBContext.newInstance(ObjectFactory.class, eu.europa.esig.jaxb.ecc.ObjectFactory.class);
		} catch (JAXBException e) {
			throw new DSSException("Unable to initialize JaxB : " + e.getMessage(), e);
		}
	}

	public TSLParser(InputStream inputStream) {
		this.inputStream = inputStream;
	}

	@Override
	@SuppressWarnings("unchecked")
	public TSLParserResult call() throws Exception {
		try {
			Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
			JAXBElement<TrustStatusListType> jaxbElement = (JAXBElement<TrustStatusListType>) unmarshaller.unmarshal(inputStream);
			TrustStatusListType trustStatusList = jaxbElement.getValue();
			return getTslModel(trustStatusList);
		} catch (Exception e) {
			throw new DSSException("Unable to parse inputstream : " + e.getMessage(), e);
		}
	}

	private TSLParserResult getTslModel(TrustStatusListType tsl) {
		TSLParserResult tslModel = new TSLParserResult();
		tslModel.setTerritory(getTerritory(tsl));
		tslModel.setSequenceNumber(getSequenceNumber(tsl));
		tslModel.setIssueDate(getIssueDate(tsl));
		tslModel.setNextUpdateDate(getNextUpdate(tsl));
		tslModel.setDistributionPoints(getDistributionPoints(tsl));
		tslModel.setPointers(getMachineProcessableTSLPointers(tsl));
		tslModel.setServiceProviders(getServiceProviders(tsl));
		return tslModel;
	}

	private int getSequenceNumber(TrustStatusListType tsl) {
		BigInteger tslSequenceNumber = tsl.getSchemeInformation().getTSLSequenceNumber();
		if (tslSequenceNumber != null) {
			return tslSequenceNumber.intValue();
		}
		return -1;
	}

	private String getTerritory(TrustStatusListType tsl) {
		return tsl.getSchemeInformation().getSchemeTerritory();
	}

	private Date getIssueDate(TrustStatusListType tsl) {
		XMLGregorianCalendar gregorianCalendar = tsl.getSchemeInformation().getListIssueDateTime();
		return convertToDate(gregorianCalendar);
	}

	private Date getNextUpdate(TrustStatusListType tsl) {
		NextUpdateType nextUpdate = tsl.getSchemeInformation().getNextUpdate();
		if (nextUpdate != null) {
			return convertToDate(nextUpdate.getDateTime());
		}
		return null;
	}

	private List<String> getDistributionPoints(TrustStatusListType tsl) {
		NonEmptyURIListType distributionPoints = tsl.getSchemeInformation().getDistributionPoints();
		if (distributionPoints != null) {
			return distributionPoints.getURI();
		}
		return new ArrayList<String>();
	}

	private Date convertToDate(XMLGregorianCalendar gregorianCalendar) {
		if (gregorianCalendar != null) {
			GregorianCalendar toGregorianCalendar = gregorianCalendar.toGregorianCalendar();
			if (toGregorianCalendar != null) {
				return toGregorianCalendar.getTime();
			}
		}
		return null;
	}

	private List<TSLPointer> getMachineProcessableTSLPointers(TrustStatusListType tsl) {
		List<TSLPointer> list = new ArrayList<TSLPointer>();
		List<TSLPointer> tslPointers = getTSLPointers(tsl);
		if (CollectionUtils.isNotEmpty(tslPointers)) {
			for (TSLPointer tslPointer : tslPointers) {
				if (TSL_MIME_TYPE.equals(tslPointer.getMimeType())) {
					list.add(tslPointer);
				}
			}
		}
		return list;
	}

	private List<TSLPointer> getTSLPointers(TrustStatusListType tsl) {
		List<TSLPointer> list = new ArrayList<TSLPointer>();
		if ((tsl.getSchemeInformation() != null) && (tsl.getSchemeInformation().getPointersToOtherTSL() != null)) {
			List<OtherTSLPointerType> pointers = tsl.getSchemeInformation().getPointersToOtherTSL().getOtherTSLPointer();
			for (OtherTSLPointerType otherTSLPointerType : pointers) {
				list.add(getPointerInfos(otherTSLPointerType));
			}
		}
		return list;
	}

	private TSLPointer getPointerInfos(OtherTSLPointerType otherTSLPointerType) {
		TSLPointer pointer = new TSLPointer();
		pointer.setUrl(otherTSLPointerType.getTSLLocation());
		pointer.setPotentialSigners(getPotentialSigners(otherTSLPointerType));
		fillPointerTerritoryAndMimeType(otherTSLPointerType, pointer);
		return pointer;
	}

	private void fillPointerTerritoryAndMimeType(OtherTSLPointerType otherTSLPointerType, TSLPointer pointer) {
		List<Serializable> textualInformationOrOtherInformation = otherTSLPointerType.getAdditionalInformation().getTextualInformationOrOtherInformation();
		if (CollectionUtils.isNotEmpty(textualInformationOrOtherInformation)) {
			Map<String, String> properties = new HashMap<String, String>();
			for (Serializable serializable : textualInformationOrOtherInformation) {
				if (serializable instanceof AnyType) {
					AnyType anyInfo = (AnyType) serializable;
					for (Object content : anyInfo.getContent()) {
						if (content instanceof JAXBElement) {
							@SuppressWarnings("rawtypes")
							JAXBElement jaxbElement = (JAXBElement) content;
							properties.put(jaxbElement.getName().toString(), jaxbElement.getValue().toString());
						} else if (content instanceof Element) {
							Element element = (Element) content;
							properties.put("{" + element.getNamespaceURI() + "}" + element.getLocalName(), element.getTextContent());
						}
					}
				}
			}
			pointer.setMimeType(properties.get("{http://uri.etsi.org/02231/v2/additionaltypes#}MimeType"));
			pointer.setTerritory(properties.get("{http://uri.etsi.org/02231/v2#}SchemeTerritory"));
		}
	}

	private List<CertificateToken> getPotentialSigners(OtherTSLPointerType otherTSLPointerType) {
		List<CertificateToken> list = new ArrayList<CertificateToken>();
		if (otherTSLPointerType.getServiceDigitalIdentities() != null) {
			List<DigitalIdentityListType> serviceDigitalIdentity = otherTSLPointerType.getServiceDigitalIdentities().getServiceDigitalIdentity();
			extractCertificates(serviceDigitalIdentity, list);
		}
		return list;
	}

	private void extractCertificates(List<DigitalIdentityListType> serviceDigitalIdentity, List<CertificateToken> result) {
		for (DigitalIdentityListType digitalIdentityListType : serviceDigitalIdentity) {
			List<CertificateToken> certificates = extractCertificates(digitalIdentityListType);
			if (CollectionUtils.isNotEmpty(certificates)) {
				result.addAll(certificates);
			}
		}
	}

	private List<CertificateToken> extractCertificates(DigitalIdentityListType digitalIdentityListType) {
		List<CertificateToken> certificates = new ArrayList<CertificateToken>();
		List<DigitalIdentityType> digitalIds = digitalIdentityListType.getDigitalId();
		for (DigitalIdentityType digitalId : digitalIds) {
			if (digitalId.getX509Certificate() != null) {
				try {
					CertificateToken certificate = DSSUtils.loadCertificate(digitalId.getX509Certificate());
					certificates.add(certificate);
				} catch (Exception e) {
					logger.warn("Unable to load certificate : " + e.getMessage(), e);
				}
			}
		}
		return certificates;
	}

	private List<X500Principal> extractX500Principals(DigitalIdentityListType digitalIdentityListType) {
		List<X500Principal> result = new ArrayList<X500Principal>();
		List<DigitalIdentityType> digitalIds = digitalIdentityListType.getDigitalId();
		for (DigitalIdentityType digitalId : digitalIds) {
			if (digitalId.getX509SubjectName() != null) {
				try {
					X500Principal x500Principal = DSSUtils.getX500Principal(digitalId.getX509SubjectName());
					result.add(x500Principal);
				} catch (Exception e) {
					logger.warn("Unable to load X500Principal : " + e.getMessage());
				}
			}
		}
		return result;
	}

	private List<TSLServiceProvider> getServiceProviders(TrustStatusListType tsl) {
		List<TSLServiceProvider> serviceProviders = new ArrayList<TSLServiceProvider>();
		TrustServiceProviderListType trustServiceProviderList = tsl.getTrustServiceProviderList();
		if ((trustServiceProviderList != null) && (CollectionUtils.isNotEmpty(trustServiceProviderList.getTrustServiceProvider()))) {
			for (TSPType tsp : trustServiceProviderList.getTrustServiceProvider()) {
				serviceProviders.add(getServiceProvider(tsp));
			}
		}
		return serviceProviders;
	}

	private TSLServiceProvider getServiceProvider(TSPType tsp) {
		TSLServiceProvider serviceProvider = new TSLServiceProvider();
		TSPInformationType tspInformation = tsp.getTSPInformation();
		if (tspInformation != null) {
			serviceProvider.setName(getEnglishOrFirst(tspInformation.getTSPName()));
			serviceProvider.setTradeName(getEnglishOrFirst(tspInformation.getTSPTradeName()));
			serviceProvider.setPostalAddress(getPostalAddress(tspInformation));
			serviceProvider.setElectronicAddress(getElectronicAddress(tspInformation));
			serviceProvider.setServices(getServices(tsp.getTSPServices()));
		}
		return serviceProvider;
	}

	private List<TSLService> getServices(TSPServicesListType tspServices) {
		List<TSLService> services = new ArrayList<TSLService>();
		if ((tspServices != null) && CollectionUtils.isNotEmpty(tspServices.getTSPService())) {
			Date previousStartDate = null;
			for (TSPServiceType tslService : tspServices.getTSPService()) {
				if (tslService.getServiceInformation() != null) {
					TSLService service = getService(tslService.getServiceInformation());
					previousStartDate = service.getStartDate();
					services.add(service);
				}
				ServiceHistoryType serviceHistory = tslService.getServiceHistory();
				if ((serviceHistory != null) && CollectionUtils.isNotEmpty(serviceHistory.getServiceHistoryInstance())) {
					for (ServiceHistoryInstanceType serviceHistoryInstance : serviceHistory.getServiceHistoryInstance()) {
						TSLService service = getService(serviceHistoryInstance, previousStartDate);
						previousStartDate = service.getStartDate();
						services.add(service);
					}
				}
			}
		}
		return services;
	}

	private TSLService getService(TSPServiceInformationType serviceInfo) {
		TSLService service = new TSLService();
		service.setName(getEnglishOrFirst(serviceInfo.getServiceName()));
		service.setStatus(serviceInfo.getServiceStatus());
		service.setStartDate(convertToDate(serviceInfo.getStatusStartingTime()));
		service.setType(serviceInfo.getServiceTypeIdentifier());
		service.setCertificateUrls(extractCertificatesUrls(serviceInfo));
		service.setCertificates(extractCertificates(serviceInfo.getServiceDigitalIdentity()));
		service.setX500Principals(extractX500Principals(serviceInfo.getServiceDigitalIdentity()));
		service.setExtensions(extractExtensions(serviceInfo.getServiceInformationExtensions()));
		return service;
	}

	private List<String> extractCertificatesUrls(TSPServiceInformationType serviceInfo) {
		List<String> certificateUrls = new ArrayList<String>();
		if ((serviceInfo.getSchemeServiceDefinitionURI() != null) && CollectionUtils.isNotEmpty(serviceInfo.getSchemeServiceDefinitionURI().getURI())) {
			List<NonEmptyMultiLangURIType> uris = serviceInfo.getSchemeServiceDefinitionURI().getURI();
			for (NonEmptyMultiLangURIType uri : uris) {
				String value = uri.getValue();
				if (isCertificateURI(value)) {
					certificateUrls.add(value);
				}
			}
		}
		return certificateUrls;
	}

	private boolean isCertificateURI(String value) {
		return StringUtils.endsWithIgnoreCase(value, ".crt");
	}

	private TSLService getService(ServiceHistoryInstanceType serviceHistory, Date endDate) {
		TSLService service = new TSLService();
		service.setName(getEnglishOrFirst(serviceHistory.getServiceName()));
		service.setStatus(serviceHistory.getServiceStatus());
		service.setType(serviceHistory.getServiceTypeIdentifier());
		service.setStartDate(convertToDate(serviceHistory.getStatusStartingTime()));
		service.setEndDate(endDate);
		service.setCertificateUrls(new ArrayList<String>());
		service.setCertificates(extractCertificates(serviceHistory.getServiceDigitalIdentity()));
		service.setX500Principals(extractX500Principals(serviceHistory.getServiceDigitalIdentity()));
		service.setExtensions(extractExtensions(serviceHistory.getServiceInformationExtensions()));
		return service;
	}

	@SuppressWarnings("rawtypes")
	private List<TSLServiceExtension> extractExtensions(ExtensionsListType serviceInformationExtensions) {
		if ((serviceInformationExtensions != null) && CollectionUtils.isNotEmpty(serviceInformationExtensions.getExtension())) {
			List<TSLServiceExtension> extensions = new ArrayList<TSLServiceExtension>();
			for (ExtensionType extensionType : serviceInformationExtensions.getExtension()) {
				List<Object> content = extensionType.getContent();
				if (CollectionUtils.isNotEmpty(content)) {
					List<TSLConditionsForQualifiers> conditionsForQualifiers = new ArrayList<TSLConditionsForQualifiers>();
					for (Object object : content) {
						if (object instanceof JAXBElement) {
							JAXBElement jaxbElement = (JAXBElement) object;
							Object objectValue = jaxbElement.getValue();
							if (objectValue instanceof QualificationsType) {
								QualificationsType qt = (QualificationsType) jaxbElement.getValue();
								if ((qt != null) && CollectionUtils.isNotEmpty(qt.getQualificationElement())) {
									for (QualificationElementType qualificationElement : qt.getQualificationElement()) {
										List<String> qualifiers = extractQualifiers(qualificationElement);
										Condition condition = getCondition(qualificationElement.getCriteriaList());
										if (CollectionUtils.isNotEmpty(qualifiers) && (condition != null)) {
											conditionsForQualifiers.add(new TSLConditionsForQualifiers(qualifiers, condition));
										}
									}
								}
							}
						}
					}
					if (CollectionUtils.isNotEmpty(conditionsForQualifiers)) {
						TSLServiceExtension extension = new TSLServiceExtension();
						extension.setCritical(extensionType.isCritical());
						extension.setConditionsForQualifiers(conditionsForQualifiers);
						extensions.add(extension);
					}
				}
			}
			return extensions;
		}
		return null;
	}

	private List<String> extractQualifiers(QualificationElementType qualificationElement) {
		List<String> qualifiers = new ArrayList<String>();
		QualifiersType qualifiersType = qualificationElement.getQualifiers();
		if ((qualifiersType != null) && CollectionUtils.isNotEmpty(qualifiersType.getQualifier())) {
			for (QualifierType qualitierType : qualifiersType.getQualifier()) {
				qualifiers.add(qualitierType.getUri());
			}
		}
		return qualifiers;
	}

	private Condition getCondition(CriteriaListType criteriaList) {
		MatchingCriteriaIndicator matchingCriteriaIndicator = MatchingCriteriaIndicator.valueOf(criteriaList.getAssert());
		CompositeCondition condition = new CriteriaListCondition(matchingCriteriaIndicator);
		addKeyUsageConditionsIfPresent(criteriaList.getKeyUsage(), condition);
		addPolicyIdConditionsIfPresent(criteriaList.getPolicySet(), condition);
		addCriteriaListConditionsIfPresent(criteriaList.getCriteriaList(), condition);
		return condition;
	}

	private void addPolicyIdConditionsIfPresent(List<PoliciesListType> policySet, CompositeCondition condition) {
		if (CollectionUtils.isNotEmpty(policySet)) {
			CompositeCondition policyIdConditions = new CompositeCondition();
			for (PoliciesListType policiesListType : policySet) {
				for (ObjectIdentifierType oidType : policiesListType.getPolicyIdentifier()) {
					IdentifierType identifier = oidType.getIdentifier();
					String id = identifier.getValue();

					// ES TSL :  <ns4:Identifier Qualifier="OIDAsURN">urn:oid:1.3.6.1.4.1.36035.1.3.1</ns4:Identifier>
					if (id.indexOf(':') >= 0) {
						id = id.substring(id.lastIndexOf(':') + 1);
					}

					policyIdConditions.addChild(new PolicyIdCondition(id));
				}
			}
			condition.addChild(policyIdConditions);
		}
	}

	private void addKeyUsageConditionsIfPresent(List<KeyUsageType> keyUsages, CompositeCondition condition) {
		if (CollectionUtils.isNotEmpty(keyUsages)) {
			CompositeCondition keyUsageConditions = new CompositeCondition();
			for (KeyUsageType keyUsageType : keyUsages) {
				for (KeyUsageBitType keyUsageBit : keyUsageType.getKeyUsageBit()) {
					keyUsageConditions.addChild(new KeyUsageCondition(keyUsageBit.getName(), keyUsageBit.isValue()));
				}
			}
			condition.addChild(keyUsageConditions);
		}
	}

	private void addCriteriaListConditionsIfPresent(List<CriteriaListType> criteriaList, CompositeCondition condition) {
		if (CollectionUtils.isNotEmpty(criteriaList)) {
			CompositeCondition compositeConditions = new CompositeCondition();
			for (CriteriaListType criteriaListType : criteriaList) {
				compositeConditions.addChild(getCondition(criteriaListType));
			}
			condition.addChild(compositeConditions);
		}
	}

	private String getPostalAddress(TSPInformationType tspInformation) {
		PostalAddressType a = null;
		if (tspInformation.getTSPAddress() == null) {
			return null;
		}
		for (PostalAddressType c : tspInformation.getTSPAddress().getPostalAddresses().getPostalAddress()) {
			if ("en".equalsIgnoreCase(c.getLang())) {
				a = c;
				break;
			}
		}
		if (a == null) {
			a = tspInformation.getTSPAddress().getPostalAddresses().getPostalAddress().get(0);
		}

		StringBuffer sb = new StringBuffer();
		if (StringUtils.isNotEmpty(a.getStreetAddress())) {
			sb.append(a.getStreetAddress());
			sb.append(", ");
		}
		if (StringUtils.isNotEmpty(a.getPostalCode())) {
			sb.append(a.getPostalCode());
			sb.append(", ");
		}
		if (StringUtils.isNotEmpty(a.getLocality())) {
			sb.append(a.getLocality());
			sb.append(", ");
		}
		if (StringUtils.isNotEmpty(a.getStateOrProvince())) {
			sb.append(a.getStateOrProvince());
			sb.append(", ");
		}
		if (StringUtils.isNotEmpty(a.getCountryName())) {
			sb.append(a.getCountryName());
		}
		return sb.toString();
	}

	private String getElectronicAddress(TSPInformationType tspInformation) {
		if (tspInformation.getTSPAddress().getElectronicAddress() == null) {
			return null;
		}
		return tspInformation.getTSPAddress().getElectronicAddress().getURI().get(0).getValue();
	}

	private String getEnglishOrFirst(InternationalNamesType names) {
		if (names == null) {
			return null;
		}
		for (MultiLangNormStringType s : names.getName()) {
			if ("en".equalsIgnoreCase(s.getLang())) {
				return s.getValue();
			}
		}
		return names.getName().get(0).getValue();
	}

}
