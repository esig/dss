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

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.datatype.XMLGregorianCalendar;

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
import eu.europa.esig.dss.tsl.TSLServiceProvider;
import eu.europa.esig.dss.tsl.TSLServiceStatusAndInformationExtensions;
import eu.europa.esig.dss.util.MutableTimeDependentValues;
import eu.europa.esig.dss.util.TimeDependentValues;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.jaxb.ecc.CriteriaListType;
import eu.europa.esig.jaxb.ecc.KeyUsageBitType;
import eu.europa.esig.jaxb.ecc.KeyUsageType;
import eu.europa.esig.jaxb.ecc.PoliciesListType;
import eu.europa.esig.jaxb.ecc.QualificationElementType;
import eu.europa.esig.jaxb.ecc.QualificationsType;
import eu.europa.esig.jaxb.ecc.QualifierType;
import eu.europa.esig.jaxb.ecc.QualifiersType;
import eu.europa.esig.jaxb.tsl.AdditionalServiceInformationType;
import eu.europa.esig.jaxb.tsl.AnyType;
import eu.europa.esig.jaxb.tsl.DigitalIdentityListType;
import eu.europa.esig.jaxb.tsl.DigitalIdentityType;
import eu.europa.esig.jaxb.tsl.ExtensionType;
import eu.europa.esig.jaxb.tsl.ExtensionsListType;
import eu.europa.esig.jaxb.tsl.InternationalNamesType;
import eu.europa.esig.jaxb.tsl.MultiLangNormStringType;
import eu.europa.esig.jaxb.tsl.NextUpdateType;
import eu.europa.esig.jaxb.tsl.NonEmptyMultiLangURIListType;
import eu.europa.esig.jaxb.tsl.NonEmptyMultiLangURIType;
import eu.europa.esig.jaxb.tsl.NonEmptyURIListType;
import eu.europa.esig.jaxb.tsl.ObjectFactory;
import eu.europa.esig.jaxb.tsl.OtherTSLPointerType;
import eu.europa.esig.jaxb.tsl.PostalAddressType;
import eu.europa.esig.jaxb.tsl.ServiceHistoryInstanceType;
import eu.europa.esig.jaxb.tsl.TSPInformationType;
import eu.europa.esig.jaxb.tsl.TSPServiceInformationType;
import eu.europa.esig.jaxb.tsl.TSPServiceType;
import eu.europa.esig.jaxb.tsl.TSPServicesListType;
import eu.europa.esig.jaxb.tsl.TSPType;
import eu.europa.esig.jaxb.tsl.TrustServiceProviderListType;
import eu.europa.esig.jaxb.tsl.TrustStatusListType;
import eu.europa.esig.jaxb.xades.IdentifierType;
import eu.europa.esig.jaxb.xades.ObjectIdentifierType;

/**
 * This class allows to parse a TSL from JAXB object to DTO's. It can be executed as a Callable
 */
public class TSLParser implements Callable<TSLParserResult> {

	private static final Logger logger = LoggerFactory.getLogger(TSLParser.class);

	private static final String ENGLISH_LANGUAGE = "en";

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
		tslModel.setVersion(getVersion(tsl));
		tslModel.setIssueDate(getIssueDate(tsl));
		tslModel.setNextUpdateDate(getNextUpdate(tsl));
		tslModel.setDistributionPoints(getDistributionPoints(tsl));
		tslModel.setPointers(getMachineProcessableTSLPointers(tsl));
		tslModel.setServiceProviders(getServiceProviders(tsl));
		tslModel.setEnglishSchemeInformationURIs(getEnglishSchemeInformationURIs(tsl));
		return tslModel;
	}

	private int getVersion(TrustStatusListType tsl) {
		BigInteger tslVersionIdentifier = tsl.getSchemeInformation().getTSLVersionIdentifier();
		if (tslVersionIdentifier != null) {
			return tslVersionIdentifier.intValue();
		}
		return -1;
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
		if (Utils.isCollectionNotEmpty(tslPointers)) {
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
		if (Utils.isCollectionNotEmpty(textualInformationOrOtherInformation)) {
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
			if (Utils.isCollectionNotEmpty(certificates)) {
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

	private List<TSLServiceProvider> getServiceProviders(TrustStatusListType tsl) {
		List<TSLServiceProvider> serviceProviders = new ArrayList<TSLServiceProvider>();
		TrustServiceProviderListType trustServiceProviderList = tsl.getTrustServiceProviderList();
		if ((trustServiceProviderList != null) && (Utils.isCollectionNotEmpty(trustServiceProviderList.getTrustServiceProvider()))) {
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
		if ((tspServices != null) && Utils.isCollectionNotEmpty(tspServices.getTSPService())) {
			for (TSPServiceType tslService : tspServices.getTSPService()) {
				if (tslService.getServiceInformation() != null) {
					services.add(getService(tslService));
				}
			}
		}
		return services;
	}

	private TSLService getService(TSPServiceType tslService) {
		TSLService service = new TSLService();
		TSPServiceInformationType serviceInfo = tslService.getServiceInformation();
		service.setName(getEnglishOrFirst(serviceInfo.getServiceName()));
		service.setCertificates(extractCertificates(serviceInfo.getServiceDigitalIdentity()));
		service.setStatusAndInformationExtensions(getStatusHistory(tslService));
		return service;
	}

	private TimeDependentValues<TSLServiceStatusAndInformationExtensions> getStatusHistory(TSPServiceType tslService) {
		MutableTimeDependentValues<TSLServiceStatusAndInformationExtensions> statusHistoryList = new MutableTimeDependentValues<TSLServiceStatusAndInformationExtensions>();

		TSPServiceInformationType serviceInfo = tslService.getServiceInformation();

		TSLServiceStatusAndInformationExtensions status = new TSLServiceStatusAndInformationExtensions();
		status.setType(serviceInfo.getServiceTypeIdentifier());
		status.setStatus(serviceInfo.getServiceStatus());
		ExtensionsListType serviceInformationExtensions = serviceInfo.getServiceInformationExtensions();
		if (serviceInformationExtensions != null) {
			status.setConditionsForQualifiers(extractConditionsForQualifiers(serviceInformationExtensions.getExtension()));
			status.setAdditionalServiceInfoUris(extractAdditionalServiceInfoUris(serviceInformationExtensions.getExtension()));
			status.setExpiredCertsRevocationInfo(extractExpiredCertsRevocationInfo(serviceInformationExtensions.getExtension()));
		}
		Date nextEndDate = convertToDate(serviceInfo.getStatusStartingTime());
		status.setStartDate(nextEndDate);
		statusHistoryList.addOldest(status);

		if (tslService.getServiceHistory() != null && Utils.isCollectionNotEmpty(tslService.getServiceHistory().getServiceHistoryInstance())) {
			for (ServiceHistoryInstanceType serviceHistory : tslService.getServiceHistory().getServiceHistoryInstance()) {
				TSLServiceStatusAndInformationExtensions statusHistory = new TSLServiceStatusAndInformationExtensions();
				statusHistory.setType(serviceHistory.getServiceTypeIdentifier());
				statusHistory.setStatus(serviceHistory.getServiceStatus());
				ExtensionsListType serviceHistoryInformationExtensions = serviceHistory.getServiceInformationExtensions();
				if (serviceHistoryInformationExtensions != null) {
					statusHistory.setConditionsForQualifiers(extractConditionsForQualifiers(serviceHistoryInformationExtensions.getExtension()));
					statusHistory.setAdditionalServiceInfoUris(extractAdditionalServiceInfoUris(serviceHistoryInformationExtensions.getExtension()));
					statusHistory.setExpiredCertsRevocationInfo(extractExpiredCertsRevocationInfo(serviceHistoryInformationExtensions.getExtension()));
				}
				statusHistory.setEndDate(nextEndDate);
				nextEndDate = convertToDate(serviceHistory.getStatusStartingTime());
				statusHistory.setStartDate(nextEndDate);
				statusHistoryList.addOldest(statusHistory);
			}
		}

		return statusHistoryList;
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
							if (uri != null && ENGLISH_LANGUAGE.equals(uri.getLang())) {
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
	private List<TSLConditionsForQualifiers> extractConditionsForQualifiers(List<ExtensionType> extensions) {
		List<TSLConditionsForQualifiers> conditionsForQualifiers = new ArrayList<TSLConditionsForQualifiers>();
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
										conditionsForQualifiers.add(new TSLConditionsForQualifiers(qualifiers, condition));

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
	private Date extractExpiredCertsRevocationInfo(List<ExtensionType> extensions) {
		for (ExtensionType extensionType : extensions) {
			List<Object> content = extensionType.getContent();
			if (Utils.isCollectionNotEmpty(content)) {
				for (Object object : content) {
					if (object instanceof JAXBElement) {
						JAXBElement jaxbElement = (JAXBElement) object;
						Object objectValue = jaxbElement.getValue();
						if (objectValue instanceof XMLGregorianCalendar) {
							XMLGregorianCalendar calendar = (XMLGregorianCalendar) objectValue;
							if (calendar != null) {
								return calendar.toGregorianCalendar().getTime();
							}
						}

					}
				}
			}
		}
		return null;
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
		MatchingCriteriaIndicator matchingCriteriaIndicator = MatchingCriteriaIndicator.valueOf(criteriaList.getAssert());
		CompositeCondition condition = new CriteriaListCondition(matchingCriteriaIndicator);

		addKeyUsageConditionsIfPresent(criteriaList.getKeyUsage(), condition);
		addPolicyIdConditionsIfPresent(criteriaList.getPolicySet(), condition);
		addCriteriaListConditionsIfPresent(criteriaList.getCriteriaList(), condition);

		return condition;
	}

	private void addPolicyIdConditionsIfPresent(List<PoliciesListType> policySet, CompositeCondition criteriaCondition) {
		if (Utils.isCollectionNotEmpty(policySet)) {
			for (PoliciesListType policiesListType : policySet) {
				CompositeCondition condition = new CompositeCondition();
				for (ObjectIdentifierType oidType : policiesListType.getPolicyIdentifier()) {
					IdentifierType identifier = oidType.getIdentifier();
					String id = identifier.getValue();

					// ES TSL : <ns4:Identifier Qualifier="OIDAsURN">urn:oid:1.3.6.1.4.1.36035.1.3.1</ns4:Identifier>
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

	private String getPostalAddress(TSPInformationType tspInformation) {
		PostalAddressType a = null;
		if (tspInformation.getTSPAddress() == null) {
			return null;
		}
		for (PostalAddressType c : tspInformation.getTSPAddress().getPostalAddresses().getPostalAddress()) {
			if (ENGLISH_LANGUAGE.equalsIgnoreCase(c.getLang())) {
				a = c;
				break;
			}
		}
		if (a == null) {
			a = tspInformation.getTSPAddress().getPostalAddresses().getPostalAddress().get(0);
		}

		StringBuffer sb = new StringBuffer();
		if (Utils.isStringNotEmpty(a.getStreetAddress())) {
			sb.append(a.getStreetAddress());
			sb.append(", ");
		}
		if (Utils.isStringNotEmpty(a.getPostalCode())) {
			sb.append(a.getPostalCode());
			sb.append(", ");
		}
		if (Utils.isStringNotEmpty(a.getLocality())) {
			sb.append(a.getLocality());
			sb.append(", ");
		}
		if (Utils.isStringNotEmpty(a.getStateOrProvince())) {
			sb.append(a.getStateOrProvince());
			sb.append(", ");
		}
		if (Utils.isStringNotEmpty(a.getCountryName())) {
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
			if (ENGLISH_LANGUAGE.equalsIgnoreCase(s.getLang())) {
				return s.getValue();
			}
		}
		return names.getName().get(0).getValue();
	}

	private List<String> getEnglishSchemeInformationURIs(TrustStatusListType tsl) {
		List<String> result = new ArrayList<String>();
		NonEmptyMultiLangURIListType schemeInformationURI = tsl.getSchemeInformation().getSchemeInformationURI();
		if (schemeInformationURI != null && Utils.isCollectionNotEmpty(schemeInformationURI.getURI())) {
			for (NonEmptyMultiLangURIType uri : schemeInformationURI.getURI()) {
				if (ENGLISH_LANGUAGE.equals(uri.getLang())) {
					result.add(uri.getValue());
				}
			}
		}
		return result;
	}

}
