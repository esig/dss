package eu.europa.esig.dss.tsl.service;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.datatype.XMLGregorianCalendar;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.tsl.TSLPointer;
import eu.europa.esig.dss.tsl.TSLPointerImpl;
import eu.europa.esig.dss.tsl.TSLValidationModel;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.jaxb.tsl.AnyType;
import eu.europa.esig.jaxb.tsl.DigitalIdentityListType;
import eu.europa.esig.jaxb.tsl.DigitalIdentityType;
import eu.europa.esig.jaxb.tsl.NextUpdateType;
import eu.europa.esig.jaxb.tsl.NonEmptyURIListType;
import eu.europa.esig.jaxb.tsl.ObjectFactory;
import eu.europa.esig.jaxb.tsl.OtherTSLPointerType;
import eu.europa.esig.jaxb.tsl.TrustStatusListType;

public class TSLParser {

	private static final Logger logger = LoggerFactory.getLogger(TSLParser.class);

	private static final String TSL_MIME_TYPE = "application/vnd.etsi.tsl+xml";

	private static final JAXBContext jaxbContext;

	static {
		try {
			jaxbContext = JAXBContext.newInstance(ObjectFactory.class);
		} catch (JAXBException e) {
			throw new DSSException("Unable to initialize JaxB : " + e.getMessage(), e);
		}
	}

	public TSLValidationModel parseTSL(File file) {
		FileInputStream fis = null;
		try {
			fis = new FileInputStream(file);
			return parseTSL(fis);
		} catch (IOException e) {
			throw new DSSException("Unable to parse file '" + file.getName() + "' : " + e.getMessage(), e);
		} finally {
			IOUtils.closeQuietly(fis);
		}
	}

	@SuppressWarnings("unchecked")
	public TSLValidationModel parseTSL(InputStream is) {
		try {
			Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
			JAXBElement<TrustStatusListType> jaxbElement = (JAXBElement<TrustStatusListType>) unmarshaller.unmarshal(is);
			TrustStatusListType trustStatusList = jaxbElement.getValue();
			return getTslModel(trustStatusList);
		} catch (JAXBException e) {
			throw new DSSException("Unable to parse inputstream : " + e.getMessage(), e);
		}
	}

	private TSLValidationModel getTslModel(TrustStatusListType tsl) {
		TSLValidationModel tslModel = new TSLValidationModel();
		tslModel.setTerritory(getTerritory(tsl));
		tslModel.setSequenceNumber(getSequenceNumber(tsl));
		tslModel.setIssueDate(getIssueDate(tsl));
		tslModel.setNextUpdateDate(getNextUpdate(tsl));
		tslModel.setDistributionPoints(getDistributionPoints(tsl));
		tslModel.setPointers(getMachineProcessableTSLPointers(tsl));
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
		TSLPointerImpl pointer = new TSLPointerImpl();
		pointer.setXmlUrl(otherTSLPointerType.getTSLLocation());
		pointer.setPotentialSigners(getPotentialSigners(otherTSLPointerType));
		fillPointerTerritoryAndMimeType(otherTSLPointerType, pointer);
		return pointer;
	}

	private void fillPointerTerritoryAndMimeType(OtherTSLPointerType otherTSLPointerType, TSLPointerImpl pointer) {
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
			for (DigitalIdentityListType digitalIdentityListType : serviceDigitalIdentity) {
				List<DigitalIdentityType> digitalIds = digitalIdentityListType.getDigitalId();
				boolean foundX509Cert = false;
				for (DigitalIdentityType digitalId : digitalIds) {
					if (digitalId.getX509Certificate() != null) {
						try {
							list.add(DSSUtils.loadCertificate(digitalId.getX509Certificate()));
						} catch (Exception e) {
							logger.warn("Unable to load certificate : " + e.getMessage(), e);
						}
						foundX509Cert = true;
					}
				}
				if (!foundX509Cert) {
					logger.warn("No base64 certificate found");
				}
			}
		}
		return list;
	}

}
