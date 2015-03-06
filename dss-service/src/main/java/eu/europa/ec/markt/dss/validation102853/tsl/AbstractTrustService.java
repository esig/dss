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
package eu.europa.ec.markt.dss.validation102853.tsl;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.security.auth.x500.X500Principal;
import javax.xml.bind.JAXBElement;
import javax.xml.datatype.XMLGregorianCalendar;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.TSLConstant;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.exception.DSSNotETSICompliantException;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;
import eu.europa.ec.markt.dss.validation102853.condition.CompositeCondition;
import eu.europa.ec.markt.dss.validation102853.condition.Condition;
import eu.europa.ec.markt.dss.validation102853.condition.CriteriaListCondition;
import eu.europa.ec.markt.dss.validation102853.condition.KeyUsageCondition;
import eu.europa.ec.markt.dss.validation102853.condition.MatchingCriteriaIndicator;
import eu.europa.ec.markt.dss.validation102853.condition.PolicyIdCondition;
import eu.europa.ec.markt.dss.validation102853.condition.ServiceInfo;
import eu.europa.ec.markt.tsl.jaxb.ecc.CriteriaListType;
import eu.europa.ec.markt.tsl.jaxb.ecc.KeyUsageBitType;
import eu.europa.ec.markt.tsl.jaxb.ecc.KeyUsageType;
import eu.europa.ec.markt.tsl.jaxb.ecc.PoliciesListType;
import eu.europa.ec.markt.tsl.jaxb.ecc.QualificationElementType;
import eu.europa.ec.markt.tsl.jaxb.ecc.QualificationsType;
import eu.europa.ec.markt.tsl.jaxb.ecc.QualifierType;
import eu.europa.ec.markt.tsl.jaxb.ecc.QualifiersType;
import eu.europa.ec.markt.tsl.jaxb.tsl.AdditionalServiceInformationType;
import eu.europa.ec.markt.tsl.jaxb.tsl.DigitalIdentityListType;
import eu.europa.ec.markt.tsl.jaxb.tsl.DigitalIdentityType;
import eu.europa.ec.markt.tsl.jaxb.tsl.ExtensionType;
import eu.europa.ec.markt.tsl.jaxb.tslx.TakenOverByType;
import eu.europa.ec.markt.tsl.jaxb.xades.IdentifierType;
import eu.europa.ec.markt.tsl.jaxb.xades.ObjectIdentifierType;

/**
 * Service information from current status and TrustedList shares some common information.
 *
 *
 */

abstract class AbstractTrustService {

	private static final Logger LOG = LoggerFactory.getLogger(AbstractTrustService.class);

	public static final String TSLX = "TSLX";
	public static final String TSL = "TSL";
	public static final String ADDITIONAL_SERVICE_INFORMATION = "AdditionalServiceInformation";
	public static final String TAKEN_OVER_BY = "TakenOverBy";

	private Date expiredCertsRevocationInfo;

	/**
	 * @return
	 */
	abstract List<ExtensionType> getExtensions();

	/**
	 * @return
	 */
	abstract DigitalIdentityListType getServiceDigitalIdentity();

	/**
	 * @return
	 */
	abstract String getType();

	/**
	 * Return the status of the service
	 *
	 * @return
	 */
	abstract String getStatus();

	/**
	 * @return
	 */
	abstract Date getStatusStartDate();

	/**
	 * @return
	 */
	abstract Date getStatusEndDate();

	/**
	 * @return
	 */
	abstract String getServiceName();

	/**
	 * Returns the list of certificate representing the digital identity of this service.
	 *
	 * @return {@code List} of {@code Object} which can be {@code X509Certificate} or {@code X500Principal}
	 */
	List<Object> getDigitalIdentity() {

		final List<Object> certs = new ArrayList<Object>();
		for (final DigitalIdentityType digitalIdentity : getServiceDigitalIdentity().getDigitalId()) {

			try {

				final byte[] x509CertificateBytes = digitalIdentity.getX509Certificate();
				if (x509CertificateBytes != null) {

					final CertificateToken x509Certificate = DSSUtils.loadCertificate(x509CertificateBytes);
					// System.out.println(" ----- > " + x509Certificate.getSubjectX500Principal());
					certs.add(x509Certificate);
				} else {

					final String x509SubjectName = digitalIdentity.getX509SubjectName();
					if (x509SubjectName != null) {

						final X500Principal x500Principal = DSSUtils.getX500Principal(x509SubjectName);
						certs.add(x500Principal);
					}
				}
			} catch (DSSException e) {
				LOG.warn(e.getLocalizedMessage());
			}
		}
		return certs;
	}

	/**
	 * @return
	 */
	ServiceInfo createServiceInfo() {

		final ServiceInfo service = new ServiceInfo();
		final List<QualificationsType> qualificationList = getQualificationsType();
		for (final QualificationsType qualifications : qualificationList) {

			for (final QualificationElementType qualificationElement : qualifications.getQualificationElement()) {

				parseQualificationElement(qualificationElement, service);
			}
		}
		service.setExpiredCertsRevocationInfo(expiredCertsRevocationInfo);
		return service;
	}

	@SuppressWarnings("rawtypes")
	private List<QualificationsType> getQualificationsType() {

		final List<QualificationsType> qualificationList = new ArrayList<QualificationsType>();
		for (final ExtensionType extension : getExtensions()) {

			for (final Object object : extension.getContent()) {

				if (object instanceof String) {

                    /* do nothing */
					// if (DSSUtils.isBlank(object.toString())) {
					//
					// } else {
					//
					//    LOG.warn("Extension containing " + object.toString());
					//    throw new RuntimeException();
					// }
				} else if (object instanceof JAXBElement) {

					final JAXBElement jaxbElement = (JAXBElement) object;
					final Object objectValue = jaxbElement.getValue();
					if (objectValue instanceof AdditionalServiceInformationType) {

						// Do nothing
					} else if (objectValue instanceof QualificationsType) {

						qualificationList.add((QualificationsType) jaxbElement.getValue());
					} else if (objectValue instanceof TakenOverByType) {

						// Do nothing
					} else if (objectValue instanceof XMLGregorianCalendar) {

						// {http://uri.etsi.org/02231/v2#}ExpiredCertsRevocationInfo
						XMLGregorianCalendar xmlGregorianCalendar = (XMLGregorianCalendar) objectValue;
						expiredCertsRevocationInfo = xmlGregorianCalendar.toGregorianCalendar().getTime();
					} else {
						LOG.warn("Unrecognized extension class {}", jaxbElement.getValue().getClass());
					}
				} else if (object instanceof Element) {

                    /* We don't know what to do with the Element without further analysis */
					final Element element = (Element) object;
					final String localName = element.getLocalName();
					String namespaceUri = element.getNamespaceURI();
					if (ADDITIONAL_SERVICE_INFORMATION.equals(localName) && TSLConstant.TSL.equals(namespaceUri)) {

						// Do nothing
					} else if (TAKEN_OVER_BY.equals(localName) && TSLConstant.TSLX.equals(namespaceUri)) {

						// Do nothing
					} else {

						if (TSLConstant.TSLX.equals(namespaceUri)) {

							namespaceUri = TSLX;
						} else if (TSLConstant.TSL.equals(namespaceUri)) {

							namespaceUri = TSL;
						}
						throw new DSSNotETSICompliantException(DSSNotETSICompliantException.MSG.UNRECOGNIZED_TAG, namespaceUri + ":" + localName);
					}
				} else {
					throw new DSSException("Unknown extension " + object.getClass());
				}
			}
		}
		return qualificationList;
	}

	private void parseQualificationElement(final QualificationElementType qualificationElement, final ServiceInfo service) {

		final QualifiersType qualifierList = qualificationElement.getQualifiers();
		if (qualifierList == null || qualifierList.getQualifier().isEmpty()) {
			return;
		}
		try {

			final CriteriaListType criteriaList = qualificationElement.getCriteriaList();
			if (criteriaList != null) {

				if (criteriaList.getKeyUsage().isEmpty() && criteriaList.getPolicySet().isEmpty() && criteriaList.getCriteriaList().isEmpty()) {

					LOG.trace("CriteriaList for service is empty, the QualificationElement is skipped.");
					return;
				}
				final Condition compositeCondition = parseCriteriaList(criteriaList);
				for (QualifierType qualifier : qualifierList.getQualifier()) {

					service.addQualifierAndCondition(qualifier.getUri(), compositeCondition);
				}
			}
		} catch (IllegalArgumentException e) {

			throw new DSSNotETSICompliantException(DSSNotETSICompliantException.MSG.UNSUPPORTED_ASSERT);
		}
	}

	private Condition parseCriteriaList(final CriteriaListType criteriaList) {

		final String assertValue = criteriaList.getAssert();
		if (assertValue == null) {

			LOG.info("CriteriaList assert=null!");
			return null;
		}
		final boolean traceEnabled = LOG.isTraceEnabled();
		if (traceEnabled) {
			LOG.trace("--- > CriteriaList: assert: " + assertValue);
		}
		final MatchingCriteriaIndicator matchingCriteriaIndicator = MatchingCriteriaIndicator.valueOf(assertValue);

		final CompositeCondition condition = new CriteriaListCondition(matchingCriteriaIndicator);
		for (final PoliciesListType policies : criteriaList.getPolicySet()) {

			final CompositeCondition compositeCondition = new CompositeCondition();
			for (final ObjectIdentifierType objectIdentifier : policies.getPolicyIdentifier()) {

				final IdentifierType identifier = objectIdentifier.getIdentifier();
				if (identifier.getQualifier() == null) {

					if (traceEnabled) {
						LOG.trace("--- > CriteriaList: id1: " + identifier.getValue());
					}
					compositeCondition.addChild(new PolicyIdCondition(identifier.getValue()));
				} else {

					String id = identifier.getValue();
					// ES TSL
					// <ns4:Identifier Qualifier="OIDAsURN">urn:oid:1.3.6.1.4.1.36035.1.3.1</ns4:Identifier>
					if (id.indexOf(':') >= 0) {

						id = id.substring(id.lastIndexOf(':') + 1);
					}
					if (traceEnabled) {
						LOG.trace("--- > CriteriaList: id2: " + id);
					}
					compositeCondition.addChild(new PolicyIdCondition(id));
				}
			}
			condition.addChild(compositeCondition);
		}
		for (final KeyUsageType keyUsage : criteriaList.getKeyUsage()) {

			final CompositeCondition compositeCondition = new CompositeCondition();
			for (final KeyUsageBitType keyUsageBit : keyUsage.getKeyUsageBit()) {

				if (traceEnabled) {
					LOG.trace("--- > CriteriaList: kub: " + keyUsageBit.getName() + " [" + keyUsageBit.isValue() + "]");
				}
				final KeyUsageCondition keyUsageCondition = new KeyUsageCondition(keyUsageBit.getName(), keyUsageBit.isValue());
				compositeCondition.addChild(keyUsageCondition);
			}
			condition.addChild(compositeCondition);
		}
		for (final CriteriaListType criteria : criteriaList.getCriteriaList()) {

			if (traceEnabled) {
				LOG.trace("--- > CriteriaList: Composite Criteria List:");
			}
			final Condition compositeCondition = parseCriteriaList(criteria);
			condition.addChild(compositeCondition);
		}
		return condition;
	}
}
