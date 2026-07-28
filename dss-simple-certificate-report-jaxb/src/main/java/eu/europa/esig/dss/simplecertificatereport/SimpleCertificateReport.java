/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.simplecertificatereport;

import eu.europa.esig.dss.enumerations.CertificateApprovalStatus;
import eu.europa.esig.dss.enumerations.CertificateQualification;
import eu.europa.esig.dss.enumerations.CertificateApprovalStatusEnum;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.QWACProfile;
import eu.europa.esig.dss.enumerations.RevocationReason;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.jaxb.object.Message;
import eu.europa.esig.dss.simplecertificatereport.jaxb.XmlCertificateApprovalStatus;
import eu.europa.esig.dss.simplecertificatereport.jaxb.XmlCertificateApprovalStatusAtTime;
import eu.europa.esig.dss.simplecertificatereport.jaxb.XmlChainItem;
import eu.europa.esig.dss.simplecertificatereport.jaxb.XmlMessage;
import eu.europa.esig.dss.simplecertificatereport.jaxb.XmlRevocation;
import eu.europa.esig.dss.simplecertificatereport.jaxb.XmlSignature;
import eu.europa.esig.dss.simplecertificatereport.jaxb.XmlSimpleCertificateReport;
import eu.europa.esig.dss.simplecertificatereport.jaxb.XmlTrustAnchor;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * A SimpleCertificateReport holder to fetch values from a JAXB SimpleCertificateReport.
 */
public class SimpleCertificateReport {

	private final XmlSimpleCertificateReport simpleReport;

	/**
	 * Default constructor
	 *
	 * @param simpleReport {@link XmlSimpleCertificateReport}
	 */
	public SimpleCertificateReport(XmlSimpleCertificateReport simpleReport) {
		this.simpleReport = simpleReport;
	}

	/**
	 * This method returns the used validation time
	 * 
	 * @return the validation time
	 */
	public Date getValidationTime() {
		return simpleReport.getValidationTime();
	}

	/**
	 * This method returns a list of certificate ids
	 * 
	 * @return the list of certificate ids
	 */
	public List<String> getCertificateIds() {
		List<String> ids = new ArrayList<>();
		XmlChainItem certificate = simpleReport.getCertificate();
		if (certificate != null) {
			ids.add(certificate.getId());
			List<XmlChainItem> chain = certificate.getChain();
			for (XmlChainItem xmlChainItem : chain) {
				ids.add(xmlChainItem.getId());
			}
		}
		return ids;
	}

	/**
	 * This method returns the notBefore date for a given certificate
	 * 
	 * @param certificateId
	 *            the certificate id
	 * @return the notBefore date
	 */
	public Date getCertificateNotBefore(String certificateId) {
		XmlChainItem cert = getCertificate(certificateId);
		if (cert != null) {
			return cert.getNotBefore();
		}
		return null;
	}

	/**
	 * This method returns the notAfter date for a given certificate
	 * 
	 * @param certificateId
	 *            the certificate id
	 * @return the notAfter date
	 */
	public Date getCertificateNotAfter(String certificateId) {
		XmlChainItem cert = getCertificate(certificateId);
		if (cert != null) {
			return cert.getNotAfter();
		}
		return null;
	}

	/**
	 * This method returns the list of AIA urls (caIssuers) for a given certificate
	 * 
	 * @param certificateId
	 *            the certificate id
	 * @return the list of AIA urls
	 */
	public List<String> getCertificateAiaUrls(String certificateId) {
		XmlChainItem cert = getCertificate(certificateId);
		if (cert != null) {
			return cert.getAiaUrls();
		}
		return Collections.emptyList();
	}

	/**
	 * This method returns the list of CPS (Certificate Practice Statements) urls for a given certificate
	 * 
	 * @param certificateId
	 *            the certificate id
	 * @return the list of CPS urls
	 */
	public List<String> getCertificateCpsUrls(String certificateId) {
		XmlChainItem cert = getCertificate(certificateId);
		if (cert != null) {
			return cert.getCpsUrls();
		}
		return Collections.emptyList();
	}

	/**
	 * This method returns the list of CRL (Certificate Revocation List) urls for a given certificate
	 * 
	 * @param certificateId
	 *            the certificate id
	 * @return the list of CRL urls
	 */
	public List<String> getCertificateCrlUrls(String certificateId) {
		XmlChainItem cert = getCertificate(certificateId);
		if (cert != null) {
			return cert.getCrlUrls();
		}
		return Collections.emptyList();
	}

	/**
	 * This method returns the list of OCSP (Online Certificate Status Protocol) urls for a given certificate
	 * 
	 * @param certificateId
	 *            the certificate id
	 * @return the list of OCSP urls
	 */
	public List<String> getCertificateOcspUrls(String certificateId) {
		XmlChainItem cert = getCertificate(certificateId);
		if (cert != null) {
			return cert.getOcspUrls();
		}
		return Collections.emptyList();
	}

	/**
	 * This method returns the list of PDS (PKI Disclosure Statements) urls for a given certificate
	 * 
	 * @param certificateId
	 *            the certificate id
	 * @return the list of PDS urls
	 */
	public List<String> getCertificatePdsUrls(String certificateId) {
		XmlChainItem cert = getCertificate(certificateId);
		if (cert != null) {
			return cert.getPdsUrls();
		}
		return Collections.emptyList();
	}

	/**
	 * This method returns the commonName attribute for a given certificate
	 * 
	 * @param certificateId
	 *            the certificate id
	 * @return the commonName if available or null
	 */
	public String getCertificateCommonName(String certificateId) {
		XmlChainItem cert = getCertificate(certificateId);
		if (cert != null) {
			return cert.getSubject().getCommonName();
		}
		return null;
	}

	/**
	 * This method returns the email attribute for a given certificate
	 * 
	 * @param certificateId
	 *            the certificate id
	 * @return the email if available or null
	 */
	public String getCertificateEmail(String certificateId) {
		XmlChainItem cert = getCertificate(certificateId);
		if (cert != null) {
			return cert.getSubject().getEmail();
		}
		return null;
	}

	/**
	 * This method returns the givenName attribute for a given certificate
	 * 
	 * @param certificateId
	 *            the certificate id
	 * @return the givenName if available or null
	 */
	public String getCertificateGivenName(String certificateId) {
		XmlChainItem cert = getCertificate(certificateId);
		if (cert != null) {
			return cert.getSubject().getGivenName();
		}
		return null;
	}

	/**
	 * This method returns the locality attribute for a given certificate
	 * 
	 * @param certificateId
	 *            the certificate id
	 * @return the locality if available or null
	 */
	public String getCertificateLocality(String certificateId) {
		XmlChainItem cert = getCertificate(certificateId);
		if (cert != null) {
			return cert.getSubject().getLocality();
		}
		return null;
	}

	/**
	 * This method returns the state attribute for a given certificate
	 * 
	 * @param certificateId
	 *            the certificate id
	 * @return the state if available or null
	 */
	public String getCertificateState(String certificateId) {
		XmlChainItem cert = getCertificate(certificateId);
		if (cert != null) {
			return cert.getSubject().getState();
		}
		return null;
	}

	/**
	 * This method returns the country attribute for a given certificate
	 * 
	 * @param certificateId
	 *            the certificate id
	 * @return the country if available or null
	 */
	public String getCertificateCountry(String certificateId) {
		XmlChainItem cert = getCertificate(certificateId);
		if (cert != null) {
			return cert.getSubject().getCountry();
		}
		return null;
	}

	/**
	 * This method returns the organizationName attribute for a given certificate
	 * 
	 * @param certificateId
	 *            the certificate id
	 * @return the organizationName if available or null
	 */
	public String getCertificateOrganizationName(String certificateId) {
		XmlChainItem cert = getCertificate(certificateId);
		if (cert != null) {
			return cert.getSubject().getOrganizationName();
		}
		return null;
	}

	/**
	 * This method returns the organizationUnit attribute for a given certificate
	 * 
	 * @param certificateId
	 *            the certificate id
	 * @return the organizationUnit if available or null
	 */
	public String getCertificateOrganizationUnit(String certificateId) {
		XmlChainItem cert = getCertificate(certificateId);
		if (cert != null) {
			return cert.getSubject().getOrganizationUnit();
		}
		return null;
	}

	/**
	 * This method returns the pseudonym attribute for a given certificate
	 * 
	 * @param certificateId
	 *            the certificate id
	 * @return the pseudonym if available or null
	 */
	public String getCertificatePseudonym(String certificateId) {
		XmlChainItem cert = getCertificate(certificateId);
		if (cert != null) {
			return cert.getSubject().getPseudonym();
		}
		return null;
	}

	/**
	 * This method returns the surname attribute for a given certificate
	 * 
	 * @param certificateId
	 *            the certificate id
	 * @return the surname if available or null
	 */
	public String getCertificateSurname(String certificateId) {
		XmlChainItem cert = getCertificate(certificateId);
		if (cert != null) {
			return cert.getSubject().getSurname();
		}
		return null;
	}

	/**
	 * This method returns the {@link Indication} (result of validation) for a given certificate
	 * 
	 * @param certificateId
	 *            the certificate id
	 * @return the {@link Indication}
	 */
	public Indication getCertificateIndication(String certificateId) {
		XmlChainItem cert = getCertificate(certificateId);
		if (cert != null) {
			return cert.getIndication();
		}
		return null;
	}

	/**
	 * This method returns the {@link SubIndication} (result of validation) for a given certificate
	 * 
	 * @param certificateId
	 *            the certificate id
	 * @return the {@link SubIndication}
	 */
	public SubIndication getCertificateSubIndication(String certificateId) {
		XmlChainItem cert = getCertificate(certificateId);
		if (cert != null) {
			return cert.getSubIndication();
		}
		return null;
	}

	/**
	 * This method returns the revocation date for a given certificate
	 * 
	 * @param certificateId
	 *            the certificate id
	 * @return the revocation date or null
	 */
	public Date getCertificateRevocationDate(String certificateId) {
		XmlChainItem cert = getCertificate(certificateId);
		if (cert != null) {
			XmlRevocation revocation = cert.getRevocation();
			if (revocation != null) {
				return revocation.getRevocationDate();
			}
		}
		return null;
	}

	/**
	 * This method returns the revocation reason for a given certificate
	 * 
	 * @param certificateId
	 *            the certificate id
	 * @return the revocation reason or null
	 */
	public RevocationReason getCertificateRevocationReason(String certificateId) {
		XmlChainItem cert = getCertificate(certificateId);
		if (cert != null) {
			XmlRevocation revocation = cert.getRevocation();
			if (revocation != null) {
				return revocation.getRevocationReason();
			}
		}
		return null;
	}

	/**
	 * This method retrieve the ETSI EN 319 102-1 X.509 certificate validation errors for a given certificate by id
	 *
	 * @param certificateId
	 *            {@link String} certificate id
	 * @return the linked errors
	 */
	public List<Message> getX509ValidationErrors(final String certificateId) {
		XmlChainItem certificate = getCertificate(certificateId);
		if (certificate != null && certificate.getX509ValidationDetails() != null) {
			return convert(certificate.getX509ValidationDetails().getError());
		}
		return Collections.emptyList();
	}

	/**
	 * This method retrieve the ETSI EN 319 102-1 X.509 certificate validation warnings for a given certificate by id
	 *
	 * @param certificateId
	 *            {@link String} certificate id
	 * @return the linked warning messages
	 */
	public List<Message> getX509ValidationWarnings(final String certificateId) {
		XmlChainItem certificate = getCertificate(certificateId);
		if (certificate != null && certificate.getX509ValidationDetails() != null) {
			return convert(certificate.getX509ValidationDetails().getWarning());
		}
		return Collections.emptyList();
	}

	/**
	 * This method retrieve the ETSI EN 319 102-1 X.509 certificate validation information messages for a given certificate by id
	 *
	 * @param certificateId
	 *            {@link String} certificate id
	 * @return the linked information messages
	 */
	public List<Message> getX509ValidationInfo(final String certificateId) {
		XmlChainItem certificate = getCertificate(certificateId);
		if (certificate != null && certificate.getX509ValidationDetails() != null) {
			return convert(certificate.getX509ValidationDetails().getInfo());
		}
		return Collections.emptyList();
	}

	/**
	 * This method retrieve the qualification process's errors for a given certificate by id at issuance time
	 *
	 * @param certificateId
	 *            {@link String} certificate id
	 * @return the linked errors
	 */
	public List<Message> getQualificationErrorsAtIssuanceTime(final String certificateId) {
		XmlChainItem certificate = getCertificate(certificateId);
		if (certificate != null && certificate.getQualificationDetailsAtIssuance() != null) {
			return convert(certificate.getQualificationDetailsAtIssuance().getError());
		}
		return Collections.emptyList();
	}

	/**
	 * This method retrieve the qualification process's warnings for a given certificate by id at issuance time
	 *
	 * @param certificateId
	 *            {@link String} certificate id
	 * @return the linked warning messages
	 */
	public List<Message> getQualificationWarningsAtIssuanceTime(final String certificateId) {
		XmlChainItem certificate = getCertificate(certificateId);
		if (certificate != null && certificate.getQualificationDetailsAtIssuance() != null) {
			return convert(certificate.getQualificationDetailsAtIssuance().getWarning());
		}
		return Collections.emptyList();
	}

	/**
	 * This method retrieve the qualification process's information messages for a given certificate by id at issuance time
	 *
	 * @param certificateId
	 *            {@link String} certificate id
	 * @return the linked information messages
	 */
	public List<Message> getQualificationInfoAtIssuanceTime(final String certificateId) {
		XmlChainItem certificate = getCertificate(certificateId);
		if (certificate != null && certificate.getQualificationDetailsAtIssuance() != null) {
			return convert(certificate.getQualificationDetailsAtIssuance().getInfo());
		}
		return Collections.emptyList();
	}

	/**
	 * This method retrieve the qualification process's errors for a given certificate by id at validation time
	 *
	 * @param certificateId
	 *            {@link String} certificate id
	 * @return the linked errors
	 */
	public List<Message> getQualificationErrorsAtValidationTime(final String certificateId) {
		XmlChainItem certificate = getCertificate(certificateId);
		if (certificate != null && certificate.getQualificationDetailsAtValidation() != null) {
			return convert(certificate.getQualificationDetailsAtValidation().getError());
		}
		return Collections.emptyList();
	}

	/**
	 * This method retrieve the qualification process's warnings for a given certificate by id at validation time
	 *
	 * @param certificateId
	 *            {@link String} certificate id
	 * @return the linked warning messages
	 */
	public List<Message> getQualificationWarningsAtValidationTime(final String certificateId) {
		XmlChainItem certificate = getCertificate(certificateId);
		if (certificate != null && certificate.getQualificationDetailsAtValidation() != null) {
			return convert(certificate.getQualificationDetailsAtValidation().getWarning());
		}
		return Collections.emptyList();
	}

	/**
	 * This method retrieve the qualification process's information messages for a given certificate by id at validation time
	 *
	 * @param certificateId
	 *            {@link String} certificate id
	 * @return the linked information messages
	 */
	public List<Message> getQualificationInfoAtValidationTime(final String certificateId) {
		XmlChainItem certificate = getCertificate(certificateId);
		if (certificate != null && certificate.getQualificationDetailsAtValidation() != null) {
			return convert(certificate.getQualificationDetailsAtValidation().getInfo());
		}
		return Collections.emptyList();
	}

	/**
	 * This method retrieve the QWAC validation process's errors for a given certificate by id
	 *
	 * @param certificateId
	 *            {@link String} certificate id
	 * @return the linked errors
	 */
	public List<Message> getQWACValidationErrors(final String certificateId) {
		XmlChainItem certificate = getCertificate(certificateId);
		if (certificate != null && certificate.getQwacDetails() != null) {
			return convert(certificate.getQwacDetails().getError());
		}
		return Collections.emptyList();
	}

	/**
	 * This method retrieve the QWAC validation process's warnings for a given certificate by id
	 *
	 * @param certificateId
	 *            {@link String} certificate id
	 * @return the linked errors
	 */
	public List<Message> getQWACValidationWarnings(final String certificateId) {
		XmlChainItem certificate = getCertificate(certificateId);
		if (certificate != null && certificate.getQwacDetails() != null) {
			return convert(certificate.getQwacDetails().getWarning());
		}
		return Collections.emptyList();
	}

	/**
	 * This method retrieve the QWAC validation process's information messages for a given certificate by id
	 *
	 * @param certificateId
	 *            {@link String} certificate id
	 * @return the linked errors
	 */
	public List<Message> getQWACValidationInfo(final String certificateId) {
		XmlChainItem certificate = getCertificate(certificateId);
		if (certificate != null && certificate.getQwacDetails() != null) {
			return convert(certificate.getQwacDetails().getInfo());
		}
		return Collections.emptyList();
	}

	/**
	 * This method retrieve the TS 119 602/605 certificate approval status process's errors for
	 * a given certificate by id at issuance time for the given {@code CertificateApprovalStatus}
	 *
	 * @param certificateId
	 *            {@link String} certificate id
	 * @return the linked errors
	 */
	public List<Message> getCertificateApprovalStatusErrorsAtIssuanceTime(final String certificateId, final CertificateApprovalStatus certificateApprovalStatus) {
		XmlChainItem certificate = getCertificate(certificateId);
		if (certificate != null && certificate.getCertificateApprovalStatusAtIssuanceTime() != null) {
			XmlCertificateApprovalStatus xmlCertificateApprovalStatus = getXmlCertificateApprovalStatus(certificate.getCertificateApprovalStatusAtIssuanceTime(), certificateApprovalStatus);
			if (xmlCertificateApprovalStatus != null && xmlCertificateApprovalStatus.getDetails() != null) {
				return convert(xmlCertificateApprovalStatus.getDetails().getError());
			}
		}
		return Collections.emptyList();
	}

	/**
	 * This method retrieve the TS 119 602/605 certificate approval status process's warnings for
	 * a given certificate by id at issuance time for the given {@code CertificateApprovalStatus}
	 *
	 * @param certificateId
	 *            {@link String} certificate id
	 * @return the linked errors
	 */
	public List<Message> getCertificateApprovalStatusWarningsAtIssuanceTime(final String certificateId, final CertificateApprovalStatus certificateApprovalStatus) {
		XmlChainItem certificate = getCertificate(certificateId);
		if (certificate != null && certificate.getCertificateApprovalStatusAtIssuanceTime() != null) {
			XmlCertificateApprovalStatus xmlCertificateApprovalStatus = getXmlCertificateApprovalStatus(certificate.getCertificateApprovalStatusAtIssuanceTime(), certificateApprovalStatus);
			if (xmlCertificateApprovalStatus != null && xmlCertificateApprovalStatus.getDetails() != null) {
				return convert(xmlCertificateApprovalStatus.getDetails().getWarning());
			}
		}
		return Collections.emptyList();
	}

	/**
	 * This method retrieve the TS 119 602/605 certificate approval status process's information messages for
	 * a given certificate by id at issuance time for the given {@code CertificateApprovalStatus}
	 *
	 * @param certificateId
	 *            {@link String} certificate id
	 * @return the linked errors
	 */
	public List<Message> getCertificateApprovalStatusInfoAtIssuanceTime(final String certificateId, final CertificateApprovalStatus certificateApprovalStatus) {
		XmlChainItem certificate = getCertificate(certificateId);
		if (certificate != null && certificate.getCertificateApprovalStatusAtIssuanceTime() != null) {
			XmlCertificateApprovalStatus xmlCertificateApprovalStatus = getXmlCertificateApprovalStatus(certificate.getCertificateApprovalStatusAtIssuanceTime(), certificateApprovalStatus);
			if (xmlCertificateApprovalStatus != null && xmlCertificateApprovalStatus.getDetails() != null) {
				return convert(xmlCertificateApprovalStatus.getDetails().getInfo());
			}
		}
		return Collections.emptyList();
	}

	/**
	 * This method retrieve the TS 119 602/605 certificate approval status process's errors for
	 * a given certificate by id at validation time for the given {@code CertificateApprovalStatus}
	 *
	 * @param certificateId
	 *            {@link String} certificate id
	 * @return the linked errors
	 */
	public List<Message> getCertificateApprovalStatusErrorsAtValidationTime(final String certificateId, final CertificateApprovalStatus certificateApprovalStatus) {
		XmlChainItem certificate = getCertificate(certificateId);
		if (certificate != null && certificate.getCertificateApprovalStatusAtValidationTime() != null) {
			XmlCertificateApprovalStatus xmlCertificateApprovalStatus = getXmlCertificateApprovalStatus(certificate.getCertificateApprovalStatusAtValidationTime(), certificateApprovalStatus);
			if (xmlCertificateApprovalStatus != null && xmlCertificateApprovalStatus.getDetails() != null) {
				return convert(xmlCertificateApprovalStatus.getDetails().getError());
			}
		}
		return Collections.emptyList();
	}

	/**
	 * This method retrieve the TS 119 602/605 certificate approval status process's warnings for
	 * a given certificate by id at validation time for the given {@code CertificateApprovalStatus}
	 *
	 * @param certificateId
	 *            {@link String} certificate id
	 * @return the linked errors
	 */
	public List<Message> getCertificateApprovalStatusWarningsAtValidationTime(final String certificateId, final CertificateApprovalStatus certificateApprovalStatus) {
		XmlChainItem certificate = getCertificate(certificateId);
		if (certificate != null && certificate.getCertificateApprovalStatusAtValidationTime() != null) {
			XmlCertificateApprovalStatus xmlCertificateApprovalStatus = getXmlCertificateApprovalStatus(certificate.getCertificateApprovalStatusAtValidationTime(), certificateApprovalStatus);
			if (xmlCertificateApprovalStatus != null && xmlCertificateApprovalStatus.getDetails() != null) {
				return convert(xmlCertificateApprovalStatus.getDetails().getWarning());
			}
		}
		return Collections.emptyList();
	}

	/**
	 * This method retrieve the TS 119 602/605 certificate approval status process's information messages for
	 * a given certificate by id at validation time for the given {@code CertificateApprovalStatus}
	 *
	 * @param certificateId
	 *            {@link String} certificate id
	 * @return the linked errors
	 */
	public List<Message> getCertificateApprovalStatusInfoAtValidationTime(final String certificateId, final CertificateApprovalStatus certificateApprovalStatus) {
		XmlChainItem certificate = getCertificate(certificateId);
		if (certificate != null && certificate.getCertificateApprovalStatusAtValidationTime() != null) {
			XmlCertificateApprovalStatus xmlCertificateApprovalStatus = getXmlCertificateApprovalStatus(certificate.getCertificateApprovalStatusAtValidationTime(), certificateApprovalStatus);
			if (xmlCertificateApprovalStatus != null && xmlCertificateApprovalStatus.getDetails() != null) {
				return convert(xmlCertificateApprovalStatus.getDetails().getInfo());
			}
		}
		return Collections.emptyList();
	}

	private Message convert(XmlMessage v) {
		if (v != null) {
			return new Message(v.getKey(), v.getValue());
		}
		return null;
	}

	private List<Message> convert(Collection<XmlMessage> messages) {
		if (messages != null) {
			return messages.stream().map(this::convert).collect(Collectors.toList());
		}
		return Collections.emptyList();
	}

	/**
	 * This method returns the qualification of the first certificate at its issuance
	 * 
	 * @return the qualification at the certificate creation
	 */
	public CertificateQualification getQualificationAtCertificateIssuance() {
		XmlChainItem cert = getFirstCertificate();
		return cert.getQualificationAtIssuance();
	}

	/**
	 * This method returns the qualification of the first certificate at the validation time
	 *
	 * @return the qualification at the validation time
	 */
	public CertificateQualification getQualificationAtValidationTime() {
		XmlChainItem cert = getFirstCertificate();
		return cert.getQualificationAtValidation();
	}

	/**
	 * This method returns the qualification of the first certificate at its issuance
	 *
	 * @return the qualification at the certificate creation
	 */
	public List<CertificateApprovalStatus> getCertificateApprovalStatusAtCertificateIssuance() {
		XmlChainItem cert = getFirstCertificate();
		return toCertificateApprovalStatusList(cert.getCertificateApprovalStatusAtIssuanceTime());
	}

	/**
	 * This method returns the qualification of the first certificate at the validation time
	 *
	 * @return the qualification at the validation time
	 */
	public List<CertificateApprovalStatus> getCertificateApprovalStatusAtValidationTime() {
		XmlChainItem cert = getFirstCertificate();
		return toCertificateApprovalStatusList(cert.getCertificateApprovalStatusAtValidationTime());
	}

	private List<CertificateApprovalStatus> toCertificateApprovalStatusList(XmlCertificateApprovalStatusAtTime xmlCertificateApprovalStatusAtTime) {
		if (xmlCertificateApprovalStatusAtTime == null) {
			return null;
		}
		List<XmlCertificateApprovalStatus> xmlCertificateApprovalStatuss = xmlCertificateApprovalStatusAtTime.getCertificateApprovalStatus();
		if (xmlCertificateApprovalStatuss == null || xmlCertificateApprovalStatuss.isEmpty()) {
			return Collections.emptyList();
		}

		final List<CertificateApprovalStatus> usages = new ArrayList<>();
		for (XmlCertificateApprovalStatus xmlCertificateApprovalStatus : xmlCertificateApprovalStatuss) {
			usages.add(toCertificateApprovalStatus(xmlCertificateApprovalStatus));
		}
		return usages;
	}

	private CertificateApprovalStatus toCertificateApprovalStatus(XmlCertificateApprovalStatus xmlCertificateApprovalStatus) {
		if (xmlCertificateApprovalStatus == null) {
			return null;
		}
		CertificateApprovalStatus result = CertificateApprovalStatus.fromDefinition(xmlCertificateApprovalStatus.getListType(),
				xmlCertificateApprovalStatus.getServiceTypeIdentifier(), xmlCertificateApprovalStatus.getServiceStatus());
		if (result != null && result.getLabel() != null && CertificateApprovalStatusEnum.CERT_FOR_UNKNOWN != result) {
			return result;
		}
		return CertificateApprovalStatus.create(CertificateApprovalStatusEnum.CERT_FOR_UNKNOWN.getLabel(), xmlCertificateApprovalStatus.getListType(),
				xmlCertificateApprovalStatus.getServiceTypeIdentifier(), xmlCertificateApprovalStatus.getServiceStatus());
	}

	private XmlCertificateApprovalStatus getXmlCertificateApprovalStatus(XmlCertificateApprovalStatusAtTime xmlCertificateApprovalStatusAtTime, CertificateApprovalStatus certificateApprovalStatus) {
		if (xmlCertificateApprovalStatusAtTime != null && xmlCertificateApprovalStatusAtTime.getCertificateApprovalStatus() != null) {
			for (XmlCertificateApprovalStatus xmlCertificateApprovalStatus : xmlCertificateApprovalStatusAtTime.getCertificateApprovalStatus()) {
				if (xmlCertificateApprovalStatus != null &&
						certificateApprovalStatus.getListType() != null && certificateApprovalStatus.getListType().getUri() != null
						&& xmlCertificateApprovalStatus.getListType() != null && certificateApprovalStatus.getListType().getUri().equals(xmlCertificateApprovalStatus.getListType().getUri()) &&
						certificateApprovalStatus.getServiceTypeIdentifier() != null && certificateApprovalStatus.getServiceTypeIdentifier().getUri() != null
						&& xmlCertificateApprovalStatus.getServiceTypeIdentifier() != null && certificateApprovalStatus.getServiceTypeIdentifier().getUri().equals(xmlCertificateApprovalStatus.getServiceTypeIdentifier().getUri())) {
					return xmlCertificateApprovalStatus;
				}
			}
		}
		return null;
	}

	/**
	 * This method returns the QWAC validation result as per ETSI TS 119 411-5.
	 * NOTE: Applicable only when validation process is executed using the {@code eu.europa.esig.dss.validation.qwac.QWACValidator}
	 *
	 * @return {@link QWACProfile}
	 */
	public QWACProfile getQWACProfile() {
		XmlChainItem cert = getFirstCertificate();
		return cert.getQwacProfile();
	}

	/**
	 * Gets the TLS Certificate Binging signature.
	 * NOTE: Applicable only when validation process is executed using the {@code eu.europa.esig.dss.validation.qwac.QWACValidator}
	 *
	 * @return {@link XmlSignature}
	 */
	public XmlSignature getTLSBindingSignature() {
		XmlChainItem cert = getFirstCertificate();
		return cert.getTLSBindingSignature();
	}

	/**
	 * Gets the Indication for the TLS Certificate Binging signature validation.
	 * NOTE: Applicable only when validation process is executed using the {@code eu.europa.esig.dss.validation.qwac.QWACValidator}
	 *
	 * @return {@link Indication}
	 */
	public Indication getTLSBindingSignatureIndication() {
		XmlSignature tlsBindingSignature = getTLSBindingSignature();
		if (tlsBindingSignature != null) {
			return tlsBindingSignature.getIndication();
		}
		return null;
	}

	/**
	 * Gets the SubIndication for the TLS Certificate Binging signature validation.
	 * NOTE: Applicable only when validation process is executed using the {@code eu.europa.esig.dss.validation.qwac.QWACValidator}
	 *
	 * @return {@link SubIndication}
	 */
	public SubIndication getTLSBindingSignatureSubIndication() {
		XmlSignature tlsBindingSignature = getTLSBindingSignature();
		if (tlsBindingSignature != null) {
			return tlsBindingSignature.getSubIndication();
		}
		return null;
	}

	/**
	 * Gets the Indication for the TLS Certificate Binging signature validation.
	 * NOTE: Applicable only when validation process is executed using the {@code eu.europa.esig.dss.validation.qwac.QWACValidator}
	 *
	 * @return {@link Indication}
	 */
	public XmlChainItem getTLSBindingSignatureIssuerCertificate() {
		XmlSignature tlsBindingSignature = getTLSBindingSignature();
		if (tlsBindingSignature != null && tlsBindingSignature.getChain() != null && !tlsBindingSignature.getChain().isEmpty()) {
			return tlsBindingSignature.getChain().get(0);
		}
		return null;
	}

	/**
	 * This method returns the qualification of the first certificate at its issuance
	 *
	 * @return the qualification at the certificate creation
	 */
	public CertificateQualification getTLSBindingSignatureIssuerQualificationAtCertificateIssuance() {
		XmlChainItem xmlChainItem = getTLSBindingSignatureIssuerCertificate();
		if (xmlChainItem != null) {
			return xmlChainItem.getQualificationAtIssuance();
		}
		return null;
	}

	/**
	 * This method returns the qualification of the first certificate at the validation time
	 *
	 * @return the qualification at the validation time
	 */
	public CertificateQualification getTLSBindingSignatureIssuerQualificationAtValidationTime() {
		XmlChainItem xmlChainItem = getTLSBindingSignatureIssuerCertificate();
		if (xmlChainItem != null) {
			return xmlChainItem.getQualificationAtValidation();
		}
		return null;
	}

	/**
	 * Gets the Indication for the TLS Certificate Binging signature validation.
	 * NOTE: Applicable only when validation process is executed using the {@code eu.europa.esig.dss.validation.qwac.QWACValidator}
	 *
	 * @return {@link Indication}
	 */
	public QWACProfile getTLSBindingSignatureIssuerCertificateQWACProfile() {
		XmlChainItem xmlChainItem = getTLSBindingSignatureIssuerCertificate();
		if (xmlChainItem != null) {
			return xmlChainItem.getQwacProfile();
		}
		return null;
	}

	/**
	 * This method returns a Set of trust anchor VAT numbers
	 * 
	 * @return a Set of VAT numbers
	 */
	public Set<String> getTrustAnchorVATNumbers() {
		Set<String> result = new HashSet<>();
		XmlChainItem cert = getTrustAnchorCertificate();
		if (cert != null) {
			List<XmlTrustAnchor> trustAnchors = cert.getTrustAnchors();
			if (trustAnchors != null) {
				for (XmlTrustAnchor xmlTrustAnchor : trustAnchors) {
					result.add(xmlTrustAnchor.getTrustServiceProviderRegistrationId());
				}
			}
		}
		return result;
	}

	private XmlChainItem getTrustAnchorCertificate() {
		XmlChainItem certificate = simpleReport.getCertificate();
		if (certificate != null) {
			if (isTrustAnchor(certificate)) {
				return certificate;
			}
			List<XmlChainItem> chain = certificate.getChain();
			for (XmlChainItem xmlChainItem : chain) {
				if (isTrustAnchor(xmlChainItem)) {
					return xmlChainItem;
				}
			}
		}
		return null;
	}

	private boolean isTrustAnchor(XmlChainItem xmlChainItem) {
		return xmlChainItem.getTrustAnchors() != null && !xmlChainItem.getTrustAnchors().isEmpty();
	}

	private XmlChainItem getFirstCertificate() {
		return simpleReport.getCertificate();
	}

	private XmlChainItem getCertificate(String certificateId) {
		if (certificateId == null) {
			return null;
		}

		XmlChainItem certificate = simpleReport.getCertificate();
		if (certificate != null) {
			if (certificateId.equals(certificate.getId())) {
				return certificate;
			}
			List<XmlChainItem> chain = certificate.getChain();
			for (XmlChainItem xmlChainItem : chain) {
				if (certificateId.equals(xmlChainItem.getId())) {
					return xmlChainItem;
				}
			}
		}

		XmlSignature tlsBindingSignature = getTLSBindingSignature();
		if (tlsBindingSignature != null) {
			List<XmlChainItem> chain = tlsBindingSignature.getChain();
			for (XmlChainItem xmlChainItem : chain) {
				if (certificateId.equals(xmlChainItem.getId())) {
					return xmlChainItem;
				}
			}
		}
		return null;
	}

	/**
	 * This methods returns the jaxb model of the simple certificate report
	 * 
	 * @return the jaxb model
	 */
	public XmlSimpleCertificateReport getJaxbModel() {
		return simpleReport;
	}

}
