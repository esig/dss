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
package eu.europa.esig.dss.validation.reports;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import eu.europa.esig.dss.jaxb.simplecertificatereport.XmlChainItem;
import eu.europa.esig.dss.jaxb.simplecertificatereport.XmlRevocation;
import eu.europa.esig.dss.jaxb.simplecertificatereport.XmlTrustAnchor;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateQualification;
import eu.europa.esig.dss.validation.policy.rules.Indication;

/**
 * A SimpleCertificateReport holder to fetch values from a JAXB SimpleCertificateReport.
 */
public class SimpleCertificateReport {

	private final eu.europa.esig.dss.jaxb.simplecertificatereport.SimpleCertificateReport simpleReport;

	public SimpleCertificateReport(eu.europa.esig.dss.jaxb.simplecertificatereport.SimpleCertificateReport simpleReport) {
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
		List<String> ids = new ArrayList<String>();
		List<XmlChainItem> chain = simpleReport.getChain();
		for (XmlChainItem xmlChainItem : chain) {
			ids.add(xmlChainItem.getId());
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
	 * This method returns the indication (result of validation) for a given certificate
	 * 
	 * @param certificateId
	 *            the certificate id
	 * @return the indication
	 */
	public Indication getCertificateIndication(String certificateId) {
		XmlChainItem cert = getCertificate(certificateId);
		if (cert != null) {
			return cert.getIndication();
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
	public String getCertificateRevocationReason(String certificateId) {
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
	 * This method returns the qualification of the first certificate at its issuance
	 * 
	 * @return the qualification at the certificate creation
	 */
	public CertificateQualification getQualificationAtCertificateIssuance() {
		XmlChainItem cert = getFirstCertificate();
		return cert.getQualificationAtIssuance();
	}

	/**
	 * This method returns a Set of trust anchor VAT numbers
	 * 
	 * @return a Set of VAT numbers
	 */
	public Set<String> getTrustAnchorVATNumbers() {
		Set<String> result = new HashSet<String>();
		XmlChainItem cert = getTrustAnchorCertificate();
		if (cert != null) {
			List<XmlTrustAnchor> trustAnchors = cert.getTrustAnchors();
			for (XmlTrustAnchor xmlTrustAnchor : trustAnchors) {
				result.add(xmlTrustAnchor.getTrustServiceProviderRegistrationId());
			}
		}
		return result;
	}

	private XmlChainItem getTrustAnchorCertificate() {
		List<XmlChainItem> chain = simpleReport.getChain();
		for (XmlChainItem xmlChainItem : chain) {
			if (Utils.isCollectionNotEmpty(xmlChainItem.getTrustAnchors())) {
				return xmlChainItem;
			}
		}
		return null;
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

	private XmlChainItem getFirstCertificate() {
		return simpleReport.getChain().get(0);
	}

	private XmlChainItem getCertificate(String certificateId) {
		List<XmlChainItem> chain = simpleReport.getChain();
		for (XmlChainItem xmlChainItem : chain) {
			if (Utils.areStringsEqual(certificateId, xmlChainItem.getId())) {
				return xmlChainItem;
			}
		}
		return null;
	}

	/**
	 * This methods returns the jaxb model of the simple certificate report
	 * 
	 * @return the jaxb model
	 */
	public eu.europa.esig.dss.jaxb.simplecertificatereport.SimpleCertificateReport getJaxbModel() {
		return simpleReport;
	}

}
