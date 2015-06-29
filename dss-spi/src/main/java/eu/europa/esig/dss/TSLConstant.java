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
package eu.europa.esig.dss;

public interface TSLConstant {

	public static final String CA_QC = "http://uri.etsi.org/TrstSvc/Svctype/CA/QC";

	/**
	 * QCStatement
	 * it is ensured by the CSP and controlled (supervision model) or audited
	 * (accreditation model) by the Member State (respectively its Supervisory Body or
	 * Accreditation Body) that all certificates issued under the service (CA/QC)
	 * identified in 'Service digital identity' (clause 5.5.3) and further identified by the
	 * above (filters) information used to further identify under the 'Sdi' identified trust
	 * service that precise set of certificates for which this additional information is
	 * required with regard to the issuance of such certificates is issued as a
	 * Qualified Certificate.
	 * This value shall not be used as an extension, if the service type is not
	 * http://uri.etsi.org/TrstSvc/Svctype/CA/QC
	 */
	public static final String QC_STATEMENT = "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/SvcInfoExt/QCStatement";
	public static final String QC_STATEMENT_119612 = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCStatement";

	/**
	 * It is ensured by the certification service provider and controlled (supervision model) or audited (accreditation
	 * model) by the referenced Member State (respectively its Supervisory Body or Accreditation Body) that any Qualified
	 * Certificate issued under the service (RootCA/QC or CA/QC) identified in "Service digital identity" and further
	 * identified by the filters information used to further identify under the "Sdi" identified certification service
	 * that precise set of Qualified Certificates for which this additional information is required with regards to the
	 * presence or absence of Secure Signature Creation Device (SSCD) support ARE supported by an SSCD (i.e. that that
	 * the private key associated with the public key in the certificate is stored in a Secure Signature Creation Device
	 * conformant with annex III of Directive 1999/93/EC [1]); Only to be used as an extension, if the servicetype is
	 * http://uri.etsi.org/TrstSvc/Svctype/CA/QC
	 */
	public static final String QC_WITH_SSCD = "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/SvcInfoExt/QCWithSSCD";
	public static final String QC_WITH_SSCD_119612 = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithSSCD";

	/**
	 * It is ensured by the certification service provider and controlled (supervision model) or audited (accreditation
	 * model) by the referenced Member State (respectively its Supervisory Body or Accreditation Body) that any Qualified
	 * Certificate issued under the service (RootCA/QC or CA/QC) identified in "Service digital identity" and further
	 * identified by the filters information used to further identify under the "Sdi" identified certification service
	 * that precise set of Qualified Certificates for which this additional information is required with regards to the
	 * presence or absence of Secure Signature Creation Device (SSCD) support ARE NOT supported by an SSCD (i.e. that
	 * that the private key associated with the public key in the certificate is not stored in a Secure Signature
	 * Creation Device conformant with annex III of the Directive 1999/93/EC [1]). Only to be used as an extension, if
	 * the servicetype is http://uri.etsi.org/TrstSvc/Svctype/CA/QC
	 */
	public static final String QC_NO_SSCD = "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/SvcInfoExt/QCNoSSCD";
	public static final String QC_NO_SSCD_119612 = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCNoSSCD";

	/**
	 * It is ensured by the certification service provider and controlled (supervision model) or audited (accreditation
	 * model) by the referenced Member State (respectively its Supervisory Body or Accreditation Body) that any Qualified
	 * Certificate issued under the service (RootCA/QC or CA/QC) identified in "Service digital identity" and further
	 * identified by the filters information used to further identify under the "Sdi" identified certification service
	 * that precise set of Qualified Certificates for which this additional information is required with regards to the
	 * presence or absence of Secure Signature Creation Device (SSCD) support SHALL contain the machine-processable
	 * information indicating whether or not the Qualified Certificate is supported by an SSCD. Only to be used as an
	 * extension, if the servicetype is http://uri.etsi.org/TrstSvc/Svctype/CA/QC.
	 */
	public static final String QCSSCD_STATUS_AS_IN_CERT = "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/SvcInfoExt/QCSSCDStatusAsInCert";
	public static final String QCSSCD_STATUS_AS_IN_CERT_119612 = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCSSCDStatusAsInCert";

	/**
	 * It is ensured by the certification service provider and controlled (supervision model) or audited (accreditation
	 * model) by the referenced Member State (respectively its Supervisory Body or Accreditation Body) that any Qualified
	 * Certificate issued under the service (RootCA/QC or CA/QC) identified in "Service digital identity" and further
	 * identified by the filters information used to further identify under the "Sdi" identified certification service
	 * that precise set of Qualified Certificates for which this additional information is required with regards to the
	 * issuance to Legal Person ARE issued to Legal Persons. Only to be used as an extension, if the servicetype is
	 * http://uri.etsi.org/TrstSvc/Svctype/CA/QC
	 */
	public static final String QC_FOR_LEGAL_PERSON = "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/SvcInfoExt/QCForLegalPerson";
	public static final String QC_FOR_LEGAL_PERSON_119612 = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForLegalPerson";

	/**
	 * <b>Supervision of Service in Cessation</b><br>
	 * The service identified in "Service digital identity" (see clause 5.5.3) provided by the Certification Service
	 * Provider (CSP) identified in "TSP name" (see clause 5.4.1) is currently in a cessation phase but still supervised
	 * until supervision is ceased or revoked. In the event a different legal person than the one identified in
	 * "TSP name" has taken over the responsibility of ensuring this cessation phase, the identification of this new or
	 * fallback legal person (fallback CSP) shall be provided in clause 5.5.6 of the service entry
	 *
	 * This status means that there is only the revocation check. Example: https://www.eett.gr/tsl/EL-TSL.xml (ADACOM
	 * Qualified Certificate Services CA)
	 */
	public static final String SERVICE_STATUS_SUPERVISIONINCESSATION = "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/Svcstatus/supervisionincessation";
	public static final String SERVICE_STATUS_SUPERVISIONINCESSATION_119612 = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionincessation";

	/**
	 * Under Supervision<b><br>
	 * The service identified in "Service digital identity" (see clause 5.5.3) provided by the Certification Service
	 * Provider (CSP) identified in "TSP name" (see clause 5.4.1) is currently under supervision, for compliance with the
	 * provisions laid down in Directive 1999/93/EC [1], by the Member State identified in the "Scheme territory" (see
	 * clause 5.3.10) in which the CSP is established.
	 */
	public static final String SERVICE_STATUS_UNDERSUPERVISION = "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/Svcstatus/undersupervision";
	public static final String SERVICE_STATUS_UNDERSUPERVISION_119612 = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/undersupervision";

	/**
	 * Accredited<br>
	 * An accreditation assessment has been performed by the Accreditation Body on behalf of the Member State identified
	 * in the "Scheme territory" (see clause 5.3.10) and the service identified in "Service digital identity" (see clause
	 * 5.5.3) provided by the trust service provider identified in "TSP name" (see clause 5.4.1) is found to be in
	 * compliance with the provisions laid down in Directive 1999/93/EC [i.3].<br>
	 * This accredited trust service provider may be established in another Member State than the one identified in the
	 * "Scheme territory" (see clause 5.3.10) of the trusted list or in a non-EU country (see article 7.1(a) of Directive
	 * 1999/93/EC [i.3]).
	 */
	public static final String SERVICE_STATUS_ACCREDITED = "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/Svcstatus/accredited";
	public static final String SERVICE_STATUS_ACCREDITED_119612 = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accredited";


	public static final String TSL = "http://uri.etsi.org/02231/v2#";

	public static final String TSLX = "http://uri.etsi.org/02231/v2/additionaltypes#";
}