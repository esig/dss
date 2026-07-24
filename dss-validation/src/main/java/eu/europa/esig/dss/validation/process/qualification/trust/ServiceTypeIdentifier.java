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
package eu.europa.esig.dss.validation.process.qualification.trust;

/**
 * Service type identifier (ETSI TS 119 612 V2.1.1)
 * 
 * It specifies the identifier of the service type.
 * 
 */
public enum ServiceTypeIdentifier {

	// ---- 5.5.1.1 Regulation (EU) No 910/2014 qualified trust service types

	/**
	 * A qualified certificate issuing trust service creating and signing qualified
	 * certificates based on the identity and other attributes verified by the
	 * relevant registration services, and under which are provided the relevant and
	 * related revocation and certificate validity revocation information services (e.g.
	 * CRLs, OCSP responses) in accordance with EU Directive 1999/93/EC [i.3] or
	 * with Regulation (EU) No 910/2014 [i.10] whichever is in force at the time of
	 * provision. This may also include generation and/or management of the
	 * associated private keys on behalf of the certified entity
	 */
	CA_QC("CA/QC", "http://uri.etsi.org/TrstSvc/Svctype/CA/QC", true, false),

	/**
	 * A certificate validity revocation information service issuing Online Certificate
	 * Status Protocol (OCSP) signed responses and operating an OCSP-server as part
	 * of a service from a (qualified) trust service provider issuing qualified
	 * certificates, in accordance with the applicable national legislation in the
	 * territory identified by the TL Scheme territory (see clause 5.3.10) or with
	 * Regulation (EU) No 910/2014 [i.10] whichever is in force at the time of
	 * provision.
	 */
	OCSP_QC("OCSP/QC", "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/OCSP/QC", true, false),

	/**
	 * A certificate validity revocation information services issuing and signing
	 * Certificate Revocation Lists (CRLs) and being part of a service from a
	 * (qualified) trust service provider issuing qualified certificates, in
	 * accordance with the applicable national legislation in the territory
	 * identified by the TL Scheme territory (see clause 5.3.10) or with Regulation
	 * (EU) No 910/2014 [i.10] whichever is in force at the time of provision.
	 */
	CRL_QC("CRL/QC", "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/CRL/QC", true, false),

	/**
	 * A qualified electronic time stamp generation service creating and signing
	 * qualified electronic time stamps in accordance with the applicable national
	 * legislation in the territory identified by the TL Scheme territory (see
	 * clause 5.3.10) or with Regulation (EU) No 910/2014 [i.10] whichever is in
	 * force at the time of provision.
	 */
	TSA_QTST("TSA/QTST", "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST", true, false),

	/**
	 * A qualified electronic delivery service providing qualified electronic
	 * deliveries in accordance with the applicable national legislation in the
	 * territory identified by the TL Scheme territory (see clause 5.3.10) or with
	 * Regulation (EU) No 910/2014 [i.10] whichever is in force at the time of
	 * provision.
	 */
	EDS_Q("EDS/Q", "http://uri.etsi.org/TrstSvc/Svctype/EDS/Q", true, false),

	/**
	 * A qualified electronic registered mail delivery service providing qualified
	 * electronic registered mail deliveries in accordance with the applicable
	 * national legislation in the territory identified by the TL Scheme territory
	 * (see clause 5.3.10) or with Regulation (EU) No 910/2014 [i.10] whichever is
	 * in force at the time of provision
	 */
	EDS_REM_Q("EDS/REM/Q", "http://uri.etsi.org/TrstSvc/Svctype/EDS/REM/Q", true, false),

	/**
	 * A qualified preservation service for qualified electronic signatures and/or
	 * qualified electronic seals in accordance with the applicable national
	 * legislation in the territory identified by the TL Scheme territory (see
	 * clause 5.3.10) or with Regulation (EU) No 910/2014 [i.10] whichever is in
	 * force at the time of provision.
	 */
	PSES_Q("PSES/Q", "http://uri.etsi.org/TrstSvc/Svctype/PSES/Q", true, false),
	
	/**
	 * A qualified validation service for qualified electronic signatures and/or
	 * qualified electronic seals in accordance with the applicable national
	 * legislation in the territory identified by the TL Scheme territory (see
	 * clause 5.3.10) or with Regulation (EU) No 910/2014 [i.10] whichever is in
	 * force at the time of provision.
	 */
	QESVALIDATION_Q("QESValidation/Q", "http://uri.etsi.org/TrstSvc/Svctype/QESValidation/Q", true, false),

	// New eIDAS 2.0 qualified trust service types (ETSI TS 119 612 v.2.4.1)

	/**
	 * The management of remote qualified electronic signature creation devices as a qualified trust service carried out
	 * by a qualified trust service provider, in accordance with Regulation (EU) No 910/2014 [i.10].
	 */
	REMOTE_QSIG_CD_MANAGEMENT_Q("RemoteQSigCDManagement/Q", "http://uri.etsi.org/TrstSvc/Svctype/RemoteQSigCDManagement/Q", true, false),

	/**
	 * The management of remote qualified electronic seal creation devices as a qualified trust service carried out by a
	 * qualified trust service provider, in accordance with Regulation (EU) No 910/2014 [i.10].
	 */
	REMOTE_QSEAL_CD_MANAGEMENT_Q("RemoteQSealCDManagement/Q", "http://uri.etsi.org/TrstSvc/Svctype/RemoteQSealCDManagement/Q", true, false),

	/**
	 * The issuance of qualified electronic attestations of attributes by a qualified trust service provider in accordance
	 * with Regulation (EU) No 910/2014 [i.10].
	 */
	EAA_Q("EAA/Q", "http://uri.etsi.org/TrstSvc/Svctype/EAA/Q", true, false),

	/**
	 * A qualified electronic archiving service provided by a qualified trust service provider in accordance with Regulation
	 * (EU) No 910/2014 [i.10].
	 */
	ELECTRONIC_ARCHIVING_Q("ElectronicArchiving/Q", "http://uri.etsi.org/TrstSvc/Svctype/ElectronicArchiving/Q", true, false),

	/**
	 * A qualified trust service for the recording of electronic data in qualified electronic ledgers by a qualified trust
	 * service provider in accordance with Regulation (EU) No 910/2014 [i.10]
	 */
	LEDGERS_Q("Ledgers/Q", "http://uri.etsi.org/TrstSvc/Svctype/Ledgers/Q", true, false),

	// ---- 5.5.1.2 Regulation (EU) No 910/2014 non qualified trust service types

	/**
	 * A certificate generation service, not qualified, creating and signing
	 * non-qualified public key certificates based on the identity and other
	 * attributes verified by the relevant registration services.
	 */
	CA_PKC("CA/PKC", "http://uri.etsi.org/TrstSvc/Svctype/CA/PKC", false, false),

	/**
	 * A certificate validity revocation service, not qualified, issuing Online
	 * Certificate Status Protocol (OCSP) signed responses.
	 */
	OCSP("OCSP", "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/OCSP", false, false),

	/**
	 * A certificate validity revocation service, not qualified, issuing CRLs.
	 */
	CRL("CRL", "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/CRL", false, false),

	/**
	 * A time-stamping generation service, not qualified, creating and signing
	 * time-stamps tokens
	 */
	TSA("TSA", "http://uri.etsi.org/TrstSvc/Svctype/TSA", false, false),

	/**
	 * A time-stamping service, not qualified, as part of a service from a trust
	 * service provider issuing qualified certificates that issues time-stamp tokens
	 * that can be used in the validation process of qualified signatures/seals or
	 * advanced signatures/seals supported by qualified certificates to ascertain
	 * and extend the signature/seal validity when the qualified certificate is
	 * (will be) revoked or expired (will expire).
	 */
	TSA_TSS_QC("TSA/TSS-QC", "http://uri.etsi.org/TrstSvc/Svctype/TSA/TSS-QC", false, false),

	/**
	 * A time-stamping service, not qualified, as part of a service from a trust
	 * service provider that issues time-stamp tokens (TST) that can be used in the
	 * validation process of qualified signatures/seals or advanced signatures/seals
	 * supported by qualified certificates to ascertain and extend the
	 * signature/seal validity when the qualified certificate is (will be) revoked
	 * or expired (will expire).
	 */
	TSA_TSS_ADESQC_AND_QES("TSA/TSS-AdESQCandQES", "http://uri.etsi.org/TrstSvc/Svctype/TSA/TSS-AdESQCandQES", false, false),

	/**
	 * An electronic delivery service, not qualified
	 */
	EDS("EDS", "http://uri.etsi.org/TrstSvc/Svctype/EDS", false, false),

	/**
	 * A Registered Electronic Mail delivery service, not qualified
	 */
	EDS_REM("EDS/REM", "http://uri.etsi.org/TrstSvc/Svctype/EDS/REM", false, false),

	/**
	 * A not qualified preservation service for electronic signatures and/or for
	 * electronic seals.
	 */
	PSES("PSES", "http://uri.etsi.org/TrstSvc/Svctype/PSES", false, false),

	/**
	 * A not qualified validation service for advanced electronic signatures and/or
	 * advanced electronic seals
	 */
	ADES_VALIDATION("AdESValidation", "http://uri.etsi.org/TrstSvc/Svctype/AdESValidation", false, false),

	/**
	 * A not qualified generation service for advanced electronic signatures and/or
	 * advanced electronic seals
	 */
	ADES_GENERATION("AdESGeneration", "http://uri.etsi.org/TrstSvc/Svctype/AdESGeneration", false, false),

	// New eIDAS 2.0 non-qualified trust service types (ETSI TS 119 612 v.2.4.1)

	/**
	 * A not qualified trust service for the management of remote electronic signature creation devices, provided by a
	 * trust service provider that generates or manages electronic signature creation data on behalf of the signatory.
	 */
	REMOTE_SIG_CD_MANAGEMENT("RemoteSigCDManagement", "http://uri.etsi.org/TrstSvc/Svctype/RemoteSigCDManagement", false, false),

	/**
	 * A not qualified trust service for the management of remote electronic seal creation devices, provided by a trust
	 * service provider that generates or manages electronic seal creation data on behalf of the seal creator.
	 */
	REMOTE_SEAL_CD_MANAGEMENT("RemoteSealCDManagement", "http://uri.etsi.org/TrstSvc/Svctype/RemoteSealCDManagement", false, false),

	/**
	 * The issuance of not qualified electronic attestations of attributes by a trust service provider in accordance with
	 * Regulation (EU) No 910/2014 [i.10].
	 */
	EAA("RemoteSealCDManagement", "http://uri.etsi.org/TrstSvc/Svctype/EAA", false, false),

	/**
	 * A not qualified electronic archiving service provided by a trust service provider in accordance with
	 * Regulation (EU) No 910/2014 [i.10].
	 */
	ELECTRONIC_ARCHIVING("ElectronicArchiving", "http://uri.etsi.org/TrstSvc/Svctype/ElectronicArchiving", false, false),

	/**
	 * A not qualified trust service for the recording of electronic data in not qualified electronic ledgers by a trust service
	 * provider in accordance with Regulation (EU) No 910/2014 [i.10].
	 */
	LEDGERS("Ledgers", "http://uri.etsi.org/TrstSvc/Svctype/Ledgers", false, false),

	/**
	 * A not qualified trust service for the validation of certificates for electronic signatures, certificates for electronic
	 * seals, or certificates for website authentication.
	 */
	PKC_VALIDATION("PKCValidation", "http://uri.etsi.org/TrstSvc/Svctype/PKCValidation", false, false),

	/**
	 * A not qualified trust service for the preservation of certificates for electronic signatures or certificates for electronic
	 * seals.
	 */
	PKC_PRESERVATION("PKCPreservation", "http://uri.etsi.org/TrstSvc/Svctype/PKCPreservation", false, false),

	/**
	 * A not qualified trust service for the validation of electronic attestation of attributes.
	 */
	EAA_VALIDATION("EAAValidation", "http://uri.etsi.org/TrstSvc/Svctype/EAAValidation", false, false),

	/**
	 * A not qualified trust service for the validation of electronic timestamps.
	 */
	TST_VALIDATION("TSTValidation", "http://uri.etsi.org/TrstSvc/Svctype/TSTValidation", false, false),

	/**
	 * A not qualified trust service for the validation of data transmitted through electronic registered delivery services
	 * and the validation of related evidences.
	 */
	EDS_VALIDATION("TSTValidatiEDSValidationon", "http://uri.etsi.org/TrstSvc/Svctype/EDSValidation", false, false),

	/**
	 * The issuance of not qualified electronic attestation of attributes as defined in Article 3(46) of
	 * Regulation (EU) No 910/2014 [i.10], issued by or on behalf of a public sector body responsible for an authentic
	 * source, acting as a trust service provider and in accordance with that Regulation.
	 */
	EAA_PUBEAA("EAA/Pub-EAA", "http://uri.etsi.org/TrstSvc/Svctype/EAA/Pub-EAA", false, false),

	/**
	 * A certificate generation service, not qualified, creating and signing non-qualified public key certificates based on
	 * the identity and other attributes verified by the relevant registration services.
	 * The nature of those public key certificates for which the revocation has been granted are neither certificates for
	 * electronic signatures, nor certificates for electronic seals, nor certificates for website authentication. They are
	 * certificates for the provision of other trust services as referred to in Article 3(16) of
	 * Regulation (EU) 910/2014 [i.10].
	 */
	CA_PKC_CERTSOFOTHERTYPESOFTS("CA/PKC/CertsforOtherTypesOfTS", "http://uri.etsi.org/TrstSvc/Svctype/CA/PKC/CertsforOtherTypesOfTS", false, false),

	/**
	 * A not qualified trust service for the validation of certificates for the provision of other trust services as referred to in
	 * Article 3(16) of Regulation (EU) 910/2014 [i.10].
	 */
	PKC_VALIDATION_CERTSOFOTHERTYPESOFTS("PKCValidation/CertsforOtherTypesOfTS", "http://uri.etsi.org/TrstSvc/Svctype/PKCValidation/CertsforOtherTypesOfTS", false, false),
	
	// ---- 5.5.1.3 Trust service types not defined in Regulation (EU) No 910/2014
	// but nationally defined

	/**
	 * A registration service that verifies the identity and, if applicable, any
	 * specific attributes of a subject for which a certificate is applied for, and
	 * whose results are passed to the relevant certificate generation service.
	 */
	RA("RA", "http://uri.etsi.org/TrstSvc/Svctype/RA", false, true),

	/**
	 * A registration service - that verifies the identity and, if applicable, any
	 * specific attributes of a subject for which a certificate is applied for, and
	 * whose results are passed to the relevant certificate generation service, and
	 * - that cannot be identified by a specific PKI-based public key.
	 */
	RA_NOTHAVINGPKIID("RA/nothavingPKIid", "http://uri.etsi.org/TrstSvc/Svctype/RA/nothavingPKIid", false, true),

	/**
	 * An attribute certificate generation service creating and signing attribute
	 * certificates based on the identity and other attributes verified by the
	 * relevant registration services.
	 */
	ACA("ACA", "http://uri.etsi.org/TrstSvc/Svctype/ACA", false, true),

	/**
	 * A service responsible for issuing, publishing or maintenance of signature
	 * policies.
	 */
	SIGNATUREPOLICYAUTHORITY("SignaturePolicyAuthority", "http://uri.etsi.org/TrstSvc/Svctype/SignaturePolicyAuthority", false, true),

	/**
	 * An Archival service.
	 */
	ARCHIV("Archiv", "http://uri.etsi.org/TrstSvc/Svctype/Archiv", false, true),

	/**
	 * An Archival service that cannot be identified by a specific PKI-based public
	 * key.
	 */
	ARCHIV_NOTHAVINGPKIID("Archiv/nothavingPKIid", "http://uri.etsi.org/TrstSvc/Svctype/Archiv/nothavingPKIid", false, true),

	/**
	 * An Identity verification service.
	 */
	IDV("IdV", "http://uri.etsi.org/TrstSvc/Svctype/IdV", false, true),

	/**
	 * An Identity verification service that cannot be identified by a specific
	 * PKI-based public key.
	 */
	IDV_NOTHAVINGPKIID("IdV/nothavingPKIid", "http://uri.etsi.org/TrstSvc/Svctype/IdV/nothavingPKIid", false, true),

	/**
	 * A Key escrow service.
	 */
	KESCROW("KEscrow", "http://uri.etsi.org/TrstSvc/Svctype/KEscrow", false, true),

	/**
	 * A Key escrow service that cannot be identified by a specific PKI-based public
	 * key.
	 */
	KESCROW_NOTHAVINGPKIID("KEscrow/nothavingPKIid", "http://uri.etsi.org/TrstSvc/Svctype/KEscrow/nothavingPKIid", false, true),

	/**
	 * Issuer of PIN- or password-based identity credentials.
	 */
	PPWD("PPwd", "http://uri.etsi.org/TrstSvc/Svctype/PPwd", false, true),

	/**
	 * Issuer of PIN- or password-based identity credentials that cannot be
	 * identified by a specific PKI-based public key
	 */
	PPWD_NOTHAVINGPKIID("PPwd/nothavingPKIid", "http://uri.etsi.org/TrstSvc/Svctype/PPwd/nothavingPKIid", false, true),

	/**
	 * A service issuing trusted lists.
	 */
	TLISSUER("TLIssuer", "http://uri.etsi.org/TrstSvd/Svctype/TLIssuer", false, true),

	/**
	 * A national root signing CA issuing root-signing or qualified certificates to
	 * trust service providers and related certification or trust services that are
	 * accredited against a national voluntary accreditation scheme or supervised
	 * under national law in accordance with the applicable European legislation.
	 */
	NATIONALROOTCA_QC("NationalRootCA-QC", "http://uri.etsi.org/TrstSvc/Svctype/NationalRootCA-QC", false, true),

	/**
	 * A trust service of an unspecified type.
	 */
	UNSPECIFIED("unspecified", "http://uri.etsi.org/TrstSvc/Svctype/unspecified", false, true);

	/** Identifier label */
	private final String shortName;

	/** Identifier URI */
	private final String uri;

	/** Identifier qualified revocation */
	private final boolean qualified;

	/** Whether identifier is for national use */
	private final boolean national;

	/**
	 * Default constructor
	 *
	 * @param shortName {@link String}
	 * @param uri {@link String}
	 * @param qualified whether the identifier corresponds to a qualifier
	 * @param national whether the identifier corresponds to a national revocation
	 */
	ServiceTypeIdentifier(String shortName, String uri, boolean qualified, boolean national) {
		this.shortName = shortName;
		this.uri = uri;
		this.qualified = qualified;
		this.national = national;
	}

	/**
	 * Gets identifier's label
	 *
	 * @return {@link String}
	 */
	public String getShortName() {
		return shortName;
	}

	/**
	 * Gets identifier's URI
	 *
	 * @return {@link String}
	 */
	public String getUri() {
		return uri;
	}

	/**
	 * Gets whether identifier corresponds to a qualified revocation
	 *
	 * @return TRUE if qualified, FALSE otherwise
	 */
	public boolean isQualified() {
		return qualified;
	}

	/**
	 * Gets whether identifier corresponds to a national revocation
	 *
	 * @return TRUE if national, FALSE otherwise
	 */
	public boolean isNational() {
		return national;
	}

	/**
	 * Checks whether the {@code serviceTypeIdentifier} is CA/QC
	 *
	 * @param serviceTypeIdentifier {@link String} identifier to check
	 * @return TRUE of the identifier is CA/QC, FALSE otherwise
	 */
	public static boolean isCaQc(String serviceTypeIdentifier) {
		return CA_QC.getUri().equals(serviceTypeIdentifier);
	}

	/**
	 * Checks whether the {@code serviceTypeIdentifier} is TSA/QTST
	 *
	 * @param serviceTypeIdentifier {@link String} identifier to check
	 * @return TRUE of the identifier is TSA/QTST, FALSE otherwise
	 */
	public static boolean isQTST(String serviceTypeIdentifier) {
		return TSA_QTST.getUri().equals(serviceTypeIdentifier);
	}

	/**
	 * Checks whether the {@code serviceTypeIdentifier} is EAA/Q
	 *
	 * @param serviceTypeIdentifier {@link String} identifier to check
	 * @return TRUE of the identifier is EAA/Q, FALSE otherwise
	 */
	public static boolean isQEAA(String serviceTypeIdentifier) {
		return EAA_Q.getUri().equals(serviceTypeIdentifier);
	}

	/**
	 * This method returns a corresponding {@code ServiceTypeIdentifier} by the given {@code uri}
	 *
	 * @param uri {@link String} to get {@code ServiceTypeIdentifier} for
	 * @return {@link ServiceTypeIdentifier}
	 */
	public static ServiceTypeIdentifier fromUri(String uri) {
		for (ServiceTypeIdentifier sti : values()) {
			if (sti.getUri().equals(uri)) {
				return sti;
			}
		}
		return null;
	}

}
