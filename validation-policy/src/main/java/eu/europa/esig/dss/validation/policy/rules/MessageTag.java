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
package eu.europa.esig.dss.validation.policy.rules;

/**
 *
 */
public enum MessageTag {

	ADEST_IMIDF("Is message imprint data found?"),
	ADEST_IMIDF_ANS("The timestamp message imprint data is not found!"),
	ADEST_IMIVC("Is message imprint verification conclusive?"),
	ADEST_IMIVC_ANS("The timestamp message imprint verification has failed!"),
	ADEST_ITVPC("Is timestamp validation process conclusive?"),
	ADEST_ITVPC_ANS_1("The timestamp is rejected, its generation time is before the best-signature-time!"),
	ADEST_ITVPC_INFO_1("The best-signature-time was set to the generation time of the timestamp."),
	ADEST_ITVPC_ANS_2("Timestamp validation is not conclusive!"),
	ADEST_ROBVPIIC("Is the result of the Basic Validation Process conclusive?"),
	ADEST_ROTVPIIC("Is the result of the timestamps validation process conclusive?"),
	ADEST_ROTVPIIC_ANS("The result of the timestamps validation process is not conclusive!"),

	BBB_CV_IRDOF("Is the reference data object(s) found?"),
	BBB_CV_IRDOF_ANS("The reference data object(s) not found!"),
	BBB_CV_IRDOI("Is the reference data object(s) intact?"),
	BBB_CV_IRDOI_ANS("The reference data object(s) is not intact!"),
	BBB_CV_ISI("Is the signature intact?"),
	BBB_CV_ISI_ANS("The signature is not intact!"),

	BBB_ICS_ISCI("Is there an identified candidate for the signing certificate?"),
	BBB_ICS_ISCI_ANS("There is no candidate for the signing certificate!"),
	BBB_ICS_ISCS("Is the signing certificate signed?"),
	BBB_ICS_ISCS_ANS("The signing certificate is not signed!"),
	BBB_ICS_ISASCP("Is the signed attribute: 'signing-certificate' present?"),
	BBB_ICS_ISASCP_ANS("The signed attribute: 'signing-certificate' is absent!"),
	BBB_ICS_ISACDP("Is the signed attribute: 'cert-digest' of the certificate present?"),
	BBB_ICS_ISACDP_ANS("The signed attribute: 'cert-digest' is absent!"),
	BBB_ICS_ICDVV("Is the certificate's digest value valid?"),
	BBB_ICS_ICDVV_ANS("The signing certificate digest value does not match!"),
	BBB_ICS_AIDNASNE("Are the issuer distinguished name and the serial number equal?"),
	BBB_ICS_AIDNASNE_ANS("The 'issuer-serial' attribute is absent or does not match!"),

	ASCCM("Are signature cryptographic constraints met?"),
	ASCCM_ANS_1("The encryption algorithm not authorised!"),
	ASCCM_ANS_2("The digest algorithm not authorised!"),
	ASCCM_ANS_3("The public key size is to small!"),
	ASCCM_ANS_4("The algorithm expiration date not found!"),
	ASCCM_ANS_5("The algorithm is expired!"),

	BBB_SAV_ISSV("Is the structure of the signature valid?"),
	BBB_SAV_ISSV_ANS("The structure of the signature is not valid!"),
	BBB_SAV_ICERRM("Is the certified role mandated?"),
	BBB_SAV_ICERRM_ANS("The requested certified role is not present!"),
	BBB_SAV_ICRM("The requested claimed role is not present!"),
	BBB_SAV_ICRM_ANS("The requested claimed role is not present!"),
	BBB_SAV_ISQPCTP("Is signed qualifying property: 'content-type' present?"),
	BBB_SAV_ISQPCTP_ANS("The signed qualifying property: 'content-type' is not present!"),
	BBB_SAV_ISQPCHP("Is signed qualifying property: 'content-hints' present?"),
	BBB_SAV_ISQPCHP_ANS("The signed qualifying property: 'content-hints' is not present!"),
	BBB_SAV_ISQPCIP("Is signed qualifying properties: 'content-identifier' present?"),
	BBB_SAV_ISQPCIP_ANS("The signed qualifying property: 'content-identifier' is not present!"),
	BBB_SAV_ISQPCTSIP("Is signed qualifying property: 'content-timestamp' present?"),
	BBB_SAV_ISQPCTSIP_ANS("The signed qualifying property: 'content-timestamp' is not present!"),
	BBB_SAV_ISQPSLP("Is signed qualifying property: 'signer-location' present?"),
	BBB_SAV_ISQPSLP_ANS("The signed qualifying property: 'signer-location' is not present!"),
	BBB_SAV_ISQPSTP("Is signed qualifying property: 'signing-time' present?"),
	BBB_SAV_ISQPSTP_ANS("The signed qualifying property: 'signing-time' is not present!"),
	BBB_SAV_ISQPXTIP("Is signed qualifying property: 'commitment-type-indication' present?"),
	BBB_SAV_ISQPXTIP_ANS("The signed qualifying property: 'commitment-type-indication' is not present!"),

	BBB_VCI_ISPK("Is the signature policy known?"),
	BBB_VCI_ISPK_ANS_1("The signature policy is mandatory!"),
	BBB_VCI_ISPK_ANS_2("An error encountered when processing the signature policy identifier!"),
	BBB_VCI_ISPK_ANS_3("The signature policy identifier is not allowed by the validation policy constraint!"),

	BBB_XCV_ACCCM("Are chain cryptographic constraints met?"),
	BBB_XCV_ACCM("Are chain constraints met?"),
	BBB_XCV_ARDCCM("Are revocation data cryptographic constraints met?"),
	BBB_XCV_CCCBB("Can the certificate chain be built till the trust anchor?"),
	BBB_XCV_CCCBB_ANS("The certificate chain is not trusted, there is no trusted anchor."),
	BBB_XCV_CMDCIITLP("Certificate meta-data constraints: Is issued to a legal person?"),
	BBB_XCV_CMDCIITLP_ANS("The signer's certificate is not issued to a legal person."),
	BBB_XCV_CMDCIQC("Certificate meta-data constraints: Is the signer's certificate qualified?"),
	BBB_XCV_CMDCIQC_ANS("The certificate is not qualified!"),
	BBB_XCV_CMDCISSCD("Certificate meta-data constraints: Is the SSCD?"),
	BBB_XCV_CMDCISSCD_ANS("The signer's certificate is not supported by SSCD!"),
	BBB_XCV_ICTIVRSC("Is the current time in the validity range of the signer's certificate?"),
	BBB_XCV_ICTIVRSC_ANS("The current time is not in the validity range of the signer's certificate."),
	BBB_XCV_IICR("Is an intermediate CA [%s] revoked?"),
	BBB_XCV_IICR_ANS("The intermediate CA is revoked"),
	BBB_XCV_IRDPFC("Is the revocation data present for the certificate?"),
	BBB_XCV_IRDPFC_ANS("No revocation data for the certificate"),
	BBB_XCV_IRDTFC("Is the revocation data trusted for the certificate?"),
	BBB_XCV_IRDTFC_ANS("The revocation data for the certificate is not trusted!"),
	BBB_XCV_IRIF("Is the revocation information fresh for the certificate?"),
	BBB_XCV_IRIF_ANS("The revocation status information is not considered as 'fresh'."),
	BBB_XCV_ISCOH("Is the signer's certificate on hold?"),
	BBB_XCV_ISCOH_ANS("The certificate is on hold!"),
	BBB_XCV_ISCR("Is the signer's certificate not revoked?"),
	BBB_XCV_ISCR_ANS("The certificate is revoked!"),
	BBB_XCV_ISCGKU("Has the signer's certificate given key-usage?"),
	BBB_XCV_ISCGKU_ANS("The signer's certificate has not expected key-usage!"),
	BBB_XCV_ICSI("Is the certificate's signature intact?"),
	BBB_XCV_ICSI_ANS("The signature of the certificate is spoiled or it is not possible to validate it!"),

	XCV_IFCCIIPC_ANS("The interval ['%s', '%s'] for the certificate ['%s'] is inconsistent in the prospective chain."),

	CTS_DRIE("Does the revocation information exist?"),
	CTS_DSOPCPOEOC("Does the set of POEs contains a proof of existence of the certificate?"),
	CTS_ICNEAIDORSI("Is the certificate not expired at the issuance date of the revocation status information?"),
	CTS_IIDORSIBCT("Is the issuance date of the revocation status information before control-time?"),
	CTS_SCT("Sliding the control-time."),
	CTS_IIDOCWVPOTS("Is the issuance date of the certificate within the validity period of trusted service?"),
	CTS_IIDOCWVPOTS_ANS("There is no concordance between the validity dates of trusted services and the certificate!"),
	CTS_WITSS("What is the trusted service status?"),
	CTS_WITSS_ANS("The status of the trusted service should be: UNDERSUPERVISION, SUPERVISIONINCESSATION or ACCREDITED!"),
	CTS_ITACBT("Is there a concordance between the trusted service and the certificate?"),
	CTS_ITACBT_ANS("There is no concordance between the trusted service and the certificate!"),

	PCV_ICTSC("Is control time sliding conclusive?"),
	PCV_ICTSC_ANS("The indications returned by control time sliding sub-process."),
	PCV_TINTA_ANS("There is no trusted anchor."),
	PCV_TIOOCIC_ANS("There is only one certificate in the chain."),

	PSV_IATVC("Is AdES-T validation conclusive?"),
	PSV_IPCVC("Is past certificate validation conclusive?"),
	PSV_IPCVC_ANS("The past certificate validation is not conclusive!"),
	PSV_IPSVC("Is past signature validation conclusive?"),
	PSV_ITPOSVAOBCT("Is there a POE of the signature value at (or before) control-time?"),

	TSV_ASTPTCT("Is the order of the timestamps correct?"),
	TSV_ASTPTCT_ANS("The order of the timestamps is not correct!"),
	TSV_IBSTAIDOSC("Is the best-signature-time after the issuance date of the signing certificate?"),
	TSV_IBSTAIDOSC_ANS("The best-signature-time is before the issuance date of the signing certificate!"),
	TSV_ISCNVABST("Is the signing certificate not valid at the best-signature-time?"),
	TSV_ISCNVABST_ANS("The past signing certificate validation must be performed!"),
	TSV_ATITRO("Are timestamps in the right order?"),
	TSV_ATITRO_ANS("The timestamps were not generated in the right order!"),

	// TSV___("The signature-time-stamp protects the signature against the revocation of the signer's certificate but not against its expiration!"),
	ADEST_IRTPTBST("Is revocation time posterior to best-signature-time?"),
	ADEST_IRTPTBST_ANS("The revocation time is not posterior to best-signature-time!"),
	ADEST_VFDTAOCST_ANS("The validation failed due to the absence of claimed signing time!"),
	ADEST_ISTPTDABST("Is the signing-time plus the timestamp delay after the best-signature-time?"),
	ADEST_ISTPTDABST_ANS("The validation failed due to the timestamp delay constraint!"),
	TSV_WACRABST("Was the algorithm(s) considered reliable at best-signature-time?"),
	TSV_WACRABST_ANS("The algorithm(s) was not considered reliable at best-signature-time!"),

	LABEL_TINTWS("Additional assurance on the signing time may be needed to prove the validity of the signature."),
	LABEL_TINVTWS("There is no valid timestamp within the signature."),

	EMPTY("");


	public static final String NAME_ID = AttributeName.NAME_ID;

	private final String message;

	MessageTag(final String message) {

		this.message = message;
	}

	/**
	 * This method return the message associated with the tag.
	 *
	 * @return {@code String} message.
	 */
	public String getMessage() {
		return message;
	}

	@Override
	public String toString() {
		return message;
	}
}
