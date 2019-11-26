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
package eu.europa.esig.dss.validation.process;

public enum MessageTag implements IMessageTag {

	/* BBB -> FC */
	BBB_FC_IEFF("Does the signature format correspond to an expected format?"),
	BBB_FC_IEFF_ANS("The signature does not correspond to the expected format(s)!"),

	BBB_FC_ICFD("Does the signature cover the whole document(s)?"),
	BBB_FC_ICFD_ANS("The signature does not cover the whole document(s)!"),
	
	BBB_FC_IECTF("Does the container type correspond to an expected type?"),
	BBB_FC_IECTF_ANS("The container type does not correspond to the expected type(s)"),

	BBB_FC_ITZCP("Is the zip file comment present?"),
	BBB_FC_ITZCP_ANS("The zip file comment is absent!"),
	
	BBB_FC_ITEZCF("Does the zip file comment correspond an expected value?"),
	BBB_FC_ITEZCF_ANS("The zip file comment does not correspond the expected value(s)!"),
	
	BBB_FC_ITMFP("Is the mimetype file present?"),
	BBB_FC_ITMFP_ANS("The mimetype file is absent!"),
	
	BBB_FC_IEMCF("Does the mimetype file content correspond to an expected value?"),
	BBB_FC_IEMCF_ANS("The mimetype file content does not correspond to the expected value(s)!"),

	BBB_FC_IMFP_ASICE("Is the manifest file present (ASiC-E)?"),
	BBB_FC_IMFP_ASICE_ANS("The manifest file is absent!"),
	
	BBB_FC_IMFP_ASICS("Is the manifest file absent (ASiC-S)?"),
	BBB_FC_IMFP_ASICS_ANS("The manifest file is present!"),
	
	/* BBB -> CV */
	BBB_CV_IRDOF("Has the reference data object been found?"),
	BBB_CV_IRDOF_ANS("The reference data object has not been found!"),
	BBB_CV_IRDOI("Is the reference data object intact?"),
	BBB_CV_IRDOI_ANS("The reference data object is not intact!"),
	BBB_CV_ISMEC("Is the validation of manifest entries performed?"),
	BBB_CV_ISMEC_ANS("The validation of manifest entries is not performed!"),
	BBB_CV_ISI("Is the signature intact?"),
	BBB_CV_ISI_ANS("The signature is not intact!"),
	BBB_CV_IAFS("Are all files signed?"),
	BBB_CV_IAFS_ANS("Not all files are signed!"),
	
	/* BBB -> ICS */
	BBB_ICS_ISCI("Is there an identified candidate for the signing certificate?"),
	BBB_ICS_ISCI_ANS("There is no candidate for the signing certificate!"),
	BBB_ICS_ISASCP("Is the signed attribute: 'signing-certificate' present?"),
	BBB_ICS_ISASCP_ANS("The signed attribute: 'signing-certificate' is absent!"),
	BBB_ICS_ISACDP("Is the signed attribute: 'cert-digest' of the certificate present?"),
	BBB_ICS_ISACDP_ANS("The signed attribute: 'cert-digest' is absent!"),
	BBB_ICS_ICDVV("Does the certificate digest value match a digest value found in the certificate reference(s)?"),
	BBB_ICS_ICDVV_ANS("The signing certificate digest value does not match!"),
	BBB_ICS_AIDNASNE("Are the issuer distinguished name and the serial number equal?"),
	BBB_ICS_AIDNASNE_ANS("The 'issuer-serial' attribute is absent or does not match!"),

	/* BBB -> RFC */
	BBB_RFC_NUP("Is there a Next Update defined for the revocation data?"),
	BBB_RFC_NUP_ANS("There is no Next Update defined for the revocation data!"),
	BBB_RFC_IRIF("Is the revocation information fresh for the certificate?"),
	BBB_RFC_IRIF_ANS("The revocation status information is not considered as 'fresh'."),
	
	/* BBB -> SAV -> TSP*/
	BBB_SAV_TSP_IMIDF("Is message imprint data found?"),
	BBB_SAV_TSP_IMIDF_ANS("The timestamp message imprint data is not found!"),
	BBB_SAV_TSP_IMSDAV("Is the digest algorithm for timestamp message imprint valid?"),
	BBB_SAV_TSP_IMIVC("Is message imprint verification conclusive?"),
	BBB_SAV_TSP_IMIVC_ANS("The timestamp message imprint verification has failed!"),
	
	
	ADEST_ITVPC("Is the timestamp validation process conclusive?"),
	ADEST_ITVPC_ANS_1("The timestamp is rejected, its generation time is before the best-signature-time!"),
	ADEST_ITVPC_INFO_1("The best-signature-time was set to the generation time of the timestamp."),
	ADEST_ITVPC_ANS_2("Timestamp validation is not conclusive!"),
	ADEST_ROBVPIIC("Is the result of the Basic Validation Process conclusive?"),
	ADEST_ROBVPIIC_ANS("The result of the Basic validation process is not conclusive!"),
	ADEST_ROTVPIIC("Is the result of the timestamps validation process conclusive?"),
	ADEST_ROTVPIIC_ANS("The result of the timestamps validation process is not conclusive!"),
	ADEST_RORPIIC("Is the result of the revocation data validation process acceptable?"),
	ADEST_RORPIIC_ANS("The result of the revocation data validation process is not acceptable!"),

	LTV_ABSV("Is the result of the Basic Validation Process acceptable?"),
	LTV_ABSV_ANS("The result of the Basic validation process is not acceptable to continue the process!"),
	
	ARCH_LTVV("Is the result of the LTV validation process acceptable?"),
	ARCH_LTVV_ANS("The result of the LTV validation process is not acceptable to continue the process!"),

	ASCCM("Are signature cryptographic constraints met?"),
	ACCCM("Are certificate cryptographic constraints met?"),
	ARCCM("Are revocation cryptographic constraints met?"),
	ATCCM("Are timestamp cryptographic constraints met?"),
	ASCCM_ANS_1("The encryption algorithm is not authorised!"),
	ASCCM_ANS_2("The digest algorithm is not authorised!"),
	ASCCM_ANS_3("The public key size is too small!"),
	ASCCM_ANS_4("The algorithm expiration date is not defined!"),
	ASCCM_ANS_5("The algorithm is no longer considered reliable!"),
	ASCCM_ANS_6("The public key size is unknown!"),
	
	ACCCRM("Are cryptographic constraints for certificate revocation data met?"),
	ACCCRM_ANS("Cryptographic constraints are not valid for revocation data!"),

	BBB_SAV_ISVA("Is the signature acceptable?"),
	BBB_SAV_ISVA_ANS("The signature is not acceptable!"),
	BBB_SAV_ISSV("Is the structure of the signature valid?"),
	BBB_SAV_ISSV_ANS("The structure of the signature is not valid!"),
	BBB_SAV_ICERRM("Is the requested certified role present?"),
	BBB_SAV_ICERRM_ANS("The requested certified role is not present!"),
	BBB_SAV_ICRM("Is the requested claimed role present?"),
	BBB_SAV_ICRM_ANS("The requested claimed role is not present!"),
	BBB_SAV_ISQPCTP("Is the signed qualifying property: 'content-type' present?"),
	BBB_SAV_ISQPCTP_ANS("The signed qualifying property: 'content-type' is not present!"),
	BBB_SAV_ISQPCHP("Is the signed qualifying property: 'content-hints' present?"),
	BBB_SAV_ISQPCHP_ANS("The signed qualifying property: 'content-hints' is not present!"),
	BBB_SAV_ISQPCIP("Is the signed qualifying properties: 'content-identifier' present?"),
	BBB_SAV_ISQPCIP_ANS("The signed qualifying property: 'content-identifier' is not present!"),
	BBB_SAV_ISQPCTSIP("Is the signed qualifying property: 'content-timestamp' present?"),
	BBB_SAV_ISQPCTSIP_ANS("The signed qualifying property: 'content-timestamp' is not present!"),
	BBB_SAV_ISQPSLP("Is the signed qualifying property: 'signer-location' present?"),
	BBB_SAV_ISQPSLP_ANS("The signed qualifying property: 'signer-location' is not present!"),
	BBB_SAV_ISQPSTP("Is the signed qualifying property: 'signing-time' present?"),
	BBB_SAV_ISQPSTP_ANS("The signed qualifying property: 'signing-time' is not present!"),
	BBB_SAV_ISQPXTIP("Is the signed qualifying property: 'commitment-type-indication' present?"),
	BBB_SAV_ISQPXTIP_ANS("The signed qualifying property: 'commitment-type-indication' is not present!"),
	BBB_SAV_IUQPCSP("Is the unsigned qualifying property: 'countersignature' present?"),
	BBB_SAV_IUQPCSP_ANS("The unsigned qualifying property: 'countersignature' is not present!"),
	BBB_SAV_ISQPMDOSPP("Is the signed qualifying property: 'message-digest' or 'SignedProperties' present?"),
	BBB_SAV_ISQPMDOSPP_ANS("The signed qualifying property: neither 'message-digest' nor 'SignedProperties' is present!"),

	BBB_VCI_ISPK("Is the signature policy known?"),
	BBB_VCI_ISPK_ANS_1("The signature policy is mandatory!"),

	BBB_VCI_ISPA("Is the signature policy available?"),
	BBB_VCI_ISPA_ANS("The signature policy is not available!"),
	
	BBB_VCI_ISPM("Does the signature policy's digest value match?"),
	BBB_VCI_ISPM_ANS("The signature policy's digest value does not match the computed value!"),

	BBB_XCV_SUB("Is the certificate validation conclusive?"),
	BBB_XCV_SUB_ANS("The certificate validation is not conclusive!"),
	BBB_XCV_RFC("Is the revocation freshness check conclusive?"),
	BBB_XCV_RFC_ANS("The revocation freshness check is not conclusive!"),
	BBB_XCV_ACCCM("Are chain cryptographic constraints met?"),
	BBB_XCV_ACCM("Are chain constraints met?"),
	BBB_XCV_ARDCCM("Are revocation data cryptographic constraints met?"),
	BBB_XCV_CCCBB("Can the certificate chain be built till a trust anchor?"),
	BBB_XCV_CCCBB_ANS("The certificate chain is not trusted, it does not contain a trust anchor."),
	BBB_XCV_CCCBB_SIG_ANS("The certificate chain for signature is not trusted, it does not contain a trust anchor."),
	BBB_XCV_CCCBB_TSP_ANS("The certificate chain for timestamp is not trusted, it does not contain a trust anchor."),
	BBB_XCV_CCCBB_REV_ANS("The certificate chain for revocation data is not trusted, it does not contain a trust anchor."),
	BBB_XCV_CMDCIPI("Certificate meta-data constraints: Does it contain a required policy id?"),
	BBB_XCV_CMDCIPI_ANS("None of the required policy ids have been found in the certificate"),
	BBB_XCV_CMDCIQCS("Certificate meta-data constraints: Does it contain a required QC Statement id?"),
	BBB_XCV_CMDCIQCS_ANS("None of the required QC Statement ids are found in the certificate."),
	BBB_XCV_CMDCIITLP("Certificate meta-data constraints: Has it been issued to a legal person?"),
	BBB_XCV_CMDCIITLP_ANS("The certificate has not been issued to a legal person."),
	BBB_XCV_CMDCIITNP("Certificate meta-data constraints: Has it been issued to a natural person?"),
	BBB_XCV_CMDCIITNP_ANS("The certificate has not been issued to a natural person."),
	BBB_XCV_CMDCIQC("Certificate meta-data constraints: Is the signer's certificate qualified?"),
	BBB_XCV_CMDCIQC_ANS("The certificate is not qualified!"),
	BBB_XCV_CMDCIQSCD("Certificate meta-data constraints: Is it supported by a QSCD?"),
	BBB_XCV_CMDCIQSCD_ANS("The certificate is not supported by a QSCD!"),
	BBB_XCV_ICTIVRSC("Is the current time in the validity range of the signer's certificate?"),
	BBB_XCV_ICTIVRSC_ANS("The current time is not in the validity range of the signer's certificate."),
	BBB_XCV_IRDPFC("Is the revocation data present for the certificate?"),
	BBB_XCV_IRDPFC_ANS("No revocation data for the certificate"),
	BBB_VTS_IRDPFC("Is there a satisfying revocation status information?"),
	BBB_VTS_IRDPFC_ANS("No satisfying revocation status information found for the certificate"),
	BBB_XCV_IRDTFC("Is the revocation data for the certificate trusted?"),
	BBB_XCV_IRDTFC_ANS("The revocation data for the certificate is not trusted!"),
	BBB_XCV_IRIF("Is the revocation information for the certificate fresh?"),
	BBB_XCV_IRIF_ANS("The revocation status information is not considered as fresh."),
	BBB_XCV_ISCOH("Is the certificate on hold?"),
	BBB_XCV_ISCOH_ANS("The certificate is on hold!"),
	BBB_XCV_ISCR("Is the certificate not revoked?"),
	BBB_XCV_ISCR_ANS("The certificate is revoked!"),
	BBB_XCV_ISCGKU("Does the signer's certificate have an expected key-usage?"),
	BBB_XCV_ISCGKU_ANS("The signer's certificate does not have an expected key-usage!"),
	BBB_XCV_ISCGEKU("Does the signer's certificate have an expected 'extended key-usage(s)'?"),
	BBB_XCV_ISCGEKU_ANS("The signer's certificate does not have an expected 'extended key-usage'!"),
	BBB_XCV_ICSI("Is the certificate signature intact?"),
	BBB_XCV_ICSI_ANS("The signature of the certificate is either corrupted or it is not possible to validate it!"),
	BBB_XCV_OCSP_NO_CHECK("The certificate has the id-pkix-ocsp-nocheck extension (RFC is skipped)"),
	BBB_XCV_PSEUDO_USE("Is a pseudonym used?"),
	BBB_XCV_PSEUDO_USE_ANS("A pseudonym is used"),
	BBB_XCV_AIA_PRES("Is the authority info access present?"),
	BBB_XCV_AIA_PRES_ANS("The authority info access is not present!"),
	BBB_XCV_REVOC_PRES("Is the revocation info access present?"),
	BBB_XCV_REVOC_PRES_ANS("The revocation info access is not present!"),
	BBB_XCV_REVOC_CERT_HASH("Does the certHash from OCSP Response(s) match?"),
	BBB_XCV_REVOC_CERT_HASH_ANS("The certHash content does not match the current certificate!"),

	BBB_XCV_ISCGCOUN("Does the certificate subject name contain an expected country-name attribute?"),
	BBB_XCV_ISCGCOUN_ANS("The country-name attribute does not correspond to the expected value(s)!"),
	BBB_XCV_ISCGORGAN("Does the certificate subject name contain an expected organization name attribute?"),
	BBB_XCV_ISCGORGAN_ANS("The organization name attribute does not correspond to the expected value(s)!"),
	BBB_XCV_ISCGORGAU("Does the certificate subject name contain an expected organization unit attribute?"),
	BBB_XCV_ISCGORGAU_ANS("The organization unit attribute does not correspond to the expected value(s)!"),
	BBB_XCV_ISCGSURN("Does the certificate subject name contain an expected surname attribute?"),
	BBB_XCV_ISCGSURN_ANS("The surname attribute does not correspond to the expected value(s)!"),
	BBB_XCV_ISCGGIVEN("Does the certificate subject name contain an expected 'given name' attribute?"),
	BBB_XCV_ISCGGIVEN_ANS("The 'given name' attribute does not correspond to the expected value(s)!"),
	BBB_XCV_ISCGPSEUDO("Does the certificate subject name contain an expected pseudonym attribute?"),
	BBB_XCV_ISCGPSEUDO_ANS("The pseudonym attribute does not correspond to the expected value(s)!"),
	BBB_XCV_ISCGCOMMONN("Does the certificate subject name contain an expected common name attribute?"),
	BBB_XCV_ISCGCOMMONN_ANS("The common name attribute does not correspond to the expected value(s)!"),

	BBB_XCV_ISSSC("Is the certificate self-signed?"),
	BBB_XCV_ISSSC_ANS("The certificate is not self-signed!"),
	
	BBB_XCV_ISNSSC("Is certificate not self-signed?"),
	BBB_XCV_ISNSSC_ANS("The certificate is self-signed!"),

	XCV_IFCCIIPC_ANS("The interval ['%s', '%s'] for the certificate ['%s'] is inconsistent in the prospective chain."),

	XCV_TSL_ESP("Has a trust service with an expected status been found?"),
	XCV_TSL_ESP_ANS("The trust service(s) does not have the expected status!"),
	XCV_TSL_ESP_SIG_ANS("The trust service(s) related to the signing certificate does not have the expected status!"),
	XCV_TSL_ESP_TSP_ANS("The trust service(s) related to the timestamp does not have the expected status!"),
	XCV_TSL_ESP_REV_ANS("The trust service(s) related to the revocation does not have expected status!"),
	XCV_TSL_ETIP("Has a trust service with an expected type identifier been found?"),
	XCV_TSL_ETIP_ANS("The trust service(s) does not have the expected type identifier!"),
	XCV_TSL_ETIP_SIG_ANS("The trust service(s) related to the signing certificate does not have the expected type identifier!"),
	XCV_TSL_ETIP_TSP_ANS("The trust service(s) related to the timestamp does not have the expected type identifier!"),
	XCV_TSL_ETIP_REV_ANS("The trust service(s) related to the revocation does not have the expected type identifier!"),

	PCV_IVTSC("Is the validation time sliding process conclusive?"),
	PCV_IVTSC_ANS("The indications returned by validation time sliding sub-process."),

	PSV_IPCVA("Is the past certificate validation conclusive?"),
	PSV_IPCVA_ANS("The past certificate validation is not conclusive!"),
	PSV_IPCVC("No POE, what is the current time validation?"),
	PSV_IPCVC_ANS("The current time validation is not conclusive!"),
	PSV_IPSVC("Is the past signature validation conclusive?"),
	PSV_IPSVC_ANS("The past signature validation is not conclusive!"),
	PSV_IPTVC("Is the past timestamp validation conclusive?"),
	PSV_IPTVC_ANS("The past timestamp validation is not conclusive!"),
	PSV_ITPOCOBCT("Is there a POE of the certificate at (or before) control-time?"),
	PSV_ITPOSVAOBCT("Is there a POE of the signature value at (or before) control-time?"),
	PSV_ITPORDAOBCT("Is there a POE of the revocation data at (or before) control-time?"),
	PSV_ITPOOBCT_ANS("No Proof Of Existence found at (or before) control-time!"),

	TSV_ASTPTCT("Are the timestamps in the right order?"),
	TSV_ASTPTCT_ANS("The timestamps were not generated in the right order!"),
	TSV_IBSTAIDOSC("Is the best-signature-time after the issuance date of the signing certificate?"),
	TSV_IBSTAIDOSC_ANS("The best-signature-time is before the issuance date of the signing certificate!"),
	TSV_ISCNVABST("Is the signing certificate valid at best-signature-time?"),
	TSV_ISCNVABST_ANS("A past certificate validation must be performed!"),

	ADEST_IRTPTBST("Is the revocation time after best-signature-time?"),
	ADEST_IRTPTBST_ANS("The revocation time is not after best-signature-time!"),
	ADEST_VFDTAOCST_ANS("The validation failed due to the absence of a claimed 'signing time'!"),
	ADEST_ISTPTDABST("Is the signing-time plus the timestamp delay after best-signature-time?"),
	ADEST_ISTPTDABST_ANS("The validation failed due to the timestamp delay constraint!"),
	TSV_WACRABST("Was the algorithm(s) considered reliable at best-signature-time?"),
	TSV_WACRABST_ANS("The algorithm(s) was not considered reliable at best-signature-time!"),

	LABEL_TINTWS("Additional assurance on the signing time may be needed to prove the validity of the signature."),
	LABEL_TINVTWS("There is no valid timestamp within the signature."),

	VTS_IRC("Is the revocation data consistant?"),
	VTS_IRC_ANS("The revocation data is not consistant!"),
	VTS_ICTBRD("Is the issuance date before control-time?"),
	VTS_ICTBRD_ANS("The issuance date of revocation data is not before control-time!"),

	QUAL_TL_EXP("Is the trusted list not expired?"),
	QUAL_TL_EXP_ANS("The next-update time of the trusted list is in the past!"),
	QUAL_TL_FRESH("Is the trusted list fresh?"),
	QUAL_TL_FRESH_ANS("The trusted list is not considered as fresh!"),
	QUAL_TL_VERSION("Does the trusted list have the expected version?"),
	QUAL_TL_VERSION_ANS("The trusted list does not have the expected version!"),
	QUAL_TL_WS("Is the trusted list well signed?"),
	QUAL_TL_WS_ANS("The trusted list is not well signed!"),
	
	QUAL_TL_SERV_CONS("Is the trust service consistent?"),
	QUAL_TL_SERV_CONS_ANS0("No CA/QC trust service found"),
	QUAL_TL_SERV_CONS_ANS1("The trust service is not consistent! (QCStatement and NotQualified)"),
	QUAL_TL_SERV_CONS_ANS2("The trust service is not consistent! (QCForLegalPerson and QCForeSig)"),
	QUAL_TL_SERV_CONS_ANS3("The trust service is not consistent! (X_QSCD and NotQSCD)"),
	QUAL_TL_SERV_CONS_ANS3A("The trust service is not consistent! (QSCDStatusAsInCert and X_QSCD)"),
	QUAL_TL_SERV_CONS_ANS4("The trust service is not consistent! (incompatible usages of QCForeSig, QCForeSeal, QCForWSA)"),
	QUAL_TL_SERV_CONS_ANS5("The trust service is not consistent! (invalid additional service info / qualifier in service before 1/7/16)"),
	QUAL_TL_SERV_CONS_ANS6("The trust service is not consistent! (conflict between additional service info and qualifier)"),

	QUAL_TRUSTED_CERT_PATH("Is the certificate path trusted?"),
	QUAL_TRUSTED_CERT_PATH_ANS("The certificate path is not trusted!"),

	QUAL_TRUSTED_LIST_ACCEPT("Is the trusted list acceptable?"),
	QUAL_TRUSTED_LIST_ACCEPT_ANS("The trusted list is not acceptable!"),

	QUAL_FOR_SIGN_AT_ST("Is the certificate for eSig at (best) signing time?"),
	QUAL_FOR_SIGN_AT_ST_ANS("The certificate is not for eSig at (best) signing time!"),
	QUAL_FOR_SIGN_AT_CC("Is the certificate for eSig at issuance time?"),
	QUAL_FOR_SIGN_AT_CC_ANS("The certificate is not for eSig at issuance time!"),
	QUAL_FOR_SIGN_AT_VT("Is the certificate for eSig at validation time?"),
	QUAL_FOR_SIGN_AT_VT_ANS("The certificate is not for eSig at validation time!"),

	QUAL_QC_AT_ST("Is the certificate qualified at (best) signing time?"),
	QUAL_QC_AT_ST_ANS("The certificate is not qualified at (best) signing time!"),
	QUAL_QC_AT_CC("Is the certificate qualified at issuance time?"),
	QUAL_QC_AT_CC_ANS("The certificate is not qualified at issuance time!"),
	QUAL_QC_AT_VT("Is the certificate qualified at validation time?"),
	QUAL_QC_AT_VT_ANS("The certificate is not qualified at validation time!"),

	QUAL_QSCD_AT_ST("Does the private key reside in a QSCD at (best) signing time?"),
	QUAL_QSCD_AT_ST_ANS("The private key does not reside in a QSCD at (best) signing time!"),
	QUAL_QSCD_AT_CC("Does the private key reside in a QSCD at issuance time?"),
	QUAL_QSCD_AT_CC_ANS("The private key does not reside in a QSCD at issuance time!"),
	QUAL_QSCD_AT_VT("Does the private key reside in a QSCD at validation time?"),
	QUAL_QSCD_AT_VT_ANS("The private key does not reside in a QSCD at validation time!"),

	QUAL_UNIQUE_CERT("Is the certificate unique?"),
	QUAL_UNIQUE_CERT_ANS("The certificate cannot be defined as unique!"),
	QUAL_IS_ADES("Is the signature/seal an acceptable AdES digital signature (ETSI EN 319 102-1)?"),
	QUAL_IS_ADES_IND("The signature/seal is an INDETERMINATE AdES digital signature!"),
	QUAL_IS_ADES_INV("The signature/seal is not a valid AdES digital signature!"),
	
	QUAL_HAS_CAQC("Is the certificate related to a CA/QC?"),
	QUAL_HAS_CAQC_ANS("The certificate is not related to a CA/QC!"),
	
	QUAL_IS_TRUST_CERT_MATCH_SERVICE("Does the trusted certificate match the trust service?"),
	QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS0("No trusted certificate found!"),
	QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS1("The organization name is missing in the trusted certificate!"),
	QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS2("The trusted certificate does not match the trust service!"),

	QUAL_HAS_GRANTED("Is the certificate related to a trust service with a granted status?"),
	QUAL_HAS_GRANTED_ANS("The certificate is not related to a granted status!"),

	QUAL_HAS_CONSISTENT("Is the certificate related to a consistent trust service declaration?"),
	QUAL_HAS_CONSISTENT_ANS("The certificate is not related to a consistent trust service declaration!"),

	QUAL_HAS_CERT_TYPE_COVERAGE("Can the certificate type be issued by a found trust service?"),
	QUAL_HAS_CERT_TYPE_COVERAGE_ANS("The certificate type cannot be issued by the found trust service(s)!"),

	QUAL_HAS_ONLY_ONE("Is the certificate qualification conclusive?"),
	QUAL_HAS_ONLY_ONE_ANS("There is a possible conflict between trust services!"),
	
	BBB_ACCEPT("Is the result of the Basic Building Block conclusive?"),
	BBB_ACCEPT_ANS("The result of the Basic Building Block is not conclusive!"),
	
	EMPTY("");

	private final String message;

	MessageTag(final String message) {
		this.message = message;
	}

	/**
	 * This method return the id code of the referred message.
	 *
	 * @return {@code String} message.
	 */
	@Override
	public String getId() {
		return name();
	}

	/**
	 * This method return the message associated with the tag.
	 *
	 * @return {@code String} message.
	 */
	@Override
	public String getMessage() {
		return message;
	}

	@Override
	public String toString() {
		return message;
	}
}
