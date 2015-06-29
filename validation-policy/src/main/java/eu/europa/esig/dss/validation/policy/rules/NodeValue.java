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

public interface NodeValue {

	String OK = "OK";
	String KO = "NOT OK";
	String IGNORED = "IGNORED";
	String INFORMATION = "INFORMATION";
	// Cannot give the name WARNING, already used as NodeName.
	String WARN = "WARNING";

	String NO_VALID_TIMESTAMP_LABEL = "There is no valid signature timestamp tokens in the signature 'time-stamp' properties/attributes present in the signature.";
	String NO_TIMESTAMP_LABEL = "There is no signature timestamp token in the signature 'time-stamp' properties/attributes present in the signature.";

	// String BBB_ICS_INFO_IIASNE_LABEL = "The issuer or the serial number are not equal.";
	// String BBB_XCV_ICTIVRSC_ANS_LABEL = "The current time is not in the validity range of the signer's certificate.";
	// String BBB_XCV_CCINT_LABEL = "The certificate chain is not trusted.";
	// String BBB_XCV_NRDFC_LABEL = "No revocation data for the certificate [%s]";
	// String BBB_XCV_RDFCINT_LABEL = "The revocation data for the certificate [%s] is not trusted (%s).";
	// String BBB_XCV_CIR_LABEL = "The certificate [%s] is revoked.";
	// String BBB_XCV_SOTSSBUSOA_LABEL = "The status of the trusted service should be: UNDERSUPERVISION, SUPERVISIONINCESSATION or ACCREDITED.";
	//    String BBB_XCV_SCINQ_LABEL = "The signer's certificate is not qualified.";
	/// String BBB_XCV_SCINSBS_LABEL = "The signer's certificate is not supported by SSCD.";
	//    String BBB_XCV_SCINITLP_LABEL = "The signer's certificate is not issued to a legal person.";

	//    String BBB_SAV_ISQPSTP_ANS_LABEL = "The signed qualifying property: 'signing-time' is not present.";
	//
	//    String BBB_SAV_ISQPCHP_ANS_LABEL = "The signed qualifying property: 'content-hints' is not present.";
	//
	//    String BBB_SAV_ISQPCTP_ANS_LABEL = "The signed qualifying property: 'content-type' is not present.";
	//
	//    String BBB_SAV_ISQPCIP_ANS_LABEL = "The signed qualifying property: 'content-identifier' is not present.";
	//
	//    String BBB_SAV_ISQPCTSIP_ANS_LABEL = "The signed qualifying property: 'content-timestamp' is not present.";
	//
	//    String BBB_SAV_ISQPXTIP_ANS_LABEL = "The signed qualifying property: 'commitment-type-indication' is not present.";
	//
	//    String BBB_SAV_ISQPSLP_ANS_LABEL = "The signed qualifying property: 'signer-location' is not present.";

	//    String BBB_SAV_ASCCM_ANS_1_LABEL = "Encryption algorithm not found";
	//    String BBB_SAV_ASCCM_ANS_2_LABEL = "Digest algorithm not found";
	//    String BBB_SAV_ASCCM_ANS_3_LABEL = "Encryption algorithm not found with the given public key size.";
	//    String BBB_SAV_ASCCM_ANS_4_LABEL = "Algorithm expiration date not found.";
	//    String BBB_SAV_ASCCM_ANS_5_LABEL = "Algorithm is expired.";

	//    String PCV_TINTA_LABEL = "There is no trusted anchor.";
	//    String PCV_TIOOCIC_LABEL = "There is only one certificate in the chain.";
	//    String XCV_IFCCIIPC_LABEL = "The interval ['%s', '%s'] for the certificate ['%s'] is inconsistent in the prospective chain.";

	//    String CTS_RBCTSSP_LABEL = "Returned by control time sliding sub-process.";
	String CTS_CTSTRT_LABEL = "Control-time set to revocation time.";
	String CTS_CTSTRIT_LABEL = "Control-time set to revocation issuing time.";
	//    String CTS_RSIFCINCAF_LABEL = "Revocation status information for the certificate ['%s'] is not considered as 'fresh'.";
	String CTS_CTSTETOCSA_LABEL = "Control-time set to expiration time of the certificate's signature algorithm.";
	String CTS_CTSTETORSA_LABEL = "Control-time set to expiration time of the revocation's signature algorithm.";

	//    String _LABEL = "";

}
