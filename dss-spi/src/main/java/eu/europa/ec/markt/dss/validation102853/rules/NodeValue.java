/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.validation102853.rules;

public interface NodeValue {

    public static final String OK = "OK";
    public static final String KO = "NOT OK";
    public static final String IGNORED = "IGNORED";
    public static final String INFORMATION = "INFORMATION";
    // Cannot give the name WARNING, already used as NodeName.
    public static final String WARN = "WARNING";

    public static final String NO_VALID_TIMESTAMP_LABEL = "There is no valid signature timestamp tokens in the signature 'time-stamp' properties/attributes present in the signature.";
    public static final String NO_TIMESTAMP_LABEL = "There is no signature timestamp token in the signature 'time-stamp' properties/attributes present in the signature.";

    // public static final String BBB_ICS_INFO_IIASNE_LABEL = "The issuer or the serial number are not equal.";
    // public static final String BBB_XCV_ICTIVRSC_ANS_LABEL = "The current time is not in the validity range of the signer's certificate.";
    // public static final String BBB_XCV_CCINT_LABEL = "The certificate chain is not trusted.";
    // public static final String BBB_XCV_NRDFC_LABEL = "No revocation data for the certificate [%s]";
    // public static final String BBB_XCV_RDFCINT_LABEL = "The revocation data for the certificate [%s] is not trusted (%s).";
    // public static final String BBB_XCV_CIR_LABEL = "The certificate [%s] is revoked.";
    // public static final String BBB_XCV_SOTSSBUSOA_LABEL = "The status of the trusted service should be: UNDERSUPERVISION, SUPERVISIONINCESSATION or ACCREDITED.";
    //    public static final String BBB_XCV_SCINQ_LABEL = "The signer's certificate is not qualified.";
    /// public static final String BBB_XCV_SCINSBS_LABEL = "The signer's certificate is not supported by SSCD.";
//    public static final String BBB_XCV_SCINITLP_LABEL = "The signer's certificate is not issued to a legal person.";

//    public static final String BBB_SAV_ISQPSTP_ANS_LABEL = "The signed qualifying property: 'signing-time' is not present.";
//
//    public static final String BBB_SAV_ISQPCHP_ANS_LABEL = "The signed qualifying property: 'content-hints' is not present.";
//
//    public static final String BBB_SAV_ISQPCTP_ANS_LABEL = "The signed qualifying property: 'content-type' is not present.";
//
//    public static final String BBB_SAV_ISQPCIP_ANS_LABEL = "The signed qualifying property: 'content-identifier' is not present.";
//
//    public static final String BBB_SAV_ISQPCTSIP_ANS_LABEL = "The signed qualifying property: 'content-timestamp' is not present.";
//
//    public static final String BBB_SAV_ISQPXTIP_ANS_LABEL = "The signed qualifying property: 'commitment-type-indication' is not present.";
//
//    public static final String BBB_SAV_ISQPSLP_ANS_LABEL = "The signed qualifying property: 'signer-location' is not present.";

//    public static final String BBB_SAV_ASCCM_ANS_1_LABEL = "Encryption algorithm not found";
//    public static final String BBB_SAV_ASCCM_ANS_2_LABEL = "Digest algorithm not found";
//    public static final String BBB_SAV_ASCCM_ANS_3_LABEL = "Encryption algorithm not found with the given public key size.";
//    public static final String BBB_SAV_ASCCM_ANS_4_LABEL = "Algorithm expiration date not found.";
//    public static final String BBB_SAV_ASCCM_ANS_5_LABEL = "Algorithm is expired.";

    //public static final String PCV_TINTA_LABEL = "There is no trusted anchor.";
//    public static final String PCV_TIOOCIC_LABEL = "There is only one certificate in the chain.";
    //public static final String XCV_IFCCIIPC_LABEL = "The interval ['%s', '%s'] for the certificate ['%s'] is inconsistent in the prospective chain.";

    //    public static final String CTS_RBCTSSP_LABEL = "Returned by control time sliding sub-process.";
    public static final String CTS_CTSTRT_LABEL = "Control-time set to revocation time.";
    public static final String CTS_CTSTRIT_LABEL = "Control-time set to revocation issuing time.";
    // public static final String CTS_RSIFCINCAF_LABEL = "Revocation status information for the certificate ['%s'] is not considered as 'fresh'.";
    public static final String CTS_CTSTETOCSA_LABEL = "Control-time set to expiration time of the certificate's signature algorithm.";
    public static final String CTS_CTSTETORSA_LABEL = "Control-time set to expiration time of the revocation's signature algorithm.";

    // public static final String _LABEL = "";
    // public static final String _LABEL = "";
    // public static final String _LABEL = "";
    // public static final String _LABEL = "";
}
