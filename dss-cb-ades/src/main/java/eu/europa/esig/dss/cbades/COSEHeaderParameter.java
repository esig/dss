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
package eu.europa.esig.dss.cbades;

import eu.europa.ec.digit.cddl4j.cbor.CBOR;
import eu.europa.ec.digit.cddl4j.cbor.CBORValue;

/**
 * Contains a list of COSE and CB-AdES header parameter definitions
 *
 */
public enum COSEHeaderParameter {

    /* RFC 9052 Header parameters */

    /** Cryptographic algorithm used for signature creation. CBOR Tag '1' */
    ALG(1L),

    /** Critical header parameters to be understood. CBOR Tag '2' */
    CRIT(2L),

    /** Content Type of the payload. CBOR Tag '3' */
    CONTENT_TYPE(3L),

    /** Key identifier. CBOR Tag '4' */
    KID(4L),

    /** Initialization Vector. CBOR Tag '5' */
    IV(5L),

    /** Partial Initialization Vector. CBOR Tag '6' */
    PARTIAL_IV(6L),

    /* RFC 8152 Header parameters */

    /** Counter signature. CBOR Tag '7' */
    COUNTER_SIGNATURE(7L),

    /** Counter signature0. CBOR Tag '9' */
    COUNTER_SIGNATURE0(9L),

    /* RFC 9338 Header parameters */

    /** Counter signature V2. CBOR Tag '11' */
    COUNTER_SIGNATURE_V2(11L),

    /** Counter signature0 V2. CBOR Tag '12' */
    COUNTER_SIGNATURE0_V2(12L),

    /* RFC 9597 Header Parameters */

    /** CWT Claims. CBOR Tag '15' */
    CWT_CLAIMS(15L),

    /* RFC 9596 Header Parameters */

    /** Type. CBOR Tag '16' */
    SIGNATURE_TYPE(16L),

    /* RFC 9360 Header parameters */

    /** An unordered bag of X.509 certificates. CBOR Tag '32' */
    X5BAG(32L),

    /** An ordered chain of X.509 certificates. CBOR Tag '33' */
    X5CHAIN(33L),

    /** Hash of an X.509 certificate. CBOR Tag '34' */
    X5T(34L),

    /** URI pointing to an X.509 certificate. CBOR Tag '35' */
    X5U(35L),

    /* ETSI TS 119 152 Header parameters */

    /** Reference to signing certificate / certs in cert path. CBOR Tag '261' */
    X5TS(261L),

    /** Signer commitments. CBOR Tag '262' */
    SR_CMS(262L),

    /** Signature production place. CBOR Tag '263' */
    SIG_PL(263L),

    /** Signer attributes. CBOR Tag '264' */
    SR_ATS(264L),

    /** COSE payload time-stamp. CBOR Tag '265' */
    ADO_TST(265L),

    /** Signature Policy Identifier. CBOR Tag '266' */
    SIG_PID(266L),

    /** Detached COSE Payload reference data. CBOR Tag '267' */
    SIG_D(267L),

    /* ETSI TS 119 152 uHeaders parameters */

    /** uHeaders header parameter contains a list of unsigned properties qualifying the CB-AdES signature. CBOR Tag '268' */
    U_HEADERS(268L),

    /** Signature time-stamp. CBOR Tag '1' */
    SIG_TST(1L),

    /** Validation data. CBOR Tag '2' */
    VAL_DATA(2L),

    /** Archive time-stamp. CBOR Tag '3' */
    ARC_TST(3L),

    /** Validation data references. CBOR Tag '4' */
    REFS(4L),

    /** Signature and validation data references time-stamp. CBOR Tag '5' */
    SIG_R_TST(5L),

    /** Validation data references time-stamp. CBOR Tag '6' */
    RFS_TST(6L),

    /** Signature policy document. CBOR Tag '7' */
    SIG_PST(7L),

    /* Subtype keys */

    /** SrCm commId: the commitment identifier: an oId data type. CBOR Tag '1' */
    SR_CM_COMM_ID(1L),

    /** SrCm commQuals: qualifiers. CBOR Tag '2' */
    SR_CM_COMM_QUALS(2L),

    /** oId id: the URI reference that is the object identifier. CBOR Tag '1' */
    OID_ID(1L),

    /** oId desc: a textual description of the identified object. CBOR Tag '2' */
    OID_DESC(2L),

    /** oId docRefs: an array of URI references to documents specifying the identified object. CBOR Tag '3' */
    OID_DOC_REFS(3L),

    /** pkiOb val: CBOR byte string encapsulating the encoded PKI object. CBOR Tag '1' */
    PKI_OB_VAL(1L),

    /** pkiOb encoding: a URI reference identifying the encoding. CBOR Tag '2' */
    PKI_OB_ENCODING(2L),

    /** pkiOb specRef: a URI reference identifying the specification of the encapsulated PKI object. CBOR Tag '3' */
    PKI_OB_SPEC_REF(3L),

    /** sigPl addressCountry. CBOR Tag '1' */
    SIG_PL_ADDRESS_COUNTRY(1L),

    /** sigPl addressLocality. CBOR Tag '2' */
    SIG_PL_ADDRESS_LOCALITY(2L),

    /** sigPl addressRegion. CBOR Tag '3' */
    SIG_PL_ADDRESS_REGION(3L),

    /** sigPl postOfficeBoxNumber. CBOR Tag '4' */
    SIG_PL_POST_OFFICE_BOX_NUMBER(4L),

    /** sigPl postalCode. CBOR Tag '5' */
    SIG_PL_POSTAL_CODE(5L),

    /** sigPl streetAddress. CBOR Tag '6' */
    SIG_PL_STREET_ADDRESS(6L),

    /** srAts certified: Certified signer attributes. CBOR Tag '1' */
    SR_ATS_CERTIFIED_ATTRS(1L),

    /** srAts signedAssertions: Signed assertions for signer. CBOR Tag '2' */
    SR_ATS_SIGNED_ASSERTIONS(2L),

    /** srAts claimed: Claimed signer attributes. CBOR Tag '3' */
    SR_ATS_CLAIMED(3L),

    /** srAtms certified CertifiedAttr x509AttrCert: encapsulates a X.509 attribute certificate. CBOR Tag '1' */
    CERTIFIED_ATTR_X509_ATTR_CERT(1L),

    /** srAtms certified CertifiedAttr otherAttrCert: encapsulates another type of attribute certificate. CBOR Tag '2' */
    CERTIFIED_ATTR_OTHER_ATTR_CERT(2L),

    /** tstContainer tstTokens: CBOR array containing one or more time-stamp tokens. CBOR Tag '1' */
    TST_CONTAINER_TST_TOKENS(1L),

    /** tstToken val: Encoded time-stamp token encapsulated in a CBOR byte string. CBOR Tag '1' */
    TST_TOKEN_VAL(1L),

    /** tstToken type: String identifying the type of time-stamp token. CBOR Tag '2' */
    TST_TOKEN_TYPE(2L),

    /** tstToken encoding: URI reference identifying the type of encoding. CBOR Tag '3' */
    TST_TOKEN_ENCODING(3L),

    /** tstToken specRef: a URI reference identifying the reference where the time-stamp token is defined. CBOR Tag '4' */
    TST_TOKEN_SPEC_REF(4L),

    /** sigPId id: instance of oId type identifying the signature policy. CBOR Tag '1' */
    SIG_P_ID_ID(1L),

    /** sigPId digAlgVal: digest algorithm and value of the signature policy document. CBOR Tag '2' */
    SIG_P_ID_DIG_ALG_VAL(2L),

    /** sigPId digPSp: indicates whether the digest has been computed according to some spec, default value: false. CBOR Tag '3' */
    SIG_P_ID_DIG_P_SP(3L),

    /** sigPId sigPQuals: signature policy qualifiers. CBOR Tag '4' */
    SIG_P_ID_SIG_P_QUALS(4L),

    /** SigPQual spURI: URL where a copy of the signature policy document can be obtained. CBOR Tag '1' */
    SIG_P_QUAL_SP_URI(1L),

    /** SigPQual spUserNotice: Info displayed when signature is validated. CBOR Tag '2' */
    SIG_P_QUAL_SP_USER_NOTICE(2L),

    /** SigPQual spDSpec: identifier of the technical specification that defines the syntax used for producing the signature policy document. CBOR Tag '3' */
    SIG_P_QUAL_SP_D_SPEC(3L),

    /** spUserNotice noticeRef: User notice and references. CBOR Tag '1' */
    SP_USER_NOTICE_NOTICE_REF(1L),

    /** spUserNotice explText: notice text to be displayed. CBOR Tag '2' */
    SP_USER_NOTICE_EXPL_TEXT(2L),

    /** noticeRef org: the name of the organization. CBOR Tag '1' */
    NOTICE_REF_ORG(1L),

    /** noticeRef noticeNumbers: the notice numbers identifying textual statements. CBOR Tag '2' */
    NOTICE_REF_NOTICE_NUMBERS(2L),

    /** sigD mId: URI identifying the mechanism used for referencing and processing each referenced data object. CBOR Tag '1' */
    SIG_D_MID(1L),

    /** sigD pars: References to data objects as per the mechanism identified by mId. CBOR Tag '2' */
    SIG_D_PARS(2L),

    /** sigD hashM: Digest algorithm identifier. CBOR Tag '3' */
    SIG_D_HASH_M(3L),

    /** sigD hashV: Digest values of referenced data objects as per algorithm identified by hashM. CBOR Tag '4' */
    SIG_D_HASH_V(4L),

    /** sigD ctys: Indication of the content type of each referenced object. CBOR Tag '5' */
    SIG_D_CTYS(5L),

    /** valData xVals: DER-encoded encapsulated X.509 certificates or other encapsulated certificates. CBOR Tag '1' */
    VAL_DATA_X_VALS(1L),

    /** valData rVals: validation material. CBOR Tag '2' */
    VAL_DATA_R_VALS(2L),

    /** X509OrOther x509Cert: DER-encoded X509 certificate encapsulated in an instance of pkiOb type. CBOR Tag '1' */
    X509_OR_OTHER_X509_CERT(1L),

    /** X509OrOther otherCert: otherCert: Other type of certificate encoded and encapsulated in an instance of pkiOb type. CBOR Tag '2' */
    X509_OR_OTHER_OTHER_CERT(2L),

    /** rVals crlVals: array of CRLs encapsulated in an instance of pkiOb type. CBOR Tag '1' */
    R_VALS_CRL_VALS(1L),

    /** rVals ocspVals: array of DER encoded OCSPResponse encapsulated in an instance of pkiOb type. CBOR Tag '2' */
    R_VALS_OCSP_VALS(2L),

    /** rVals otherVals: other revocation values encoded and encapsulated in an instance of pkiOb type. CBOR Tag '3' */
    R_VALS_OTHER_VALS(3L),

    /** refs xRefs: references to certificates. CBOR Tag '1' */
    REFS_X_REFS(1L),

    /** refs rRefs: references to revocation data. CBOR Tag '2' */
    REFS_R_REFS(2L),

    /** CertId x5t: the digest algorithm identifier and value. CBOR Tag '1' */
    CERT_ID_X5T(1L),

    /** CertId kid: optional key identifier. CBOR Tag '2' */
    CERT_ID_KID(2L),

    /** CertId x5u: URI reference to X.509 certificate. CBOR Tag '3' */
    CERT_ID_X5U(3L),

    /** rRefs crlRefs: array of references to CRLs. CBOR Tag '1' */
    R_REFS_CRL_REF(1L),

    /** rRefs ocspRefs: array of references to OCSP responses. CBOR Tag '2' */
    R_REFS_OCSP_REF(2L),

    /** rRefs otherRefs: array of references to OCSP responses. CBOR Tag '3' */
    R_REFS_ANY(3L),

    /** CRLRef digAlgVal: digest algorithm and value of DER-encoded CRL. CBOR Tag '1' */
    CRL_REF_DIG_ALG_VAL(1L),

    /** CRLRef crlId: identifier of the CRL. CBOR Tag '2' */
    CRL_REF_CRL_ID(2L),

    /** CRLId issuer: the DER-encoded issuer of the CRL. CBOR Tag '1' */
    CRL_ID_ISSUER(1L),

    /** CRLId issueTime: the date and time of issuance. CBOR Tag '2' */
    CRL_ID_ISSUE_TIME(2L),

    /** CRLId number: the issuance number. CBOR Tag '3' */
    CRL_ID_NUMBER(3L),

    /** CRLId uri: an URI reference to the CRL (hint). CBOR Tag '4' */
    CRL_ID_URI(4L),

    /** OCSPRef digAlgVal: digest algorithm and value of the OCSP response. CBOR Tag '1' */
    OCSP_REF_DIG_ALG_VAL(1L),

    /** OCSPRef ocspId: identifier of the OCSP response. CBOR Tag '2' */
    OCSP_REF_OCSP_ID(2L),

    /** OCSPId responderChoice: a choice for identifying the responder. CBOR Tag '1' */
    OCSP_ID_RESPONDER_ID_CHOICE(1L),

    /** OCSPId producedAt: same time as the time indicated by the ProducedAt field of the referenced OCSP response. CBOR Tag '2' */
    OCSP_ID_PRODUCED_AT(2L),

    /** OCSPId uri: an URI reference to the OCSP response (hint). CBOR Tag '3' */
    OCSP_ID_URI(3L),

    /** ResponderIdChoice responderIdByName: the name of the responder wrapped in a CBOR byte string. CBOR Tag '1' */
    RESPONDER_ID_CHOICE_RESPONDER_ID_BY_NAME(1L),

    /** ResponderIdChoice responderIdByKey: the key of the responder wrapped in a CBOR byte string. CBOR Tag '2' */
    RESPONDER_ID_CHOICE_RESPONDER_ID_BY_KEY(2L);
    
    /** Long encoded key */
    private final CBORValue cborKey;

    /**
     * Default constructor
     * 
     * @param longKey long key value
     */
    COSEHeaderParameter(final Long longKey) {
        this.cborKey = CBOR.integer(longKey);
    }

    /**
     * Gets a representation of the key in a form of a CBOR object
     *
     * @return {@link CBORValue}
     */
    public CBORValue cbor() {
        return cborKey;
    }

}
