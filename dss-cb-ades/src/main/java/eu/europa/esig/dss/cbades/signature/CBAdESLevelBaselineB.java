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
package eu.europa.esig.dss.cbades.signature;

import co.nstant.in.cbor.CborException;
import eu.europa.esig.dss.cbades.CBAdESUtils;
import eu.europa.esig.dss.cbades.COSEHeaderParameter;
import eu.europa.esig.dss.cbades.COSEProtectedHeader;
import eu.europa.esig.dss.cbades.COSEUnprotectedHeader;
import eu.europa.esig.dss.cbades.cbor.CBORArray;
import eu.europa.esig.dss.cbades.cbor.CBORByteString;
import eu.europa.esig.dss.cbades.cbor.CBORMap;
import eu.europa.esig.dss.cbades.cbor.CBORObject;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.cbades.cwt.CWTClaims;
import eu.europa.esig.dss.enumerations.CommitmentType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SigDMechanism;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.CommitmentQualifier;
import eu.europa.esig.dss.model.CommonCommitmentType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Policy;
import eu.europa.esig.dss.model.SignerLocation;
import eu.europa.esig.dss.model.SpDocSpecification;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.model.UserNotice;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.x509.BaselineBCertificateSelector;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * The class builds a COSE header according to TS 119-152
 *
 */
public class CBAdESLevelBaselineB {

    private static final Logger LOG = LoggerFactory.getLogger(CBAdESLevelBaselineB.class);

    /** The CertificateVerifier to use */
    private final CertificateVerifier certificateVerifier;

    /** The signature parameters */
    private final CBAdESSignatureParameters parameters;

    /** List of documents to sign */
    private List<DSSDocument> documentsToSign;

    /** COSE Protected Header map representation */
    private COSEProtectedHeader signedProperties = new COSEProtectedHeader();

    /** COSE Unprotected Header map representation */
    private COSEUnprotectedHeader unsignedProperties = new COSEUnprotectedHeader();

    /**
     * The default constructor
     *
     * @param certificateVerifier {@link CertificateVerifier}
     * @param parameters {@link CBAdESSignatureParameters}
     * @param documentsToSign a list of {@link DSSDocument}s to sign
     */
    public CBAdESLevelBaselineB(final CertificateVerifier certificateVerifier, final CBAdESSignatureParameters parameters,
                                final List<DSSDocument> documentsToSign) {
        this(certificateVerifier, parameters);
        if (Utils.isCollectionEmpty(documentsToSign)) {
            throw new IllegalArgumentException("Documents to sign must be provided!");
        }
        this.documentsToSign = documentsToSign;
    }

    /**
     * The constructor without original document (used for counter signing)
     *
     * @param certificateVerifier {@link CertificateVerifier}
     * @param parameters {@link CBAdESSignatureParameters}
     */
    protected CBAdESLevelBaselineB(final CertificateVerifier certificateVerifier, final CBAdESSignatureParameters parameters) {
        Objects.requireNonNull(certificateVerifier, "certificateVerifier must not be null!");
        Objects.requireNonNull(parameters, "signatureParameters must be defined!");
        this.certificateVerifier = certificateVerifier;
        this.parameters = parameters;
    }

    /**
     * Returns a map representing the signed header of a signature
     *
     * @return a map representing the signed header
     */
    public COSEProtectedHeader getSignedProperties() {
        // RFC 9052 headers
        incorporateSignatureAlgorithm();
        incorporateContentType();
        incorporateKeyIdentifier();

        // RFC 9360 headers
        incorporateSigningCertificateUri();
        incorporateSigningCertificate();
        incorporateCertificateChain();

        // RFC 9596 headers
        incorporateSignatureType();

        // TS 119-152 headers
        incorporateSigningTime();
        incorporateX509CertificateDigests();
        incorporateSignerCommitments();
        incorporateSignatureProductionPlace();
        incorporateSignerAttributes();
        incorporateContentTimestamps();
        incorporateSignaturePolicy();
        incorporateDetachedContents();

        // must be executed the last
        incorporateCritical();

        return signedProperties;
    }

    /**
     * Returns a map representing the unsigned header of a signature
     *
     * @return a map representing the unsigned header
     */
    public COSEUnprotectedHeader getUnsignedProperties() {
        // RFC 9360 headers
        incorporateUnsignedCertificateChain();

        return unsignedProperties;
    }

    /**
     * Incorporates 5.1.2 The alg header parameter
     */
    protected void incorporateSignatureAlgorithm() {
        Long coseId = parameters.getSignatureAlgorithm().getCOSEId();
        if (coseId != null) {
            addHeader(COSEHeaderParameter.ALG.cbor(), coseId); // int/tstr
        } else {
            throw new UnsupportedOperationException(String.format("The defined signature algorithm '%s' is not supported!",
                    parameters.getSignatureAlgorithm()));
        }
    }

    /**
     * Incorporates 5.1.3 The content type (content type) header parameter
     */
    protected void incorporateContentType() {
        if (SignaturePackaging.DETACHED.equals(parameters.getSignaturePackaging())) {
            // not applicable for detached signatures (see TS 119-152 ch.5.1.3)
            return;
        }
        MimeType mimeType = documentsToSign.get(0).getMimeType();
        if (mimeType != null) {
            // TODO : add support of "Integers from the "CoAP Content-Formats" IANA registry table [COAP.Formats]."
            // TODO : currently only the text values format is supported
            String mimeTypeString = mimeType.getMimeTypeString();
            addHeader(COSEHeaderParameter.CONTENT_TYPE.cbor(), mimeTypeString); // tstr/uint
        }
    }

    /**
     * Incorporates 5.1.4 The kid (key identifier) header parameter
     */
    protected void incorporateKeyIdentifier() {
        if (parameters.isIncludeKeyIdentifier()) {
            byte[] kid = parameters.getKeyIdentifier();
            if (kid == null && parameters.getSigningCertificate() != null) {
                kid = DSSUtils.generateKid(parameters.getSigningCertificate());
            }
            if (kid != null) {
                addHeader(COSEHeaderParameter.KID.cbor(), kid); // bstr
            }
        }
    }

    /**
     * Incorporates 5.1.5 The x5u (X.509 URL) header parameter (RFC 9360)
     */
    protected void incorporateSigningCertificateUri() {
        String x509Url = parameters.getX509Url();
        if (Utils.isStringNotEmpty(x509Url)) {
            addHeader(COSEHeaderParameter.X5U.cbor(), x509Url);
        }
    }

    /**
     * Incorporates 5.1.7 The x5t CBOR array or 5.2.3 The x5ts (X509 certificates Thumbprints) CBOR Array
     */
    protected void incorporateSigningCertificate() {
        CertificateToken signingCertificate = parameters.getSigningCertificate();
        if (signingCertificate == null) {
            return;
        }

        DigestAlgorithm digestAlgorithm = parameters.getSigningCertificateDigestMethod();
        if (parameters.isIncludeCertificateChainThumbprints()) {
            List<CertificateToken> certificateTokens = getBaselineBCertificates();
            if (Utils.isCollectionNotEmpty(certificateTokens)) {
                CBORArray x5ts = new CBORArray(certificateTokens.size());
                for (CertificateToken certificateToken : certificateTokens) {
                    x5ts.add(getCoseCertHash(certificateToken, digestAlgorithm));
                }
                addHeader(COSEHeaderParameter.X5TS.cbor(), x5ts); // [+x5t : COSE_CertHash]
            } else {
                LOG.debug("No certificate chain found to be incorporated within 'x5ts' signed header");
            }

        } else {
            // incorporate 'x5t'
            CBORArray x5t = getCoseCertHash(signingCertificate, digestAlgorithm);
            addHeader(COSEHeaderParameter.X5T.cbor(), x5t); // [ hashAlg: (int / tstr), hashValue: bstr ]
        }
    }

    private List<CertificateToken> getBaselineBCertificates() {
        BaselineBCertificateSelector certificateSelector = new BaselineBCertificateSelector(
                parameters.getSigningCertificate(), parameters.getCertificateChain())
                .setTrustAnchorBPPolicy(parameters.bLevel().isTrustAnchorBPPolicy())
                .setTrustedCertificateSource(certificateVerifier.getTrustedCertSources());
        return certificateSelector.getCertificates();
    }

    private CBORArray getCoseCertHash(CertificateToken certificateToken, DigestAlgorithm digestAlgorithm) {
        byte[] digestValue = certificateToken.getDigest(digestAlgorithm);

        CBORArray coseCertHash = new CBORArray();
        coseCertHash.add(digestAlgorithm.getCoseId());
        coseCertHash.add(digestValue);
        return coseCertHash;
    }

    /**
     * Incorporates 5.1.8 The x5chain CBOR array member
     */
    protected void incorporateCertificateChain() {
        if (!parameters.isIncludeCertificateChain() || parameters.getSigningCertificate() == null || !isCertificateChainSigned()) {
            return;
        }

        CBORObject x5Chain = getX5Chain();
        if (x5Chain != null) {
            addHeader(COSEHeaderParameter.X5CHAIN.cbor(), x5Chain);
        }
    }

    private CBORObject getX5Chain() {
        List<CertificateToken> certificates = getBaselineBCertificates();
        if (Utils.collectionSize(certificates) == 0) {
            LOG.debug("No certificate chain found to be incorporated within 'x5chain' header");
            return null;

        } else if (Utils.collectionSize(certificates) == 1) {
            return new CBORByteString(certificates.get(0).getEncoded()); // bstr

        } else {
            CBORArray certificateByteStrings = new CBORArray();
            for (CertificateToken certificateToken : certificates) {
                certificateByteStrings.add(certificateToken.getEncoded());
            }
            return certificateByteStrings; // [ 2*certs: bstr ]
        }
    }

    /**
     * Incorporates 5.1.8 The x5chain CBOR array member as an unsigned property
     */
    protected void incorporateUnsignedCertificateChain() {
        if (!parameters.isIncludeCertificateChain() || parameters.getSigningCertificate() == null || isCertificateChainSigned()) {
            return;
        }

        CBORObject x5Chain = getX5Chain();
        if (x5Chain != null) {
            switch (parameters.getX5ChainHeaderPlacement()) {
                case unprotectedHeader:
                    addUnsignedHeader(COSEHeaderParameter.X5CHAIN.cbor(), x5Chain);
                    break;
                case uHeaders:
                    CBORArray uHeaders = new CBORArray();
                    CBORMap x5ChainEntry = new CBORMap();
                    x5ChainEntry.put(COSEHeaderParameter.X5CHAIN.cbor(), x5Chain);
                    uHeaders.add(CBORUtils.toCborBtsrWrapped(x5ChainEntry));
                    addUnsignedHeader(COSEHeaderParameter.U_HEADERS.cbor(), uHeaders);
                    break;
                default:
                    throw new UnsupportedOperationException(String.format(
                            "The 'x5chain' placement '%s' is not supported for the unsigned certificate chain!",
                            parameters.getX5ChainHeaderPlacement()));
            }
        }
    }

    private boolean isCertificateChainSigned() {
        // Signed is default behavior (when NULL)
        return parameters.getX5ChainHeaderPlacement() == null ||
                CBAdESSignatureParameters.X5ChainHeaderPlacement.protectedHeader == parameters.getX5ChainHeaderPlacement();
    }

    /**
     * Incorporates RFC 9596: CBOR Object Signing and Encryption (COSE) "typ" (type) Header Parameter
     */
    protected void incorporateSignatureType() {
        if (parameters.getSignatureType() == null) {
            return;
        }
        addHeader(COSEHeaderParameter.SIGNATURE_TYPE.cbor(), parameters.getSignatureType()); // tstr/uint
    }

    /**
     * Incorporates 5.1.9 iat (issued at) header parameter
     */
    protected void incorporateSigningTime() {
        final Date signingDate = parameters.bLevel().getSigningDate();
        long signedTimeInSeconds = DSSUtils.getTimeValueInSeconds(signingDate.getTime());

        CBORMap cwtClaims = new CBORMap();
        cwtClaims.put(CWTClaims.IAT.cbor(), signedTimeInSeconds); // NumericDate

        addHeader(COSEHeaderParameter.CWT_CLAIMS.cbor(), cwtClaims);
    }

    /**
     * Incorporates RFC 9052 The crit header parameter (3.1. Common COSE Header Parameters)
     */
    protected void incorporateCritical() {
        CBORArray criticalHeaderNames = new CBORArray();
        for (CBORObject headerKey : signedProperties.getKeys()) {
            if (CBORUtils.isRequiredCriticalHeader(headerKey)) {
                criticalHeaderNames.add(headerKey);
            }
        }
        if (!criticalHeaderNames.isEmpty()) {
            addHeader(COSEHeaderParameter.CRIT.cbor(), criticalHeaderNames);
        }
    }

    /**
     * Incorporates 5.2.2 The x5ts (X509 certificates Thumbprints) header parameter
     */
    protected void incorporateX509CertificateDigests() {
        // addition of multiple signing certificate references are not supported in DSS
    }

    /**
     * Incorporates 5.2.3 The srCms (signer commitments) header parameter
     */
    protected void incorporateSignerCommitments() {
        if (Utils.isCollectionEmpty(parameters.bLevel().getCommitmentTypeIndications())) {
            return;
        }

        // srCms = [+SrCm]
        // SrCm = {
        //     1 => oId,	;commId the commitment identifier: an oId data type
        //     ?2 => [+any]	;commQuals: qualifiers
        // }

        CBORArray srCms = new CBORArray();

        for (CommitmentType commitmentType : parameters.bLevel().getCommitmentTypeIndications()) {
            if (Utils.isStringEmpty(commitmentType.getUri()) && Utils.isStringEmpty(commitmentType.getOid())) {
                throw new IllegalArgumentException(
                        "Either URI or OID shall be defined for CommitmentType signed attribute in CB-AdES!");
            }

            CBORMap srCmParams = new CBORMap();

            CBORMap oid = CBAdESUtils.getOidObject(commitmentType);// Only simple Oid form is supported
            srCmParams.put(COSEHeaderParameter.SR_CM_COMM_ID.cbor(), oid);

            CBORArray commQuals = getCommitmentQualifiers(commitmentType);
            if (!commQuals.isEmpty()) {
                srCmParams.put(COSEHeaderParameter.SR_CM_COMM_QUALS.cbor(), commQuals);
            }

            srCms.add(srCmParams);
        }

        addHeader(COSEHeaderParameter.SR_CMS.cbor(), srCms);
    }

    private CBORArray getCommitmentQualifiers(CommitmentType commitmentType) {
        CBORArray commQuals = new CBORArray();
        if (commitmentType instanceof CommonCommitmentType) {
            CommitmentQualifier[] commitmentQualifiers = ((CommonCommitmentType) commitmentType).getCommitmentTypeQualifiers();
            if (Utils.isArrayNotEmpty(commitmentQualifiers)) {
                for (CommitmentQualifier commitmentQualifier : commitmentQualifiers) {
                    Objects.requireNonNull(commitmentQualifier, "CommitmentTypeQualifier cannot be null!");
                    DSSDocument content = commitmentQualifier.getContent();
                    if (content == null) {
                        throw new IllegalArgumentException("CommitmentTypeQualifier content cannot be null!");
                    }

                    if (CBORUtils.isCbor(content)) {
                        try {
                            CBORObject cborObject = CBORUtils.parseCbor(content);
                            commQuals.add(cborObject);

                        } catch (CborException e) {
                            throw new IllegalArgumentException(String.format(
                                    "Unable to parse CBOR Commitment Type Qualifier : %s", e.getMessage()), e);
                        }

                    } else {
                        LOG.info("None CBOR encoded CommitmentTypeQualifier has been provided. Incorporate as binary.");
                        commQuals.add(DSSUtils.toByteArray(content));
                    }

                }
            }
        }
        return commQuals;
    }

    /**
     * Incorporates 5.2.4 The sigPl (signature production place) header parameter
     */
    protected void incorporateSignatureProductionPlace() {
        SignerLocation signerProductionPlace = parameters.bLevel().getSignerLocation();
        if (signerProductionPlace != null && !signerProductionPlace.isEmpty()) {

            // sigPl = {
            //     ? 1 => tstr,	; addressCountry
            //     ? 2 => tstr,	; addressLocality
            //     ? 3 => tstr,	; addressRegion
            //     ? 4 => tstr,	; postOfficeBoxNumber
            //     ? 5 => tstr,	; postalCode
            //     ? 6 => tstr,	; streetAddress
            // }

            String city = signerProductionPlace.getLocality();
            String streetAddress = signerProductionPlace.getStreetAddress();
            String stateOrProvince = signerProductionPlace.getStateOrProvince();
            String postOfficeBoxNumber = signerProductionPlace.getPostOfficeBoxNumber();
            String postalCode = signerProductionPlace.getPostalCode();
            String country = signerProductionPlace.getCountry();

            CBORMap sigPlaceMap = new CBORMap();

            if (country != null) {
                sigPlaceMap.put(COSEHeaderParameter.SIG_PL_ADDRESS_COUNTRY.cbor(), country);
            }
            if (city != null) {
                sigPlaceMap.put(COSEHeaderParameter.SIG_PL_ADDRESS_LOCALITY.cbor(), city);
            }
            if (stateOrProvince != null) {
                sigPlaceMap.put(COSEHeaderParameter.SIG_PL_ADDRESS_REGION.cbor(), stateOrProvince);
            }
            if (postOfficeBoxNumber != null) {
                sigPlaceMap.put(COSEHeaderParameter.SIG_PL_POST_OFFICE_BOX_NUMBER.cbor(), postOfficeBoxNumber);
            }
            if (postalCode != null) {
                sigPlaceMap.put(COSEHeaderParameter.SIG_PL_POSTAL_CODE.cbor(), postalCode);
            }
            if (streetAddress != null) {
                sigPlaceMap.put(COSEHeaderParameter.SIG_PL_STREET_ADDRESS.cbor(), streetAddress);
            }

            addHeader(COSEHeaderParameter.SIG_PL.cbor(), sigPlaceMap);
        }
    }

    /**
     * Incorporates 5.2.5 The srAts (signer attributes) header parameter
     */
    protected void incorporateSignerAttributes() {
        CBORMap srAtsParams = new CBORMap();

        // TODO : certified are not supported
        // srAtsParams.put(COSEConstraints.CERTIFIED, certifiedList);

        List<String> signedAssertions = parameters.bLevel().getSignedAssertions();
        if (Utils.isCollectionNotEmpty(signedAssertions)) {
            srAtsParams.put(COSEHeaderParameter.SR_ATS_SIGNED_ASSERTIONS.cbor(), getAttrArrays(signedAssertions));
        }

        List<String> claimedSignerRoles = parameters.bLevel().getClaimedSignerRoles();
        if (Utils.isCollectionNotEmpty(claimedSignerRoles)) {
            srAtsParams.put(COSEHeaderParameter.SR_ATS_CLAIMED.cbor(), getAttrArrays(claimedSignerRoles));
        }

        if (!srAtsParams.isEmpty()) {
            addHeader(COSEHeaderParameter.SR_ATS.cbor(), srAtsParams);
        }
    }

    private CBORArray getAttrArrays(List<String> values) {
        final CBORArray attrArrays = new CBORArray();

        CBORArray notCertifiedItem = new CBORArray();
        notCertifiedItem.add(MimeTypeEnum.TEXT.getMimeTypeString()); // mediaType : tstr
        notCertifiedItem.add(CBORUtils.CONTENT_ENCODING_BINARY); // encoding : tsrt

        CBORArray qVals = new CBORArray(values.size());
        for (String value : values) {
            qVals.add(value);
        }
        notCertifiedItem.add(qVals); // qVals : [+any]

        attrArrays.add(notCertifiedItem);
        return attrArrays;
    }

    /**
     * Incorporates 5.2.6 The adoTst (COSE payload time-stamp) header parameter
     */
    protected void incorporateContentTimestamps() {
        if (Utils.isCollectionEmpty(parameters.getContentTimestamps())) {
            return;
        }

        List<TimestampBinary> contentTimestampBinaries = toTimestampBinaries(parameters.getContentTimestamps());
        CBORMap tstContainer = CBAdESUtils.getTstContainer(contentTimestampBinaries);
        addHeader(COSEHeaderParameter.ADO_TST.cbor(), tstContainer);
    }

    private List<TimestampBinary> toTimestampBinaries(List<TimestampToken> timestampTokens) {
        if (Utils.isCollectionEmpty(timestampTokens)) {
            return Collections.emptyList();
        }
        return timestampTokens.stream().map(t -> new TimestampBinary(t.getEncoded())).collect(Collectors.toList());
    }

    /**
     * Incorporates 5.2.7 The sigPId (signature policy identifier) header parameter
     */
    protected void incorporateSignaturePolicy() {
        Policy signaturePolicy = parameters.bLevel().getSignaturePolicy();
        if (signaturePolicy != null && !signaturePolicy.isEmpty()) {
            assertSignaturePolicyValid(signaturePolicy);

            /*
             * sigPId = {
             * 	   1 => oId,					;id: instance of oId type identifying the signature policy
             * 	   2 => DigAlgVal,				;digAlgVal: digest algorithm and value of the signature policy
			 * 				                    ;document
			 *     ? 3 => bool .default false,	;digPSp: indicates whether the digest has been computed according to
			 *                                  ;some spec, default value: false
			 *     ? 4 => [+SigPQual]			;sigPQuals: signature policy qualifiers
			 * }
             */

            CBORMap sigPIdParams = new CBORMap();

            String signaturePolicyId = signaturePolicy.getId();
            CBORMap oid = CBAdESUtils.getOidObject(signaturePolicyId, signaturePolicy.getDescription(), signaturePolicy.getDocumentationReferences());
            sigPIdParams.put(COSEHeaderParameter.SIG_P_ID_ID.cbor(), oid);

            if (signaturePolicy.getDigestAlgorithm() != null && signaturePolicy.getDigestValue() != null) {
                CBORArray digAlgValue = new CBORArray();
                digAlgValue.add(signaturePolicy.getDigestAlgorithm().getCoseId());
                digAlgValue.add(signaturePolicy.getDigestValue());
                sigPIdParams.put(COSEHeaderParameter.SIG_P_ID_DIG_ALG_VAL.cbor(), digAlgValue); // DigAlgVal = [ hashAlg: (int / tstr), hashValue: bstr ]
            }

            if (signaturePolicy.isHashAsInTechnicalSpecification()) {
                sigPIdParams.put(COSEHeaderParameter.SIG_P_ID_DIG_P_SP.cbor(), signaturePolicy.isHashAsInTechnicalSpecification());
            }

            if (signaturePolicy.isSPQualifierPresent()) {
                CBORArray signaturePolicyQualifiers = getSignaturePolicyQualifiers(signaturePolicy);
                sigPIdParams.put(COSEHeaderParameter.SIG_P_ID_SIG_P_QUALS.cbor(), signaturePolicyQualifiers);
            }

            addHeader(COSEHeaderParameter.SIG_PID.cbor(), sigPIdParams);
        }
    }

    private void assertSignaturePolicyValid(Policy signaturePolicy) {
        if (Utils.isStringEmpty(signaturePolicy.getId())) {
            // see TS 119-152 ch. 5.2.8.1 Semantics and syntax ('id' is required)
            throw new IllegalArgumentException("Implicit policy is not allowed in CB-AdES! The signaturePolicyId attribute is required!");
        }
        if (signaturePolicy.isHashAsInTechnicalSpecification() &&
                (signaturePolicy.getSpDocSpecification() == null || Utils.isStringEmpty(signaturePolicy.getSpDocSpecification().getId()))) {
            throw new IllegalArgumentException("SpDocSpecification shall be defined when DigestAsInTechnicalSpecification is set to true!");
        }
    }

    private CBORArray getSignaturePolicyQualifiers(Policy signaturePolicy) {
        /*
         * SigPQual = {
         *     spUri_l => #6.32 //				;spURI: URL where a copy of the signature policy document can be
         *  									;obtained
         * 	   spUserNotice_l => SpUserNotice// ;spUserNotice: Info displayed when signature is validated
         * 	   spDSpec_l => SpDesc //			;spDSpec: identifier of the technical specification that defines
         * 								     	;the syntax used for producing the signature policy document
         * 	   label => any					    ;otherQuals: extension point for qualifiers not specified here
         * }
         */
        CBORArray sigPQualifiers = new CBORArray();

        final String spuri = signaturePolicy.getSpuri();
        if (Utils.isStringNotEmpty(spuri)) {
            sigPQualifiers.add(getQualifier(COSEHeaderParameter.SIG_P_QUAL_SP_URI.cbor(), spuri));
        }

        final UserNotice userNotice = signaturePolicy.getUserNotice();
        if (userNotice != null && !userNotice.isEmpty()) {
            /*
             * SpUserNotice = {
             * 	   ? 1 => NoticeRef,	; noticeRef: User notice and references
             *     ? 2 => tstr	        ;explText: notice text to be displayed
             * }
             *
             * NoticeRef = [
             *     1 => tstr,	;org: the name of the organization
             * 	   2 : [+uint]	;notNumbres: the notice numbers identifying textual statements
             * ]
             */
            CBORMap spUserNotice = new CBORMap();

            final String organization = userNotice.getOrganization();
            final int[] noticeNumbers = userNotice.getNoticeNumbers();
            if (Utils.isStringNotEmpty(organization) && noticeNumbers != null && noticeNumbers.length > 0) {
                CBORMap noticeRef = new CBORMap();
                noticeRef.put(COSEHeaderParameter.NOTICE_REF_ORG.cbor(), organization);
                noticeRef.put(COSEHeaderParameter.NOTICE_REF_NOTICE_NUMBERS.cbor(), getNoticeNumbersArray(noticeNumbers));
                spUserNotice.put(COSEHeaderParameter.SP_USER_NOTICE_NOTICE_REF.cbor(), noticeRef);
            }

            final String explicitText = userNotice.getExplicitText();
            if (Utils.isStringNotEmpty(explicitText)) {
                spUserNotice.put(COSEHeaderParameter.SP_USER_NOTICE_EXPL_TEXT.cbor(), explicitText);
            }

            sigPQualifiers.add(getQualifier(COSEHeaderParameter.SIG_P_QUAL_SP_USER_NOTICE.cbor(), spUserNotice));
        }

        final SpDocSpecification spDocSpecification = signaturePolicy.getSpDocSpecification();
        if (spDocSpecification != null && Utils.isStringNotEmpty(spDocSpecification.getId())) {
            CBORMap oidObject = CBAdESUtils.getOidObject(spDocSpecification.getId(),
                    spDocSpecification.getDescription(), spDocSpecification.getDocumentationReferences());
            sigPQualifiers.add(getQualifier(COSEHeaderParameter.SIG_P_QUAL_SP_D_SPEC.cbor(), oidObject));
        }

        return sigPQualifiers;
    }

    private CBORMap getQualifier(CBORObject qualifierId, Object value) {
        CBORMap qualifier = new CBORMap();
        qualifier.put(qualifierId, value);
        return qualifier;
    }

    private CBORArray getNoticeNumbersArray(int[] noticeNumbers) {
        CBORArray cborArray = new CBORArray(noticeNumbers.length);
        for (int number : noticeNumbers) {
            cborArray.add((long) number);
        }
        return cborArray;
    }

    /**
     * Incorporates 5.2.9 The sigD header parameter
     */
    protected void incorporateDetachedContents() {
        if (SignaturePackaging.DETACHED.equals(parameters.getSignaturePackaging())) {
            assertDetachedContentValid();

            /*
             * sigD : {
             * 	   1 => #6.32(tstr),	;mId: URI identifying the mechanism used for referencing and processing each
             * 		    				;referenced data object
             * 	   2 => [+tstr],	    ;pars: References to data objects as per the mechanism identified by mId
             * 	   ? 3 => int	;hashM: Digest algorithm identifier
             * 	   ? 4 => [+bstr],	    ;hashV: Digest values of referenced data objects as per algorithm identified by
             * 	   			         	;hashM
             * 	   ? 5 => [+tstr]	    ;ctys: Indication of the content type of each referenced object
             * }
             */

            CBORMap sigDParams;
            switch (parameters.getSigDMechanism()) {
                case OBJECT_ID_BY_URI:
                    // 5.2.9.2.2 Mechanism ObjectIdByURI
                    sigDParams = getSigDForObjectIdByUriMechanism(documentsToSign);
                    break;
                case OBJECT_ID_BY_URI_HASH:
                    // 5.2.9.2.3 Mechanism ObjectIdByURIHash
                    sigDParams = getSigDForObjectIdByUriHashMechanism(documentsToSign);
                    break;
                case NO_SIG_D:
                    // do not incorporate the SigD
                    return;
                default:
                    throw new DSSException(String.format("The 'sigD' mechanism '%s' is not supported for CB-AdES!", parameters.getSigDMechanism()));
            }
            addHeader(COSEHeaderParameter.SIG_D.cbor(), sigDParams);
        }
    }

    private void assertDetachedContentValid() {
        SigDMechanism sigDMechanism = parameters.getSigDMechanism();
        if (sigDMechanism == null) {
            throw new IllegalArgumentException("The SigDMechanism is not defined for a detached signature! "
                    + "Please use CBAdESSignatureParameters.setSigDMechanism(sigDMechanism) method.");
        }
        if (SigDMechanism.NO_SIG_D == sigDMechanism) {
            if (Utils.collectionSize(documentsToSign) > 1) {
                throw new IllegalArgumentException(String.format(
                        "Only one detached document is allowed with '%s' mechanism!", SigDMechanism.NO_SIG_D.name()));
            }

        } else if (SigDMechanism.OBJECT_ID_BY_URI == sigDMechanism || SigDMechanism.OBJECT_ID_BY_URI_HASH == sigDMechanism) {
            List<String> documentNames = new ArrayList<>();
            for (DSSDocument document : documentsToSign) {
                if (Utils.isStringEmpty(document.getName())) {
                    throw new IllegalArgumentException("The signed document must have names for a detached CB-AdES signature!");
                }
                if (documentNames.contains(document.getName())) {
                    throw new IllegalArgumentException(String.format("The documents to be signed shall have different names! "
                            + "The name '%s' appears multiple times.", document.getName()));
                }
                documentNames.add(document.getName());
            }
        }
    }

    private CBORMap getSigDForObjectIdByUriMechanism(List<DSSDocument> detachedContents) {
        CBORMap sigDParams = new CBORMap();
        sigDParams.put(COSEHeaderParameter.SIG_D_MID.cbor(), SigDMechanism.OBJECT_ID_BY_URI.getCBAdESUri());
        sigDParams.put(COSEHeaderParameter.SIG_D_PARS.cbor(), getSignedDataReferences(detachedContents));
        sigDParams.put(COSEHeaderParameter.SIG_D_CTYS.cbor(), getSignedDataMimeTypesIfPresent(detachedContents));
        return sigDParams;
    }

    private CBORMap getSigDForObjectIdByUriHashMechanism(List<DSSDocument> detachedContents) {
        CBORMap sigDParams = new CBORMap();

        sigDParams.put(COSEHeaderParameter.SIG_D_MID.cbor(), SigDMechanism.OBJECT_ID_BY_URI_HASH.getCBAdESUri());
        sigDParams.put(COSEHeaderParameter.SIG_D_PARS.cbor(), getSignedDataReferences(detachedContents));

        DigestAlgorithm digestAlgorithm = getReferenceDigestAlgorithmOrDefault();
        sigDParams.put(COSEHeaderParameter.SIG_D_HASH_M.cbor(), digestAlgorithm.getCoseId());
        sigDParams.put(COSEHeaderParameter.SIG_D_HASH_V.cbor(), getSignedDataDigests(detachedContents, digestAlgorithm));

        sigDParams.put(COSEHeaderParameter.SIG_D_CTYS.cbor(), getSignedDataMimeTypesIfPresent(detachedContents));

        return sigDParams;
    }

    private CBORArray getSignedDataReferences(List<DSSDocument> detachedContents) {
        CBORArray cborArray = new CBORArray(detachedContents.size());
        detachedContents.forEach(d -> cborArray.add(d.getName()));
        return cborArray;
    }

    /**
     * Returns a 'ctys' array for given documents
     *
     * @param detachedContents a list of {@link DSSDocument} to be signed
     * @return {@link CBORArray} 'ctys' object
     */
    private CBORArray getSignedDataMimeTypesIfPresent(List<DSSDocument> detachedContents) {
        CBORArray mimeTypes = new CBORArray();
        for (DSSDocument document : detachedContents) {
            MimeType mimeType = document.getMimeType();
            if (mimeType == null) {
                mimeType = MimeTypeEnum.BINARY;
            }
            String mimeTypeString = mimeType.getMimeTypeString();
            mimeTypes.add(mimeTypeString);  // tstr/uint
        }
        return mimeTypes;
    }

    private DigestAlgorithm getReferenceDigestAlgorithmOrDefault() {
        return parameters.getReferenceDigestAlgorithm() != null ? parameters.getReferenceDigestAlgorithm() : parameters.getDigestAlgorithm();
    }

    private CBORArray getSignedDataDigests(List<DSSDocument> detachedContents, DigestAlgorithm digestAlgorithm) {
        CBORArray digests = new CBORArray(detachedContents.size());
        detachedContents.forEach(d -> digests.add(d.getDigestValue(digestAlgorithm)));
        return digests;
    }

    /**
     * Adds a new header to the {@code signedProperties} map
     *
     * @param headerLabel unique identifier of the header
     * @param value {@link Object} to add
     */
    protected void addHeader(CBORObject headerLabel, Object value) {
        signedProperties.put(headerLabel, value);
    }

    /**
     * Adds a new header to the {@code unsignedProperties} map
     *
     * @param headerLabel unique identifier of the header
     * @param value {@link Object} to add
     */
    protected void addUnsignedHeader(CBORObject headerLabel, Object value) {
        unsignedProperties.put(headerLabel, value);
    }

    /**
     * Returns COSE payload for the given signature parameters
     *
     * @return payload byte array
     */
    public byte[] getPayloadBytes() {
        if (SignaturePackaging.DETACHED.equals(parameters.getSignaturePackaging())) {
            assertDetachedContentValid();
        }
        if (!SignaturePackaging.DETACHED.equals(parameters.getSignaturePackaging()) ||
                SigDMechanism.NO_SIG_D.equals(parameters.getSigDMechanism())) {
            return DSSUtils.toByteArray(documentsToSign.get(0));

        } else if (SigDMechanism.OBJECT_ID_BY_URI.equals(parameters.getSigDMechanism())) {
            return CBAdESUtils.concatenateDSSDocuments(documentsToSign);

        } else if (SigDMechanism.OBJECT_ID_BY_URI_HASH.equals(parameters.getSigDMechanism())) {
            /*
             * 5.2.9.2.3 Mechanism ObjectIdByURIHash
             *
             * When using this mechanism, the COSE Payload shall contribute as an empty stream to the computation of the JWS Signature Value.
             */
            return DSSUtils.EMPTY_BYTE_ARRAY;
        }
        throw new IllegalArgumentException("The configured signature format is not supported!");
    }

}
