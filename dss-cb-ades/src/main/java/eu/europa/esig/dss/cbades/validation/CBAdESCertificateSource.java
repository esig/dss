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
package eu.europa.esig.dss.cbades.validation;

import eu.europa.ec.digit.cddl4j.cbor.CBORValue;
import eu.europa.esig.dss.cbades.CBAdESUtils;
import eu.europa.esig.dss.cbades.COSEHeaderParameter;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.SignatureCertificateSource;
import eu.europa.esig.dss.spi.x509.CandidatesForSigningCertificate;
import eu.europa.esig.dss.spi.x509.CertificateRef;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CertificateValidity;
import eu.europa.esig.dss.spi.x509.KidCertificateSource;
import eu.europa.esig.dss.spi.x509.X509URLCertificateSource;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Extracts and stores certificates from a CB-AdES signature
 *
 */
public class CBAdESCertificateSource extends SignatureCertificateSource {

    private static final long serialVersionUID = -8170607661341382049L;

    private static final Logger LOG = LoggerFactory.getLogger(CBAdESCertificateSource.class);

    /** The COSE Signature to extract certificates from */
    private final transient CBORSignature cose;

    /** Represents the unsigned 'uHeaders' header */
    private final transient CBAdESUHeaders uHeaders;

    /** Map of 'kid' certificates, when present */
    private final Map<String, CertificateToken> kidMap = new HashMap<>();

    /** Map of 'x5u' certificates, when present */
    private final Map<String, Collection<CertificateToken>> x509UrlMap = new HashMap<>();

    /**
     * Default constructor
     *
     * @param cose {@link CBORSignature} signature to extract certificate values from
     * @param uHeaders {@link CBAdESUHeaders} containing the unsigned properties of the signature
     */
    public CBAdESCertificateSource(final CBORSignature cose, final CBAdESUHeaders uHeaders) {
        Objects.requireNonNull(cose, "CBOR signature cannot be null");

        this.cose = cose;
        this.uHeaders = uHeaders;

        // signing certificate
        extractProtectedHeaderX5T();
        extractX5Ts();
        extractKid();
        extractProtectedHeaderX509Url();

        // certificate chain
        extractProtectedHeaderX5Bag();
        extractProtectedHeaderX5Chain();

        // unprotected headers
        extractUnprotectedHeaderX5T();
        extractUnprotectedHeaderX509Url();

        extractUnprotectedHeaderX5Bag();
        extractUnprotectedHeaderX5Chain();

        extractUHeaders();
    }

    /**
     * Retrieves the list of {@link CertificateRef}s referenced within a 'kid' (key identifier) header
     *
     * @return the list of references to the signing certificate (from key identifier)
     */
    public List<CertificateRef> getKeyIdentifierCertificateRefs() {
        return getCertificateRefsByOrigin(CertificateRefOrigin.KEY_IDENTIFIER);
    }

    /**
     * Retrieves the Set of {@link CertificateToken}s according to a reference present
     * within a 'kid' (key identifier) header
     *
     * @return Set of {@link CertificateToken}s
     */
    public Set<CertificateToken> getKeyIdentifierCertificates() {
        return findTokensFromRefs(getKeyIdentifierCertificateRefs());
    }

    private void extractProtectedHeaderX5T() {
        /*
         * x5t: This header parameter identifies the end-entity X.509
         * certificate by a hash value (a thumbprint). The 'x5t' header
         * parameter is represented as an array of two elements.  The first
         * element is an algorithm identifier that is an integer or a string
         * containing the hash algorithm identifier corresponding to the
         * Value column (integer or text string) of the algorithm registered
         * in the "COSE Algorithms" registry (see
         * <https://www.iana.org/assignments/cose/>). The second element is
         * a binary string containing the hash value computed over the DER-
         * encoded certificate.
         */
        CBORValue x5t = cose.getProtectedHeaderValueAsArray(COSEHeaderParameter.X5T.cbor());
        extractX5T(x5t, CertificateRefOrigin.SIGNING_CERTIFICATE);
    }

    private void extractUnprotectedHeaderX5T() {
        CBORValue x5t = cose.getUnprotectedHeaderValueAsArray(COSEHeaderParameter.X5T.cbor());
        extractX5T(x5t, CertificateRefOrigin.UNPROTECTED_HEADER_REFS);
    }

    private void extractX5T(CBORValue x5t, CertificateRefOrigin certificateRefOrigin) {
        Digest digest = CBAdESUtils.extractX5TDigest(x5t);
        if (digest != null) {
            CertificateRef certRef = new CertificateRef();
            certRef.setCertDigest(digest);
            addCertificateRef(certRef, certificateRefOrigin);
        }
    }

    private void extractProtectedHeaderX509Url() {
        CBORValue x5u = cose.getProtectedHeaderValue(COSEHeaderParameter.X5U.cbor());
        String uri = CBORUtils.fromUri(x5u);
        extractX509Url(uri, CertificateRefOrigin.X509_URL);
    }

    private void extractUnprotectedHeaderX509Url() {
        CBORValue x5u = cose.getUnprotectedHeaderValue(COSEHeaderParameter.X5U.cbor());
        String uri = CBORUtils.fromUri(x5u);
        extractX509Url(uri, CertificateRefOrigin.UNPROTECTED_HEADER_REFS);
    }

    private void extractX509Url(String x5u, CertificateRefOrigin certificateRefOrigin) {
        /*
         * x5u: This header parameter provides the ability to identify an X.509
         * certificate by a URI [RFC3986]. It contains a CBOR text string.
         */
        if (Utils.isStringNotEmpty(x5u)) {
            CertificateRef certificateRef = new CertificateRef();
            certificateRef.setX509Url(x5u);
            addCertificateRef(certificateRef, certificateRefOrigin);
        }
    }

    private void extractProtectedHeaderX5Bag() {
        CBORValue x5bag = cose.getProtectedHeaderValue(COSEHeaderParameter.X5BAG.cbor());
        extractX5Bag(x5bag, CertificateOrigin.KEY_INFO);
    }

    private void extractUnprotectedHeaderX5Bag() {
        CBORValue x5bag = cose.getUnprotectedHeaderValue(COSEHeaderParameter.X5BAG.cbor());
        extractX5Bag(x5bag, CertificateOrigin.UNPROTECTED_HEADER);
    }

    private void extractX5Bag(CBORValue x5bagObject, CertificateOrigin certificateOrigin) {
        if (x5bagObject == null) {
            // skip

        } else if (x5bagObject.isByteString()) {
            CertificateToken certificate = loadCertificate(x5bagObject.asBytes());
            if (certificate != null) {
                addCertificate(certificate, certificateOrigin);
            }

        } else if (x5bagObject.isArray()) {
            for (CBORValue cborValue : x5bagObject.getElements()) {
                if (cborValue.isByteString()) {
                    CertificateToken certificate = loadCertificate(cborValue.asBytes());
                    if (certificate != null) {
                        addCertificate(certificate, certificateOrigin);
                    }
                } else {
                    LOG.warn("The item of 'x5bag' CBOR array shall be a byte string!");
                }
            }
        }
    }

    private void extractProtectedHeaderX5Chain() {
        CBORValue x5chain = cose.getProtectedHeaderValue(COSEHeaderParameter.X5CHAIN.cbor());
        extractX5Chain(x5chain, CertificateOrigin.KEY_INFO);
    }

    private void extractUnprotectedHeaderX5Chain() {
        CBORValue x5chain = cose.getUnprotectedHeaderValue(COSEHeaderParameter.X5CHAIN.cbor());
        extractX5Chain(x5chain, CertificateOrigin.UNPROTECTED_HEADER);
    }

    private void extractX5Chain(CBORValue x5chainObject, CertificateOrigin certificateOrigin) {
        if (x5chainObject == null) {
            // skip

        } else if (x5chainObject.isByteString()) {
            CertificateToken certificate = loadCertificate(x5chainObject.asBytes());
            if (certificate != null) {
                addCertificate(certificate, certificateOrigin);
            }

        } else if (x5chainObject.isArray()) {
            for (CBORValue cborValue : x5chainObject.getElements()) {
                if (cborValue.isByteString()) {
                    CertificateToken certificate = loadCertificate(cborValue.asBytes());
                    if (certificate != null) {
                        addCertificate(certificate, certificateOrigin);
                    }
                } else {
                    LOG.warn("The item of 'x5chain' CBOR array shall be a byte string!");
                }
            }

        } else {
            LOG.warn("The 'x5chain' shall be either of a CBOR Byte String or CBOR Array type! Found type : {}", x5chainObject.getClass().getSimpleName());
        }
    }

    private void extractKid() {
        byte[] kid = getKidValue();
        if (kid != null) {
            CertificateRef certificateRef = new CertificateRef();
            IssuerSerial issuerSerial = CBORUtils.getIssuerSerial(kid);
            if (issuerSerial != null) {
                certificateRef.setCertificateIdentifier(DSSASN1Utils.toSignerIdentifier(issuerSerial));
            } else {
                certificateRef.setKid(Utils.toBase64(kid));
            }
            addCertificateRef(certificateRef, CertificateRefOrigin.KEY_IDENTIFIER);
        }
    }

    private byte[] getKidValue() {
        return cose.getProtectedHeaderValueAsBinaries(COSEHeaderParameter.KID.cbor());
    }

    private void extractX5Ts() {
        CBORValue x5ts = cose.getProtectedHeaderValueAsArray(COSEHeaderParameter.X5TS.cbor());
        if (x5ts != null && x5ts.size() != 0) {
            for (CBORValue item : x5ts.getElements()) {
                if (item.isArray()) {
                    extractX5T(item, CertificateRefOrigin.SIGNING_CERTIFICATE);
                } else {
                    LOG.warn("The entry of 'x5ts' CBOR array shall be a CBOR array!");
                }
            }
        }
    }

    private CertificateToken loadCertificate(byte[] binaries) {
        try {
            return DSSUtils.loadCertificate(binaries);
        } catch (Exception e) {
            LOG.warn("Unable to decode a certificate from binaries! Reason : {}", e.getMessage(), e);
            return null;
        }
    }

    private void extractUHeaders() {
        if (uHeaders == null || !uHeaders.isExist()) {
            return;
        }

        for (CBAdESAttribute attribute : uHeaders.getAttributes()) {
            extractValidationData(attribute);
            extractUHeadersX5Chain(attribute);
            extractCompleteCertificateRefs(attribute);
        }
    }

    private void extractValidationData(CBAdESAttribute attribute) {
        if (COSEHeaderParameter.VAL_DATA.cbor().equals(attribute.getHeaderId())) {
            CBORValue valData = attribute.getValue();
            if (valData.isMap()) {
                CBORValue xVals = valData.getAsArrayOrNull(COSEHeaderParameter.VAL_DATA_X_VALS.cbor());
                if (xVals != null && xVals.size() != 0) {
                    extractCertificateValues(xVals, CertificateOrigin.ANY_VALIDATION_DATA);
                }
            } else {
                LOG.warn("The value of header 'valData' shall be represented by a CBOR Map! Entry is skipped.");
            }
        }
    }

    private void extractUHeadersX5Chain(CBAdESAttribute attribute) {
        if (COSEHeaderParameter.X5CHAIN.cbor().equals(attribute.getHeaderId())) {
            CBORValue x5chainObject = attribute.getValue();
            extractX5Chain(x5chainObject, CertificateOrigin.UNPROTECTED_HEADER);
        }
    }

    private void extractCertificateValues(CBORValue xVals, CertificateOrigin origin) {
        for (CBORValue x509OrOther : xVals.getElements()) {
            if (x509OrOther.isMap()) {
                CBORValue pkiOb = x509OrOther.getAsMapOrNull(COSEHeaderParameter.X509_OR_OTHER_X509_CERT.cbor());
                extractX509Cert(pkiOb, origin);

                CBORValue otherCert = x509OrOther.getAsMapOrNull(COSEHeaderParameter.X509_OR_OTHER_OTHER_CERT.cbor());
                if (otherCert != null) {
                    LOG.warn("The header 'otherCert' is not supported! The entry is skipped.");
                }

            } else {
                LOG.warn("The value of 'x509OrOther' shall be represented by a CBOR Map! Entry is skipped.");
            }
        }
    }

    private void extractX509Cert(CBORValue pkiOb, CertificateOrigin origin) {
        byte[] val = CBAdESUtils.extractDerEncodedPkiObject(pkiOb);
        if (Utils.isArrayNotEmpty(val)) {
            CertificateToken certificateToken = loadCertificate(val);
            addCertificate(certificateToken, origin);
        }
    }

    private void extractCompleteCertificateRefs(CBAdESAttribute attribute) {
        if (COSEHeaderParameter.REFS.cbor().equals(attribute.getHeaderId())) {
            CBORValue refs = attribute.getValue();
            if (refs.isMap()) {
                CBORValue xRefs = refs.getAsArrayOrNull(COSEHeaderParameter.REFS_X_REFS.cbor());
                if (xRefs != null && xRefs.size() != 0) {
                    extractCertificateRefs(xRefs, CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS);
                }
            } else {
                LOG.warn("The value of header 'refs' shall be represented by a CBOR Map! Entry is skipped.");
            }
        }
    }

    private void extractCertificateRefs(CBORValue xRefs, CertificateRefOrigin origin) {
        for (CBORValue certId : xRefs.getElements()) {
            if (certId.isMap()) {
                CertificateRef certificateRef = CBAdESUtils.fromCertId(certId);
                if (certificateRef != null) {
                    addCertificateRef(certificateRef, origin);
                }
            } else {
                LOG.warn("The value of 'CertId' shall be represented by a CBOR Map! Entry is skipped.");
            }
        }
    }

    @Override
    protected CandidatesForSigningCertificate extractCandidatesForSigningCertificate(
            CertificateSource signingCertificateSource) {

        CandidatesForSigningCertificate candidatesForSigningCertificate = initCandidatesList(signingCertificateSource);
        if (!candidatesForSigningCertificate.isEmpty()) {
            return candidatesForSigningCertificate;
        }

        for (final CertificateToken certificateToken : getKeyInfoCertificates()) {
            candidatesForSigningCertificate.add(new CertificateValidity(certificateToken));
        }

        // if x5chain does not contain certificates,
        // check other certificates embedded into the signature
        if (candidatesForSigningCertificate.isEmpty()) {

            // Add all found certificates
            for (final CertificateToken certificateToken : getCertificates()) {
                candidatesForSigningCertificate.add(new CertificateValidity(certificateToken));
            }

        }

        if (signingCertificateSource != null) {
            resolveFromSource(signingCertificateSource, candidatesForSigningCertificate);
        }

        checkSigningCertificateRef(candidatesForSigningCertificate);

        return candidatesForSigningCertificate;
    }

    private void resolveFromSource(CertificateSource signingCertificateSource, CandidatesForSigningCertificate candidatesForSigningCertificate) {
        CertificateToken kidCandidate = resolveByKid(signingCertificateSource);
        if (kidCandidate != null) {
            LOG.debug("Resolved certificate by kid");
            super.addCertificate(kidCandidate);
            candidatesForSigningCertificate.add(new CertificateValidity(kidCandidate));
            return;
        }

        Collection<CertificateToken> uriCandidates = resolveByUri(signingCertificateSource);
        if (Utils.isCollectionNotEmpty(uriCandidates)) {
            LOG.debug("Resolved certificates by x5u");
            for (CertificateToken externalCandidate : uriCandidates) {
                super.addCertificate(externalCandidate);
                candidatesForSigningCertificate.add(new CertificateValidity(externalCandidate));
            }
            return;
        }

        Digest certificateDigest = getSigningCertificateDigest();
        if (certificateDigest != null) {
            Set<CertificateToken> certificatesByDigest = signingCertificateSource.getByCertificateDigest(certificateDigest);
            if (Utils.isCollectionNotEmpty(certificatesByDigest)) {
                LOG.debug("Resolved certificate by digest");
                for (CertificateToken certificateToken : certificatesByDigest) {
                    candidatesForSigningCertificate.add(new CertificateValidity(certificateToken));
                }
            }

        } else {
            List<CertificateToken> certificates = signingCertificateSource.getCertificates();
            LOG.debug("No signing certificate reference found. " +
                    "Resolve all {} certificates from the provided certificate source as signing candidates.", certificates.size());
            for (CertificateToken certCandidate : certificates) {
                candidatesForSigningCertificate.add(new CertificateValidity(certCandidate));
            }
        }
    }

    private CertificateToken resolveByKid(CertificateSource signingCertificateSource) {
        byte[] kid = getKidValue();
        if (kid != null) {
            if (signingCertificateSource instanceof KidCertificateSource) {
                KidCertificateSource kidCertificateSource = (KidCertificateSource) signingCertificateSource;
                CertificateToken certificateByKid = kidCertificateSource.getCertificateByKid(kid);
                if (certificateByKid != null) {
                    kidMap.put(Utils.toBase64(kid), certificateByKid);
                }
                return certificateByKid;
            } else {
                LOG.info("COSE/CB-AdES contains a 'kid' header (provide a KidCertificateSource to resolve it)");
            }
        }
        return null;
    }

    private Collection<CertificateToken> resolveByUri(CertificateSource signingCertificateSource) {
        CBORValue x5uHeader = cose.getProtectedHeaderValue(COSEHeaderParameter.X5U.cbor());
        if (x5uHeader == null) {
            x5uHeader = cose.getUnprotectedHeaderValue(COSEHeaderParameter.X5U.cbor());
        }
        String uri = CBORUtils.fromUri(x5uHeader);
        if (Utils.isStringNotEmpty(uri)) {
            if (signingCertificateSource instanceof X509URLCertificateSource) {
                X509URLCertificateSource x509URLCertificateSource = (X509URLCertificateSource) signingCertificateSource;
                Collection<CertificateToken> certificatesByUri = x509URLCertificateSource.getCertificatesByUrl(uri);
                if (Utils.isCollectionNotEmpty(certificatesByUri)) {
                    x509UrlMap.put(uri, certificatesByUri);
                }
                return certificatesByUri;
            } else {
                LOG.info("COSE/CB-AdES contains a 'x5u' header (provide a X509URLCertificateSource to resolve it)");
            }
        }
        return Collections.emptyList();
    }

    private Digest getSigningCertificateDigest() {
        List<CertificateRef> signingCertificateRefs = getSigningCertificateRefs();
        if (Utils.isCollectionNotEmpty(signingCertificateRefs)) {
            // must contain only one reference
            final CertificateRef signingCert = signingCertificateRefs.get(0);
            return signingCert.getCertDigest();
        }
        return null;
    }

    private void checkSigningCertificateRef(CandidatesForSigningCertificate candidates) {
        CertificateRef signingCertRef = null;
        final List<CertificateRef> potentialSigningCertificates = getSigningCertificateRefs();
        if (Utils.isCollectionNotEmpty(potentialSigningCertificates)) {
            // first reference shall be a reference to a signing certificate
            signingCertRef = potentialSigningCertificates.get(0);
        }

        CertificateRef kidCertRef = null;
        final List<CertificateRef> keyIdentifierCertificateRefs = getKeyIdentifierCertificateRefs();
        if (Utils.isCollectionNotEmpty(keyIdentifierCertificateRefs)) {
            kidCertRef = keyIdentifierCertificateRefs.get(0);
        }

        if (signingCertRef != null) {
            CertificateValidity bestCertificateValidity = null;
            // check all certificates against the signingCert ref and find the best one
            final List<CertificateValidity> certificateValidityList = candidates.getCertificateValidityList();
            for (final CertificateValidity certificateValidity : certificateValidityList) {
                if (isValid(certificateValidity, signingCertRef, kidCertRef)) {
                    bestCertificateValidity = certificateValidity;
                }
            }
            if (bestCertificateValidity != null) {
                candidates.setTheCertificateValidity(bestCertificateValidity);
            }
        }
    }

    private boolean isValid(CertificateValidity certificateValidity,
                            CertificateRef signingCertRef, CertificateRef kidCertRef) {
        certificateValidity.setDigestPresent(signingCertRef != null && signingCertRef.getCertDigest() != null);
        certificateValidity.setIssuerSerialPresent(kidCertRef != null && kidCertRef.getCertificateIdentifier() != null);

        CertificateToken certificateToken = certificateValidity.getCertificateToken();
        if (certificateToken != null) {
            if (signingCertRef != null) {
                certificateValidity.setDigestEqual(certificateMatcher.matchByDigest(certificateToken, signingCertRef));
            }
            if (kidCertRef != null) {
                certificateValidity.setSerialNumberEqual(certificateMatcher.matchBySerialNumber(certificateToken, kidCertRef));
                certificateValidity.setDistinguishedNameEqual(certificateMatcher.matchByIssuerName(certificateToken, kidCertRef));
            }
        }
        return certificateValidity.isValid();
    }

    @Override
    public List<CertificateRef> getReferencesForCertificateToken(CertificateToken certificateToken) {
        final List<CertificateRef> result = super.getReferencesForCertificateToken(certificateToken);
        for (Map.Entry<String, CertificateToken> kidEntry : kidMap.entrySet()) {
            if (kidEntry.getValue().equals(certificateToken)) {
                for (CertificateRef certificateRef : getCertificateRefsByOrigin(CertificateRefOrigin.KEY_IDENTIFIER)) {
                    if (kidEntry.getKey().equals(certificateRef.getKid())) {
                        result.add(certificateRef);
                    }
                }
            }
        }
        for (CertificateRef certificateRef : getCertificateRefsByOrigin(CertificateRefOrigin.UNPROTECTED_HEADER_REFS)) {
            if (doesCertificateReferenceMatch(certificateToken, certificateRef)) {
                result.add(certificateRef);
            }
        }
        for (Map.Entry<String, Collection<CertificateToken>> x5uEntry : x509UrlMap.entrySet()) {
            if (x5uEntry.getValue().contains(certificateToken)) {
                for (CertificateRef certificateRef : getCertificateRefsByOrigin(CertificateRefOrigin.X509_URL)) {
                    if (x5uEntry.getKey().equals(certificateRef.getX509Url())) {
                        result.add(certificateRef);
                    }
                }
                for (CertificateRef certificateRef : getCertificateRefsByOrigin(CertificateRefOrigin.UNPROTECTED_HEADER_REFS)) {
                    if (certificateRef.getX509Url() != null && x5uEntry.getKey().equals(certificateRef.getX509Url())) {
                        result.add(certificateRef);
                    }
                }
            }
        }
        return result;
    }

    @Override
    public Set<CertificateToken> findTokensFromCertRef(CertificateRef certificateRef) {
        final Set<CertificateToken> certificates = super.findTokensFromCertRef(certificateRef);
        if (Utils.isStringNotEmpty(certificateRef.getKid())) {
            CertificateToken certificateTokenByKid = kidMap.get(certificateRef.getKid());
            if (certificateTokenByKid != null) {
                certificates.add(certificateTokenByKid);
            }
        }
        if (Utils.isStringNotEmpty(certificateRef.getX509Url())) {
            Collection<CertificateToken> x509UrlCertificates = x509UrlMap.get(certificateRef.getX509Url());
            if (Utils.isCollectionNotEmpty(x509UrlCertificates)) {
                certificates.addAll(x509UrlCertificates);
            }
        }
        return certificates;
    }

}
