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
package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.identifier.EncapsulatedRevocationTokenIdentifier;
import eu.europa.esig.dss.model.identifier.Identifier;
import eu.europa.esig.dss.model.identifier.IdentifierBasedObject;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.Token;
import eu.europa.esig.dss.model.x509.X500PrincipalHelper;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.tsl.LOTLInfo;
import eu.europa.esig.dss.spi.tsl.PivotInfo;
import eu.europa.esig.dss.spi.tsl.TLInfo;
import eu.europa.esig.dss.spi.x509.CertificateRef;
import eu.europa.esig.dss.spi.x509.revocation.RevocationRef;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLRef;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPRef;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPResponseBinary;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.scope.SignatureScope;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.x500.X500Principal;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * Creates an identifier for a given token by the template:
 *
 * TOKEN-CommonCertName-CreationDate-id(optional)
 *
 * Examples:
 * SIGNATURE-JohnConner-20201015-2045
 * CERTIFICATE-CryptoSign-20151014-1425
 */
public class UserFriendlyIdentifierProvider implements TokenIdentifierProvider {

    private static final Logger LOG = LoggerFactory.getLogger(UserFriendlyIdentifierProvider.class);

    /** String is used to separate different parts of the identifier */
    private static final String STRING_DELIMITER = "_";

    /** String to be used to replace non-alphanumeric characters in a certificate's common name */
    private static final String NAME_REPLACEMENT = "-";

    /** To be used to define an issuer name */
    private static final String ISSUER = "ISSUER-";

    /** To be used to define a serial number */
    private static final String SERIAL = "SERIAL-";

    /** String used when token's signing certificate is not identified */
    private static final String UNKNOWN_SIGNER = "UNKNOWN-SIGNER";

    /** String used when token's signing certificate does not have a human-readable name */
    private static final String UNNAMED_SIGNER = "UNNAMED-SIGNER";

    /**
     * Represents a cached values map for processed tokens between the original DSS hash-based Id
     * and the one computed by the class (including preservation from duplicates)
     */
    private final Map<String, String> uniqueTokenIdsMap = new HashMap<>();

    /**
     * Map between DSS identifiers of processed tokens and the computed ids by the provider.
     * The map can contain duplicates. Used to identify duplicates.
     */
    private final Map<String, String> generatedTokenIdsMap = new HashMap<>();

    /** The prefix to be used for a signature identifier creation */
    private String signaturePrefix = "SIGNATURE";

    /** The prefix to be used for a timestamp identifier creation */
    private String timestampPrefix = "TIMESTAMP";

    /** The prefix to be used for a certificate identifier creation */
    private String certificatePrefix = "CERTIFICATE";

    /** The prefix to be used for an CRL identifier creation */
    private String crlPrefix = "CRL";

    /** The prefix to be used for an OCSP identifier creation */
    private String ocspPrefix = "OCSP";

    /** The prefix to be used for an original document identifier creation */
    private String signedDataPrefix = "DOCUMENT";

    /** The prefix to be used for a List of Trusted Lists identifier creation */
    private String lotlPrefix = "LOTL";

    /** The prefix to be used for a Trusted List identifier creation */
    private String tlPrefix = "TL";

    /** The prefix to be used for a pivot identifier creation */
    private String pivotPrefix = "PIVOT";

    /** The date format to be used for a token identifier creation */
    private String dateFormat = "yyyyMMdd-HHmm";

    /**
     * Sets the prefix to be used for signature identifiers
     *
     * Default = "SIGNATURE"
     *
     * @param signaturePrefix {@link String}
     */
    public void setSignaturePrefix(String signaturePrefix) {
        assertNotBlank(signaturePrefix);
        this.signaturePrefix = signaturePrefix;
    }

    /**
     * Sets the prefix to be used for timestamp identifiers
     *
     * Default = "TIMESTAMP"
     *
     * @param timestampPrefix {@link String}
     */
    public void setTimestampPrefix(String timestampPrefix) {
        assertNotBlank(timestampPrefix);
        this.timestampPrefix = timestampPrefix;
    }

    /**
     * Sets the prefix to be used for certificate identifiers
     *
     * Default = "CERTIFICATE"
     *
     * @param certificatePrefix {@link String}
     */
    public void setCertificatePrefix(String certificatePrefix) {
        assertNotBlank(certificatePrefix);
        this.certificatePrefix = certificatePrefix;
    }

    /**
     * Sets the prefix to be used for CRL identifiers
     *
     * Default = "CRL"
     *
     * @param crlPrefix {@link String}
     */
    public void setCrlPrefix(String crlPrefix) {
        assertNotBlank(crlPrefix);
        this.crlPrefix = crlPrefix;
    }

    /**
     * Sets the prefix to be used for OCSP identifiers
     *
     * Default = "OCSP"
     *
     * @param ocspPrefix {@link String}
     */
    public void setOcspPrefix(String ocspPrefix) {
        assertNotBlank(ocspPrefix);
        this.ocspPrefix = ocspPrefix;
    }

    /**
     * Sets the prefix to be used for original document identifiers
     *
     * Default = "DOCUMENT"
     *
     * @param signedDataPrefix {@link String}
     */
    public void setSignedDataPrefix(String signedDataPrefix) {
        assertNotBlank(signedDataPrefix);
        this.signedDataPrefix = signedDataPrefix;
    }

    /**
     * Sets the prefix to be used for a LOTL identifier
     *
     * Default = "LOTL"
     *
     * @param lotlPrefix {@link String}
     */
    public void setLOTLPrefix(String lotlPrefix) {
        this.lotlPrefix = lotlPrefix;
    }

    /**
     * Sets the prefix to be used for TL identifiers
     *
     * Default = "TL"
     *
     * @param tlPrefix {@link String}
     */
    public void setTLPrefix(String tlPrefix) {
        this.tlPrefix = tlPrefix;
    }

    /**
     * Sets the prefix to be used for pivot identifiers
     *
     * Default = "PIVOT"
     *
     * @param pivotPrefix {@link String}
     */
    public void setPivotPrefix(String pivotPrefix) {
        this.pivotPrefix = pivotPrefix;
    }

    /**
     * Sets the dataFormat to be used for identifiers creation
     *
     * Default = "yyyyMMdd-HHmm"
     *
     * @param dateFormat {@link String} the target date format
     */
    public void setDateFormat(String dateFormat) {
        Objects.requireNonNull(dateFormat, "The dataFormat cannot be null!");
        this.dateFormat = dateFormat;
    }

    @Override
    public String getIdAsString(IdentifierBasedObject object) {
        Objects.requireNonNull(object, "The object cannot be null!");

        String cachedIdentifier = getCachedIdentifier(object);
        if (Utils.isStringNotEmpty(cachedIdentifier)) {
            return cachedIdentifier;

        } else if (object instanceof AdvancedSignature) {
            return getIdAsStringForSignature((AdvancedSignature) object);

        } else if (object instanceof Token) {
            return getIdAsStringForToken((Token) object);

        } else if (object instanceof SignatureScope) {
            return getIdAsStringForSignatureScope((SignatureScope) object);

        } else if (object instanceof TLInfo) {
            return getIdAsStringForTL((TLInfo) object);

        } else if (object instanceof CertificateRef) {
            return getIdAsStringForCertRef((CertificateRef) object);

        } else if (object instanceof RevocationRef) {
            return getIdAsStringForRevRef((RevocationRef) object);

        } else if (object instanceof EncapsulatedRevocationTokenIdentifier) {
            return getIdAsStringForRevTokenIdentifier((EncapsulatedRevocationTokenIdentifier) object);

        }
        LOG.warn("The class '{}' is not supported! Return the original identifier for the object.", object.getClass());
        return object.getDSSId().asXmlId();
    }

    private String getCachedIdentifier(IdentifierBasedObject object) {
        Identifier identifier = object.getDSSId();
        if (identifier == null) {
            throw new IllegalArgumentException(String.format(
                    "The returned Identifier cannot be null for the object of class '%s'!", object.getClass()));
        }
        String originalIdentifier = identifier.asXmlId();
        String value = uniqueTokenIdsMap.get(originalIdentifier);
        if (value != null) {
            LOG.trace("The identifier for the token with Id '{}' has been found in the map. Returning the value...",
                    originalIdentifier);
            return value;
        } else {
            LOG.trace("Computing the user-friendly identifier for the token with Id '{}'...", originalIdentifier);
        }
        return null;
    }

    /**
     * Gets a {@code String} identifier for a given {@code AdvancedSignature}
     *
     * @param signature {@link AdvancedSignature} to get String id for
     * @return {@link String}
     */
    protected String getIdAsStringForSignature(AdvancedSignature signature) {
        X500PrincipalHelper subject = signature.getSigningCertificateToken() != null ?
                signature.getSigningCertificateToken().getSubject() : null;
        return createIdString(signaturePrefix, subject, signature.getSigningTime(), signature.getId());
    }

    /**
     * Gets a {@code String} identifier for a given {@code Token}
     *
     * @param token {@link Token} to get String id for
     * @return {@link String}
     */
    protected String getIdAsStringForToken(Token token) {
        return createIdString(getTokenPrefix(token), getTokenSubject(token), token.getCreationDate(),
                token.getDSSIdAsString());
    }

    /**
     * Gets a {@code String} identifier for a given {@code SignatureScope}
     *
     * @param signatureScope {@link SignatureScope} to get String id for
     * @return {@link String}
     */
    protected String getIdAsStringForSignatureScope(SignatureScope signatureScope) {
        StringBuilder stringBuilder = new StringBuilder(signedDataPrefix);
        stringBuilder.append(STRING_DELIMITER);
        if (Utils.isStringNotBlank(signatureScope.getName())) {
            stringBuilder.append(getUserFriendlyString(signatureScope.getName()));
        } else {
            stringBuilder.append(signatureScope.getType().toString());
        }
        return generateId(stringBuilder, signatureScope.getDSSIdAsString());
    }

    /**
     * Gets a {@code String} identifier for a given {@code TLInfo}
     *
     * @param tlInfo {@link TLInfo} to get String id for
     * @return {@link String}
     */
    protected String getIdAsStringForTL(TLInfo tlInfo) {
        StringBuilder stringBuilder = new StringBuilder(getTlPrefix(tlInfo));
        if (tlInfo.getParsingCacheInfo() != null &&
                Utils.isStringNotBlank(tlInfo.getParsingCacheInfo().getTerritory())) {
            stringBuilder.append(STRING_DELIMITER);
            stringBuilder.append(getUserFriendlyString(tlInfo.getParsingCacheInfo().getTerritory()));
        }
        if (tlInfo.getParsingCacheInfo() != null && tlInfo.getParsingCacheInfo().getIssueDate() != null) {
            stringBuilder.append(STRING_DELIMITER);
            stringBuilder.append(DSSUtils.formatDateWithCustomFormat(
                    tlInfo.getParsingCacheInfo().getIssueDate(), dateFormat));
        }
        return generateId(stringBuilder, tlInfo.getDSSIdAsString());
    }

    /**
     * Gets a {@code String} identifier for a given {@code CertificateRef}
     *
     * @param certificateRef {@link CertificateRef} to get String id for
     * @return {@link String}
     */
    protected String getIdAsStringForCertRef(CertificateRef certificateRef) {
        StringBuilder stringBuilder = new StringBuilder(certificatePrefix);
        if (certificateRef.getResponderId() != null) {
            stringBuilder.append(STRING_DELIMITER);
            X500PrincipalHelper x500PrincipalHelper = new X500PrincipalHelper(
                    certificateRef.getResponderId().getX500Principal());
            stringBuilder.append(getHumanReadableName(x500PrincipalHelper));

        } else if (certificateRef.getCertificateIdentifier() != null) {
            if (certificateRef.getCertificateIdentifier().getIssuerName() != null) {
                stringBuilder.append(STRING_DELIMITER);
                stringBuilder.append(ISSUER);
                X500PrincipalHelper x500PrincipalHelper = new X500PrincipalHelper(
                        certificateRef.getCertificateIdentifier().getIssuerName());
                stringBuilder.append(getHumanReadableName(x500PrincipalHelper));
            }
            if (certificateRef.getCertificateIdentifier().getSerialNumber() != null) {
                stringBuilder.append(STRING_DELIMITER);
                stringBuilder.append(SERIAL);
                stringBuilder.append(certificateRef.getCertificateIdentifier().getSerialNumber());
            }

        } else if (certificateRef.getCertDigest() != null) {
            stringBuilder.append(STRING_DELIMITER);
            stringBuilder.append(certificateRef.getCertDigest().getHexValue());
        }
        return generateId(stringBuilder, certificateRef.getDSSIdAsString());
    }

    /**
     * Gets a {@code String} identifier for a given {@code RevocationRef}
     *
     * @param revocationRef {@link RevocationRef} to get String id for
     * @return {@link String}
     */
    protected String getIdAsStringForRevRef(RevocationRef<?> revocationRef) {
        StringBuilder stringBuilder = new StringBuilder(getRevocationRefPrefix(revocationRef));
        stringBuilder.append(STRING_DELIMITER);
        stringBuilder.append(revocationRef.getDigest().getHexValue());
        return generateId(stringBuilder, revocationRef.getDSSIdAsString());
    }

    /**
     * Gets a {@code String} identifier for a given {@code EncapsulatedRevocationTokenIdentifier}
     *
     * @param revocationIdentifier {@link EncapsulatedRevocationTokenIdentifier} to get String id for
     * @return {@link String}
     */
    protected String getIdAsStringForRevTokenIdentifier(EncapsulatedRevocationTokenIdentifier<?> revocationIdentifier) {
        StringBuilder stringBuilder = new StringBuilder(getRevocationIdentifierPrefix(revocationIdentifier));
        stringBuilder.append(STRING_DELIMITER);
        stringBuilder.append(Utils.toHex(revocationIdentifier.getDigestValue(DigestAlgorithm.SHA256)));
        return generateId(stringBuilder, revocationIdentifier.asXmlId());
    }

    private String createIdString(String prefix, X500PrincipalHelper subject, Date creationDate, String dssId) {
        StringBuilder stringBuilder = new StringBuilder(prefix);
        stringBuilder.append(STRING_DELIMITER);
        if (subject != null) {
            stringBuilder.append(getHumanReadableName(subject));
        } else {
            stringBuilder.append(UNKNOWN_SIGNER);
        }
        if (creationDate != null) {
            stringBuilder.append(STRING_DELIMITER);
            stringBuilder.append(DSSUtils.formatDateWithCustomFormat(creationDate, dateFormat));
        }
        return generateId(stringBuilder, dssId);
    }

    private String getHumanReadableName(X500PrincipalHelper subject) {
        String name = DSSASN1Utils.getHumanReadableName(subject);
        if (Utils.isStringNotEmpty(name)) {
            return getUserFriendlyString(name);
        }
        return UNNAMED_SIGNER;
    }

    private String generateId(StringBuilder stringBuilder, String dssId) {
        String generatedId = stringBuilder.toString();
        Long duplicatesNumber = getDuplicatesNumber(generatedId, dssId);
        if (duplicatesNumber != 0) {
            stringBuilder.append(STRING_DELIMITER);
            stringBuilder.append(++duplicatesNumber);
        }
        generatedTokenIdsMap.put(dssId, generatedId);

        String uniqueId = stringBuilder.toString();
        uniqueTokenIdsMap.put(dssId, uniqueId);
        return uniqueId;
    }

    private Long getDuplicatesNumber(String builtId, String dssId) {
        return generatedTokenIdsMap.entrySet().stream()
                .filter(e -> !dssId.equals(e.getKey()) && builtId.equals(e.getValue()))
                .collect(Collectors.counting());
    }

    private String getTokenPrefix(Token token) {
        if (token instanceof CertificateToken) {
            return certificatePrefix;
        } else if (token instanceof CRLToken) {
            return crlPrefix;
        } else if (token instanceof OCSPToken) {
            return ocspPrefix;
        } else if (token instanceof TimestampToken) {
            return timestampPrefix;
        } else {
            throw new IllegalArgumentException(String.format(
                    "Unsupported token of class '%s' has been reached!", token.getClass()));
        }
    }

    private X500PrincipalHelper getTokenSubject(Token token) {
        X500PrincipalHelper subject = null;
        if (token instanceof CertificateToken) {
            CertificateToken certificateToken = (CertificateToken) token;
            subject = certificateToken.getSubject();
        } else {
            X500Principal issuerX500Principal = token.getIssuerX500Principal();
            if (issuerX500Principal != null) {
                subject = new X500PrincipalHelper(issuerX500Principal);
            }
        }
        return subject;
    }

    private String getTlPrefix(TLInfo tlInfo) {
        if (tlInfo instanceof PivotInfo) {
            return pivotPrefix;
        } else if (tlInfo instanceof LOTLInfo) {
            return lotlPrefix;
        } else {
            return tlPrefix;
        }
    }

    private String getRevocationRefPrefix(RevocationRef<?> revocationRef) {
        if (revocationRef instanceof CRLRef) {
            return crlPrefix;
        } else if (revocationRef instanceof OCSPRef) {
            return ocspPrefix;
        } else {
            throw new IllegalArgumentException(String.format(
                    "Unsupported RevocationRef of class '%s' has been reached!", revocationRef.getClass()));
        }
    }

    private String getRevocationIdentifierPrefix(EncapsulatedRevocationTokenIdentifier<?> revocationIdentifier) {
        if (revocationIdentifier instanceof CRLBinary) {
            return crlPrefix;
        } else if (revocationIdentifier instanceof OCSPResponseBinary) {
            return ocspPrefix;
        } else {
            throw new IllegalArgumentException(String.format(
                    "Unsupported RevocationTokenIdentifier of class '%s' has been reached!",
                    revocationIdentifier.getClass()));
        }
    }

    private String getUserFriendlyString(String str) {
        str = DSSUtils.removeControlCharacters(str);
        str = DSSUtils.replaceAllNonAlphanumericCharacters(str, NAME_REPLACEMENT);
        return trim(str, NAME_REPLACEMENT);
    }

    private String trim(String str, String trimmedStr) {
        while (str.length() > trimmedStr.length() && str.startsWith(trimmedStr)) {
            str = Utils.substringAfter(str, trimmedStr);
        }
        while (str.length() > trimmedStr.length() && str.endsWith(trimmedStr)) {
            str = str.substring(0, str.length() - trimmedStr.length());
        }
        return str;
    }

    private void assertNotBlank(String str) {
        if (Utils.isStringBlank(str)) {
            throw new IllegalArgumentException("The prefix cannot be null or blank!");
        }
    }

}
