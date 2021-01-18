package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.identifier.EncapsulatedRevocationTokenIdentifier;
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
import org.bouncycastle.asn1.x500.style.BCStyle;

import javax.security.auth.x500.X500Principal;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * Creates an identifier for a given token by the template:
 *
 * TOKEN-CommonCertName-CreationDate-id
 *
 * Examples:
 * SIGNATURE-JohnConner-20201015-2045-1
 * CERTIFICATE-CryptoSign-20151014-1425-1
 */
public class UserFriendlyIdentifierProvider implements TokenIdentifierProvider {

    /** String is used to separate different parts of the identifier */
    private static final String STRING_DELIMITER = "_";

    /** String to be used to replace non-alphanumeric characters in a certificate's common name */
    private static final String NAME_REPLACEMENT = "-";

    /** String used when token's signing certificate is not identified */
    private static final String UNKNOWN_SIGNER = "unknownSigner";

    /**
     * Represents a map for processed tokens between the original DSS hash-based Id
     * and the one computed by the class
     */
    private final Map<String, String> tokenIdsMap = new HashMap<>();

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
    private String dateFormat = "yyyyMMdd-hhmm";

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
     * Default = "yyyyMMdd-hhmm"
     *
     * @param dateFormat {@link String} the target date format
     */
    public void setDateFormat(String dateFormat) {
        Objects.requireNonNull(dateFormat, "The dataFormat cannot be null!");
        this.dateFormat = dateFormat;
    }

    @Override
    public String getIdAsString(AdvancedSignature signature) {
        return createIdString(signaturePrefix, signature.getSigningCertificateToken().getSubject(),
                signature.getSigningTime(), signature.getId());
    }

    @Override
    public String getIdAsString(Token token) {
        return createIdString(getTokenPrefix(token), getTokenSubject(token),
                token.getCreationDate(), token.getDSSIdAsString());
    }

    @Override
    public String getIdAsString(SignatureScope signatureScope) {
        StringBuilder stringBuilder = new StringBuilder(signedDataPrefix);
        stringBuilder.append(STRING_DELIMITER);
        if (Utils.isStringNotBlank(signatureScope.getName())) {
            stringBuilder.append(getUserFriendlyString(signatureScope.getName()));
        } else {
            stringBuilder.append(signatureScope.getType().toString());
        }
        return generateId(stringBuilder, signatureScope.getDSSIdAsString());
    }

    @Override
    public String getIdAsString(TLInfo tlInfo) {
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

    @Override
    public String getIdAsString(CertificateRef certificateRef) {
        StringBuilder stringBuilder = new StringBuilder(certificatePrefix);
        stringBuilder.append(STRING_DELIMITER);
        stringBuilder.append(certificateRef.getOrigin().toString());
        if (certificateRef.getResponderId() != null) {
            stringBuilder.append(STRING_DELIMITER);
            X500PrincipalHelper x500PrincipalHelper = new X500PrincipalHelper(
                    certificateRef.getResponderId().getX500Principal());
            stringBuilder.append(getCommonName(x500PrincipalHelper));
        } else if (certificateRef.getCertificateIdentifier() != null &&
                certificateRef.getCertificateIdentifier().getSerialNumber() != null) {
            stringBuilder.append(STRING_DELIMITER);
            stringBuilder.append(certificateRef.getCertificateIdentifier().getSerialNumber());
        } else if (certificateRef.getCertDigest() != null) {
            stringBuilder.append(STRING_DELIMITER);
            stringBuilder.append(certificateRef.getCertDigest().getHexValue());
        }
        return generateId(stringBuilder, certificateRef.getDSSIdAsString());
    }

    @Override
    public String getIdAsString(RevocationRef<?> revocationRef) {
        StringBuilder stringBuilder = new StringBuilder(getRevocationRefPrefix(revocationRef));
        stringBuilder.append(STRING_DELIMITER);
        stringBuilder.append(revocationRef.getDigest().getHexValue());
        return generateId(stringBuilder, revocationRef.getDSSIdAsString());
    }

    @Override
    public String getIdAsString(EncapsulatedRevocationTokenIdentifier<?> revocationIdentifier) {
        StringBuilder stringBuilder = new StringBuilder(getRevocationIdentifierPrefix(revocationIdentifier));
        stringBuilder.append(STRING_DELIMITER);
        stringBuilder.append(Utils.toHex(revocationIdentifier.getDigestValue(DigestAlgorithm.SHA256)));
        return generateId(stringBuilder, revocationIdentifier.asXmlId());
    }

    private String createIdString(String prefix, X500PrincipalHelper subject, Date creationDate, String dssId) {
        StringBuilder stringBuilder = new StringBuilder(prefix);
        stringBuilder.append(STRING_DELIMITER);
        if (subject != null) {
            stringBuilder.append(getCommonName(subject));
        } else {
            stringBuilder.append(UNKNOWN_SIGNER);
        }
        if (creationDate != null) {
            stringBuilder.append(STRING_DELIMITER);
            stringBuilder.append(DSSUtils.formatDateWithCustomFormat(creationDate, dateFormat));
        }
        return generateId(stringBuilder, dssId);
    }

    private String getCommonName(X500PrincipalHelper subject) {
        String commonName = DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.CN, subject);
        if (Utils.isStringNotEmpty(commonName)) {
            return getUserFriendlyString(commonName);
        }
        return null;
    }

    private String generateId(StringBuilder stringBuilder, String dssId) {
        Long duplicatesNumber = getDuplicatesNumber(stringBuilder.toString(), dssId);
        if (duplicatesNumber != 0) {
            stringBuilder.append(STRING_DELIMITER);
            stringBuilder.append(++duplicatesNumber);
        }
        String generatedId = stringBuilder.toString();
        tokenIdsMap.put(dssId, generatedId);
        return generatedId;
    }

    private Long getDuplicatesNumber(String builtId, String dssId) {
        return tokenIdsMap.entrySet().stream()
                .filter(e -> !e.getKey().contains(dssId) && e.getValue().contains(builtId))
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
