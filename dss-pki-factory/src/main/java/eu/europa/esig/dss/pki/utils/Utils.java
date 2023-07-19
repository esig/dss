package eu.europa.esig.dss.pki.utils;

import eu.europa.esig.dss.pki.DigestAlgo;
import eu.europa.esig.dss.pki.EncryptionAlgo;
import eu.europa.esig.dss.pki.RevocationReason;
import org.bouncycastle.asn1.x509.CRLReason;

import java.util.HashMap;
import java.util.Map;

public final class Utils {

    /**
     * A map between digest algo JavaName and a {@code DigestAlgo} name value
     */
    private static Map<String, String> digestAlgoMap;

    static {
        digestAlgoMap = new HashMap<>();
        digestAlgoMap.put("SHA-1", "SHA1");
        digestAlgoMap.put("SHA-256", "SHA256");
        digestAlgoMap.put("SHA-512", "SHA512");
        digestAlgoMap.put("SHA3-256", "SHA3-256");
        digestAlgoMap.put("SHA3-512", "SHA3-512");
    }

    private Utils() {
    }

    public static int getCRLReason(RevocationReason revocationReason) {
        if (revocationReason == null) {
            return CRLReason.unspecified;
        }

        switch (revocationReason) {
            case A_A_COMPROMISE:
                return CRLReason.aACompromise;
            case AFFILIATION_CHANGED:
                return CRLReason.affiliationChanged;
            case CESSATION_OF_OPERATION:
                return CRLReason.cessationOfOperation;
            case C_A_COMPROMISE:
                return CRLReason.cACompromise;
            case CERTIFICATE_HOLD:
                return CRLReason.certificateHold;
            case KEY_COMPROMISE:
                return CRLReason.keyCompromise;
            case PRIVILEGE_WITHDRAWN:
                return CRLReason.privilegeWithdrawn;
            case REMOVE_FROM_CRL:
                return CRLReason.removeFromCRL;
            case SUPERSEDED:
                return CRLReason.superseded;
            default:
                return CRLReason.unspecified;
        }
    }

    public static String getAlgorithmString(String encryption, DigestAlgo digestAlgo, boolean pss) {
        String digestAlgoString = null;
        if (digestAlgo != null) {
            digestAlgoString = digestAlgo.value();
        }
        return getAlgorithmString(encryption, digestAlgoString, pss);
    }

    public static String getAlgorithmString(String encryption, String digestAlgo, boolean pss) {
        String encryptionToUse = encryption;
        if ("Ed25519".equalsIgnoreCase(encryptionToUse)) {
            return "Ed25519";
        } else if ("Ed448".equalsIgnoreCase(encryptionToUse)) {
            return "Ed448";
        }

        if (EncryptionAlgo.RSASSA_PSS.value().equals(encryption)) {
            encryptionToUse = "RSA";
        }

        // "SHA512withRSA"
        String pssValue = "";
        if (pss) {
            pssValue = "andMGF1";
        }
        return digestAlgo + "with" + encryptionToUse + pssValue;
    }

    /**
     * Returns a {@code DigestAlgo} by a java name of the digest algorithm
     *
     * @param javaName {@link String} Java name of a digest algorithm
     * @return corresponding {@link DigestAlgo} if found, null otherwise
     */
    public static DigestAlgo getDigestAlgoByJavaName(String javaName) {
        String digestAlgoName = digestAlgoMap.get(javaName);
        if (digestAlgoName == null) {
            return null;
        }
        return DigestAlgo.fromValue(digestAlgoName);
    }

}
