package eu.europa.esig.dss.pki.jaxb.utils;


import eu.europa.esig.dss.enumerations.RevocationReason;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.pki.jaxb.XmlDigestAlgo;
import eu.europa.esig.dss.pki.jaxb.XmlEncryptionAlgo;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.X509CertificateHolder;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class PKIUtils {

    /**
     * A map between digest algo JavaName and a {@code XmlDigestAlgo} name value
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

    private PKIUtils() {
    }

    public int getCRLReason(RevocationReason revocationReason) {
        if (revocationReason == null) {
            return CRLReason.unspecified;
        }

        switch (revocationReason) {
            case AA_COMPROMISE:
                return CRLReason.aACompromise;
            case AFFILIATION_CHANGED:
                return CRLReason.affiliationChanged;
            case CESSATION_OF_OPERATION:
                return CRLReason.cessationOfOperation;
            case CA_COMPROMISE:
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

    public static String getAlgorithmString(String encryption, XmlDigestAlgo digestAlgo, boolean pss) {
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

        if (XmlEncryptionAlgo.RSASSA_PSS.value().equals(encryption)) {
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
     * Returns a {@code XmlDigestAlgo} by a java name of the digest algorithm
     *
     * @param javaName {@link String} Java name of a digest algorithm
     * @return corresponding {@link XmlDigestAlgo} if found, null otherwise
     */
    public static XmlDigestAlgo getDigestAlgoByJavaName(String javaName) {
        String digestAlgoName = digestAlgoMap.get(javaName);
        if (digestAlgoName == null) {
            return null;
        }
        return XmlDigestAlgo.fromValue(digestAlgoName);
    }

    public static byte[] convertDerToPem(byte[] derEncodedCRL) {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            baos.write("-----BEGIN CRL-----\n".getBytes());

            Base64.Encoder encoder = Base64.getEncoder();
            byte[] base64Encoded = encoder.encode(derEncodedCRL);
            baos.write(base64Encoded);

            baos.write("\n-----END CRL-----".getBytes());

            return baos.toByteArray();
        } catch (IOException e) {
            throw new DSSException("Unable to generate the CRL");
        }
    }

    public static String getCommonName(X509CertificateHolder cert) {
        return cert.getSubject().getRDNs(BCStyle.CN)[0].getFirst().getValue().toString();
    }
}
