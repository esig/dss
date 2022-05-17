package eu.europa.esig.dss.validation.process.bbb.fc.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * This class verifies whether the elliptic curve key size used to create the signature corresponds to
 * the defined within 'alg' header of the JWA signature as per RFC 7518.
 *
 */
public class EllipticCurveKeySizeCheck extends ChainItem<XmlFC> {

    /** The PDF signature to be checked */
    private final SignatureWrapper signature;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlFC}
     * @param signature {@link SignatureWrapper}
     * @param constraint {@link LevelConstraint}
     */
    public EllipticCurveKeySizeCheck(I18nProvider i18nProvider, XmlFC result, SignatureWrapper signature, LevelConstraint constraint) {
        super(i18nProvider, result, constraint);
        this.signature = signature;
    }

    @Override
    protected boolean process() {
        if (!isEncryptionAlgorithmKnown() || !isDigestAlgorithmKnown() || !isKeySizeKnown()) {
            return false;
        }
        return !signature.getEncryptionAlgorithm().isEquivalent(EncryptionAlgorithm.ECDSA) ||
                isDigestAlgorithmAuthorized() && keySizeCorrespondsDigestAlgorithm();
    }

    private boolean isEncryptionAlgorithmKnown() {
        return signature.getEncryptionAlgorithm() != null;
    }

    private boolean isDigestAlgorithmKnown() {
        return signature.getDigestAlgorithm() != null;
    }

    private boolean isKeySizeKnown() {
        return signature.getKeyLengthUsedToSignThisToken() != null;
    }

    private boolean isDigestAlgorithmAuthorized() {
        /*
         * Only three DigestAlgorithms are authorized to be used with ECDSA/PLAIN-ECDSA in RFC 7518
         */
        switch (signature.getDigestAlgorithm()) {
            case SHA256:
            case SHA384:
            case SHA512:
                return true;
            default:
                return false;
        }
    }

    private boolean keySizeCorrespondsDigestAlgorithm() {
        String correspondingKeySize = getCorrespondingKeySize(signature.getDigestAlgorithm());
        return correspondingKeySize != null && correspondingKeySize.equals(signature.getKeyLengthUsedToSignThisToken());
    }

    private String getCorrespondingKeySize(DigestAlgorithm digestAlgorithm) {
        switch (digestAlgorithm) {
            case SHA256:
                return "256";
            case SHA384:
                return "384";
            case SHA512:
                return "521";
            default:
                return null;
        }
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BBB_FC_IECKSCDA;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        if (!isEncryptionAlgorithmKnown()) {
            return MessageTag.BBB_FC_IECKSCDA_ANS1;
        } else if (!isDigestAlgorithmKnown()) {
            return MessageTag.BBB_FC_IECKSCDA_ANS2;
        } else if (!isKeySizeKnown()) {
            return MessageTag.BBB_FC_IECKSCDA_ANS3;
        } else if (!isDigestAlgorithmAuthorized()) {
            return MessageTag.BBB_FC_IECKSCDA_ANS4;
        } else if (!keySizeCorrespondsDigestAlgorithm()) {
            return MessageTag.BBB_FC_IECKSCDA_ANS5;
        }
        return null;
    }

    @Override
    protected String buildAdditionalInfo() {
        if (isEncryptionAlgorithmKnown() && isDigestAlgorithmKnown() && isKeySizeKnown()) {
            return i18nProvider.getMessage(MessageTag.SIGNATURE_ALGORITHM_WITH_KEY_SIZE,
                    signature.getSignatureAlgorithm().getName(), signature.getKeyLengthUsedToSignThisToken());
        }
        return null;
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return Indication.FAILED;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return SubIndication.FORMAT_FAILURE;
    }

}
