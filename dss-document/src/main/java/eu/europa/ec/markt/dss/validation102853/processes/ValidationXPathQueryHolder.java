package eu.europa.ec.markt.dss.validation102853.processes;

/**
 * TODO
 *
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public interface ValidationXPathQueryHolder {

    public static final String XP_REFERENCE_DATA_FOUND = "./BasicSignature/ReferenceDataFound/text()";
    public static final String XP_REFERENCE_DATA_INTACT = "./BasicSignature/ReferenceDataIntact/text()";
    public static final String XP_SIGNATURE_INTACT = "./BasicSignature/SignatureIntact/text()";
    public static final String XP_SIGNATURE_VALID = "./BasicSignature/SignatureValid/text()";

    public static final String XP_MESSAGE_IMPRINT_DATA_FOUND = "./MessageImprintDataFound/text()";
    public static final String XP_MESSAGE_IMPRINT_DATA_INTACT = "./MessageImprintDataIntact/text()";

    public static final String XP_ENCRYPTION_ALGO_USED_TO_SIGN_THIS_TOKEN = "./BasicSignature/EncryptionAlgoUsedToSignThisToken/text()";
    public static final String XP_DIGEST_ALGO_USED_TO_SIGN_THIS_TOKEN = "./BasicSignature/DigestAlgoUsedToSignThisToken/text()";
    public static final String XP_KEY_LENGTH_USED_TO_SIGN_THIS_TOKEN = "./BasicSignature/KeyLengthUsedToSignThisToken/text()";
}
