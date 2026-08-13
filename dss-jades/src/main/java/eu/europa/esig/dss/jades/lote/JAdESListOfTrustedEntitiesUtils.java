package eu.europa.esig.dss.jades.lote;

import eu.europa.esig.dss.model.DSSDocument;

import java.util.List;
import java.util.Objects;

/**
 * This class contains utils for a JAdES signature creation of an JSON List of Trusted Entities
 *
 */
public class JAdESListOfTrustedEntitiesUtils {

    /**
     * Empty constructor
     */
    private JAdESListOfTrustedEntitiesUtils() {
        // empty
    }

    /**
     * This method helps to determine whether the chosen signature parameters builders is 
     * applicable to the given {@code DSSDocument}. Thus, it verifies whether the provided document representing 
     * the JSON List of Trusted Entities is conformant to the definition.
     * Returns a list of errors if problems have been found during the validation.
     * Returns an empty list in case of a valid JSON List of Trusted Entities conformant to the specified version.
     *
     * @param loteDocument {@link DSSDocument} the JSON List of Trusted Entities document to be validated
     * @return a list of {@link String} messages in case of issues on validation, empty list for a passed validation
     */
    public static List<String> validateUnsignedLOTE(DSSDocument loteDocument) {
        Objects.requireNonNull(loteDocument, "JSON List of Trusted Entities cannot be null!");
        return new JsonLoTEStructureVerifier().setSigningMode(true).validate(loteDocument);
    }

    /**
     * This method helps to determine whether the chosen signature parameters builders is
     * applicable to the given JSON {@code String}. Thus, it verifies whether the provided document representing
     * the JSON List of Trusted Entities is conformant to the definition.
     * Returns a list of errors if problems have been found during the validation.
     * Returns an empty list in case of a valid JSON List of Trusted Entities conformant to the specified version.
     *
     * @param loteDocument {@link String} the JSON List of Trusted Entities document to be validated
     * @return a list of {@link String} messages in case of issues on validation, empty list for a passed validation
     */
    public static List<String> validateUnsignedLOTE(String loteDocument) {
        Objects.requireNonNull(loteDocument, "JSON List of Trusted Entities cannot be null!");
        return new JsonLoTEStructureVerifier().setSigningMode(true).validate(loteDocument);
    }

}
