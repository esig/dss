package eu.europa.esig.dss.xades.validation;

/**
 * Creates a relevant implementation of {@code XAdESStructureValidator}.
 * This class also evaluates a presence of 'dss-validation' module in the classpath.
 *
 */
public class XAdESStructureValidatorFactory {

    /** Current factory instance */
    private static XAdESStructureValidatorFactory singleton;

    /**
     * Default constructor
     */
    protected XAdESStructureValidatorFactory() {
        // empty
    }

    /**
     * Gets the instance of {@code XAdESStructureValidatorFactory}
     *
     * @return {@link XAdESStructureValidatorFactory}
     */
    public static XAdESStructureValidatorFactory getInstance() {
        if (singleton == null) {
            singleton = new XAdESStructureValidatorFactory();
        }
        return singleton;
    }

    /**
     * Creates a {@code XAdESStructureValidator} for the given {@code XAdESSignature}
     *
     * @param signature {@link XAdESSignature} to validate structure of
     * @return {@link XAdESStructureValidator}
     */
    public XAdESStructureValidator fromXAdESSignature(XAdESSignature signature) {
        assertXAdESStructureValidatorLoaded();
        return new XAdESStructureValidator(signature.getSignatureElement(), signature.getXAdESPaths());
    }

    /**
     * Verifies whether the {@code XAdESStructureValidator} is available and 'dss-validation' module is successfully loaded
     */
    protected void assertXAdESStructureValidatorLoaded() {
        try {
            Class.forName("eu.europa.esig.dss.xades.validation.XAdESStructureValidator");
        } catch (ClassNotFoundException | NoClassDefFoundError e) {
            throw new ExceptionInInitializerError(
                    "No implementation found for XSD Utils in classpath, please include 'dss-validation' module for structure validation.");
        }
    }

}
