package eu.europa.esig.dss;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.utils.Utils;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Node;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import java.io.ByteArrayOutputStream;
import java.util.HashSet;
import java.util.Set;

/**
 * Contains a set of method for canonicalization of {@code org.w3c.dom.Node}
 *
 */
public class XMLCanonicalizer {

    private static final Logger LOG = LoggerFactory.getLogger(XMLCanonicalizer.class);

    /** List of supported canonicalization methods */
    private static final Set<String> canonicalizers;

    /**
     * This is the default canonicalization method used for production of signatures
     * within DSS framework.
     * Another complication arises because of the way that the default
     * canonicalization algorithm handles namespace declarations; frequently a
     * signed XML document needs to be embedded in another document; in this case
     * the original canonicalization algorithm will not yield the same result as if
     * the document is treated alone. For this reason, the so-called Exclusive
     * Canonicalization, which serializes XML namespace declarations independently
     * of the surrounding XML, was created.
     */
    public static final String DEFAULT_DSS_C14N_METHOD = CanonicalizationMethod.EXCLUSIVE;

    /**
     * This is the default canonicalization method for XMLDSIG used for signatures
     * and timestamps (see XMLDSIG 4.4.3.2) when one is not defined.
     */
    public static final String DEFAULT_XMLDSIG_C14N_METHOD = CanonicalizationMethod.INCLUSIVE;

    /** Xmlsec canonicalizer instance */
    private final Canonicalizer c14n;

    static {
        SantuarioInitializer.init();

        canonicalizers = new HashSet<>();
        registerDefaultCanonicalizers();
    }

    /**
     * This method registers the default canonicalizers.
     */
    private static void registerDefaultCanonicalizers() {
        registerCanonicalizer(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);
        registerCanonicalizer(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        registerCanonicalizer(Canonicalizer.ALGO_ID_C14N11_OMIT_COMMENTS);
        registerCanonicalizer(Canonicalizer.ALGO_ID_C14N_PHYSICAL);
        registerCanonicalizer(Canonicalizer.ALGO_ID_C14N_WITH_COMMENTS);
        registerCanonicalizer(Canonicalizer.ALGO_ID_C14N_EXCL_WITH_COMMENTS);
        registerCanonicalizer(Canonicalizer.ALGO_ID_C14N11_WITH_COMMENTS);
    }

    /**
     * Default constructor
     */
    private XMLCanonicalizer(String canonicalizationMethod) {
        canonicalizationMethod = getCanonicalizationMethod(canonicalizationMethod);
        assertCanonicalizationMethodSupported(canonicalizationMethod);
        this.c14n = initCanonicalizer(canonicalizationMethod);
    }

    /**
     * Creates in instance of {@code XMLCanonicalizer} to be used with
     * default XMLDSig canonicalization method "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
     *
     * @return {@link XMLCanonicalizer}
     */
    public static XMLCanonicalizer createInstance() {
        return createInstance(null);
    }

    /**
     * Creates in instance of {@code XMLCanonicalizer} with provided canonicalization method.
     * If the canonicalization method is null, the default XMLDSig canonicalization method
     * "http://www.w3.org/TR/2001/REC-xml-c14n-20010315" will be used.
     *
     * @param canonicalizationMethod {@link String} canonicalization method to instantiate XML Canonicalizer with
     * @return {@link XMLCanonicalizer}
     */
    public static XMLCanonicalizer createInstance(String canonicalizationMethod) {
        return new XMLCanonicalizer(canonicalizationMethod);
    }

    private static void assertCanonicalizationMethodSupported(String canonicalizationMethod) {
        if (!canCanonicalize(canonicalizationMethod)) {
            throw new IllegalArgumentException(String.format("The canonicalization method '{}' is not supported! " +
                    "Use #registerCanonicalizer method to add support of a canonicalization method.", canonicalizationMethod));
        }
    }

    private static Canonicalizer initCanonicalizer(String canonicalizationMethod) {
        try {
            return Canonicalizer.getInstance(canonicalizationMethod);
        } catch (InvalidCanonicalizerException e) {
            throw new DSSException(String.format(
                    "The canonicalizer cannot be instantiated with canonicalization method '%s'! Reason : %s",
                    canonicalizationMethod, e.getMessage()), e);
        }
    }

    /**
     * This method says if the framework can canonicalize an XML data with the provided method.
     *
     * @param canonicalizationMethod
     *            the canonicalization method to be checked
     * @return true if it is possible to canonicalize false otherwise
     */
    public static boolean canCanonicalize(final String canonicalizationMethod) {
        return canonicalizers.contains(canonicalizationMethod);
    }

    /**
     * This method allows to register a canonicalizer.
     *
     * @param c14nAlgorithmURI
     *            the URI of canonicalization algorithm
     * @return true if this set did not already contain the specified element
     */
    public static boolean registerCanonicalizer(final String c14nAlgorithmURI) {
        return canonicalizers.add(c14nAlgorithmURI);
    }

    /**
     * This method canonicalizes the given array of bytes using the defined canonicalization method.
     *
     * @param toCanonicalizeBytes
     *            array of bytes to canonicalize
     * @return array of canonicalized bytes
     * @throws DSSException
     *             if any error is encountered
     */
    public byte[] canonicalize(byte[] toCanonicalizeBytes) throws DSSException {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            c14n.canonicalize(toCanonicalizeBytes, baos, true);
            return baos.toByteArray();
        } catch (Exception e) {
            throw new DSSException("Cannot canonicalize the binaries", e);
        }
    }

    /**
     * This method canonicalizes the given {@code Node} using the defined canonicalization method.
     *
     * @param node
     *            {@code Node} to canonicalize
     * @return array of canonicalized bytes
     */
    public byte[] canonicalize(final Node node) {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            c14n.canonicalizeSubtree(node, baos);
            return baos.toByteArray();
        } catch (Exception e) {
            throw new DSSException("Cannot canonicalize the subtree", e);
        }
    }

    /**
     * Returns the {@code canonicalizationMethod} if provided, otherwise returns the DEFAULT_CANONICALIZATION_METHOD
     *
     * @param canonicalizationMethod {@link String} canonicalization method (can be null)
     * @return canonicalizationMethod to be used
     */
    private static String getCanonicalizationMethod(String canonicalizationMethod) {
        if (Utils.isStringEmpty(canonicalizationMethod)) {
            // The INCLUSIVE canonicalization is used by default (See DSS-2208)
            LOG.warn("Canonicalization method is not defined. "
                    + "An inclusive canonicalization '{}' will be used (see XMLDSIG 4.4.3.2).", DEFAULT_XMLDSIG_C14N_METHOD);
            return DEFAULT_XMLDSIG_C14N_METHOD;
        }
        return canonicalizationMethod;
    }

}
