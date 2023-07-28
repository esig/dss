package eu.europa.esig.dss.evidencerecord.xml;

import eu.europa.esig.dss.model.DSSException;
import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.Canonicalizer;
import org.w3c.dom.Node;

import java.io.ByteArrayOutputStream;

/**
 * Contains util methods for XML Evidence Record processing
 */
// TODO : consider creation a separate module with xml/xmlsec utils
public class XmlEvidenceRecordUtils {

    /**
     * Default constructor
     */
    private XmlEvidenceRecordUtils() {
        // empty
    }

    static {
        // TODO : move Santuario/XML to a separate module
        Init.init();

        //
        // Set the default c14n algorithms
        //
        Canonicalizer.registerDefaultAlgorithms();
    }

    /**
     * This method canonicalizes the given array of bytes using the {@code canonicalizationMethod} parameter.
     *
     * @param canonicalizationMethod
     *            canonicalization method
     * @param toCanonicalizeBytes
     *            array of bytes to canonicalize
     * @return array of canonicalized bytes
     * @throws DSSException
     *             if any error is encountered
     */
    public static byte[] canonicalize(final String canonicalizationMethod, final byte[] toCanonicalizeBytes) throws DSSException {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            final Canonicalizer c14n = Canonicalizer.getInstance(canonicalizationMethod);
            c14n.canonicalize(toCanonicalizeBytes, baos, true);
            return baos.toByteArray();
        } catch (Exception e) {
            throw new DSSException("Cannot canonicalize the binaries", e);
        }
    }

    /**
     * This method canonicalizes the given {@code Node}.
     * If canonicalization method is not provided, the {@code DEFAULT_CANONICALIZATION_METHOD} is being used
     *
     * @param canonicalizationMethod
     *            canonicalization method (can be null)
     * @param node
     *            {@code Node} to canonicalize
     * @return array of canonicalized bytes
     */
    public static byte[] canonicalizeSubtree(final String canonicalizationMethod, final Node node) {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            final Canonicalizer c14n = Canonicalizer.getInstance(canonicalizationMethod);
            c14n.canonicalizeSubtree(node, baos);
            return baos.toByteArray();
        } catch (Exception e) {
            throw new DSSException("Cannot canonicalize the subtree", e);
        }
    }

}
