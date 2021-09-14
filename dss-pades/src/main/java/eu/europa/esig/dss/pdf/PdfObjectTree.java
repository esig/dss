package eu.europa.esig.dss.pdf;

import java.util.ArrayList;
import java.util.List;

/**
 * Represents a PDF object chain from a root to the current object
 *
 */
public class PdfObjectTree {

    private static final String SLASH = "/";

    private static final String SPACE = " ";

    private static final String REFERENCE = " 0 R";

    /** Key chain */
    private List<String> keyChain;

    /** Used to build a user-friendly string */
    private StringBuilder sb;

    /**
     * Default constructor
     *
     * @param key {@link String} root key
     */
    public PdfObjectTree(String key) {
        this.keyChain = new ArrayList<>();
        this.sb = new StringBuilder();
        addKey(key);
    }

    private PdfObjectTree(PdfObjectTree objectTree) {
        this.keyChain = new ArrayList<>(objectTree.keyChain);
        this.sb = new StringBuilder(objectTree.sb.toString());
    }

    /**
     * Creates a copy of the object (changes within a copy will not affect the original object)
     *
     * @return {@link PdfObjectTree} copy
     */
    public PdfObjectTree copy() {
        return new PdfObjectTree(this);
    }

    /**
     * Adds a key
     *
     * @param key {@link String}
     */
    public void addKey(String key) {
        keyChain.add(key);
        if (sb.length() != 0) {
            sb.append(SPACE);
        }
        sb.append(SLASH);
        sb.append(key);
    }

    /**
     * Adds a numeric reference number
     *
     * @param objectNumber {@link Number}
     */
    public void addReference(Number objectNumber) {
        if (sb.length() != 0) {
            sb.append(SPACE);
        }
        sb.append(objectNumber);
        sb.append(REFERENCE);
    }

    /**
     * Gets a complete key chain
     *
     * @return a list of {@link String}s
     */
    public List<String> getKeyChain() {
        return keyChain;
    }

    /**
     * Returns a last key
     *
     * @return {@link String}
     */
    public String getLastKey() {
        return keyChain.get(keyChain.size() - 1);
    }

    @Override
    public String toString() {
        return sb.toString();
    }

}
