/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.pdf.modifications;

import eu.europa.esig.dss.pades.validation.PdfObjectKey;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Represents a PDF object chain from a root to the current object
 *
 */
public class PdfObjectTree {

    private static final String SLASH = "/";

    private static final String SPACE = " ";

    private static final String REFERENCE = " 0 R";

    private static final String STREAM = "stream";

    /** Key chain */
    private List<String> keyChain;

    /** Processed references */
    private List<PdfObjectKey> refChain;

    /** Used to build a user-friendly string */
    private StringBuilder sb;

    /**
     * Constructor without starting key
     */
    public PdfObjectTree() {
        this.keyChain = new ArrayList<>();
        this.refChain = new ArrayList<>();
        this.sb = new StringBuilder();
    }

    /**
     * Default constructor
     *
     * @param key {@link String} root key
     */
    public PdfObjectTree(String key) {
        this.keyChain = new ArrayList<>();
        this.refChain = new ArrayList<>();
        this.sb = new StringBuilder();
        addKey(key);
    }

    private PdfObjectTree(PdfObjectTree objectTree) {
        this.keyChain = new ArrayList<>(objectTree.keyChain);
        this.refChain = new ArrayList<>(objectTree.refChain);
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
     * Adds a pdf object key
     *
     * @param objectKey {@link PdfObjectKey}
     */
    public void addReference(PdfObjectKey objectKey) {
        refChain.add(objectKey);
        if (sb.length() != 0) {
            sb.append(SPACE);
        }
        sb.append(objectKey.getNumber());
        sb.append(REFERENCE);
    }

    /**
     * This method allows to specify that a stream have been processed
     *
     */
    public void setStream() {
        if (sb.length() != 0) {
            sb.append(SPACE);
        }
        sb.append(STREAM);
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
     * Returns the deepness of the current objects chain
     *
     * @return chain deepness
     */
    public int getChainDeepness() {
        return keyChain.size();
    }

    /**
     * Returns a last key
     *
     * @return {@link String}
     */
    public String getLastKey() {
        return keyChain.get(keyChain.size() - 1);
    }

    /**
     * Checks whether a reference to the given object by number has been already processed in this tree
     *
     * @param objectKey {@link PdfObjectKey} reference number to an object
     * @return TRUE if the reference has been already processed, FALSE otherwise
     */
    public boolean isProcessedReference(PdfObjectKey objectKey) {
        return refChain.contains(objectKey);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof PdfObjectTree)) return false;

        PdfObjectTree that = (PdfObjectTree) o;

        if (!Objects.equals(keyChain, that.keyChain)) return false;
        if (!Objects.equals(refChain, that.refChain)) return false;
        return Objects.equals(sb.toString(), that.sb.toString());
    }

    @Override
    public int hashCode() {
        int result = keyChain != null ? keyChain.hashCode() : 0;
        result = 31 * result + (refChain != null ? refChain.hashCode() : 0);
        result = 31 * result + (sb != null ? sb.toString().hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        return sb.toString();
    }

}
