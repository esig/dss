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
package eu.europa.esig.dss.diagnostic;

import eu.europa.esig.dss.diagnostic.jaxb.XmlByteRange;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDocMDP;
import eu.europa.esig.dss.diagnostic.jaxb.XmlModification;
import eu.europa.esig.dss.diagnostic.jaxb.XmlModificationDetection;
import eu.europa.esig.dss.diagnostic.jaxb.XmlObjectModification;
import eu.europa.esig.dss.diagnostic.jaxb.XmlObjectModifications;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFLockDictionary;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFRevision;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFSignatureField;
import eu.europa.esig.dss.enumerations.CertificationPermission;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Contains user-friendly methods to extract information from an {@code eu.europa.esig.dss.diagnostic.jaxb.XmlPDFRevision}
 *
 */
public class PDFRevisionWrapper {

    /** Wrapped {@code XmlPDFRevision} */
    private final XmlPDFRevision pdfRevision;

    /**
     * Default constructor
     *
     * @param pdfRevision {@link XmlPDFRevision}
     */
    public PDFRevisionWrapper(XmlPDFRevision pdfRevision) {
        Objects.requireNonNull(pdfRevision, "XmlPDFRevision cannot be null!");
        this.pdfRevision = pdfRevision;
    }

    /**
     * Checks if any visual modifications detected in the PDF
     *
     * @return TRUE if modifications detected in a PDF, FALSE otherwise
     */
    public boolean arePdfModificationsDetected() {
        XmlModificationDetection modificationDetection = pdfRevision.getModificationDetection();
        if (modificationDetection != null) {
            return !modificationDetection.getAnnotationOverlap().isEmpty() ||
                    !modificationDetection.getVisualDifference().isEmpty() ||
                    !modificationDetection.getPageDifference().isEmpty();
        }
        return false;
    }

    /**
     * Returns a list of PDF annotation overlap concerned pages
     *
     * @return a list of page numbers
     */
    public List<BigInteger> getPdfAnnotationsOverlapConcernedPages() {
        XmlModificationDetection modificationDetection = pdfRevision.getModificationDetection();
        if (modificationDetection != null) {
            List<XmlModification> annotationOverlap = modificationDetection.getAnnotationOverlap();
            return getConcernedPages(annotationOverlap);
        }
        return Collections.emptyList();
    }

    /**
     * Returns a list of PDF visual difference concerned pages
     *
     * @return a list of page numbers
     */
    public List<BigInteger> getPdfVisualDifferenceConcernedPages() {
        XmlModificationDetection modificationDetection = pdfRevision.getModificationDetection();
        if (modificationDetection != null) {
            List<XmlModification> visualDifference = modificationDetection.getVisualDifference();
            return getConcernedPages(visualDifference);
        }
        return Collections.emptyList();
    }

    /**
     * Returns a list of pages missing/added to the final revision in a comparison with a signed one
     *
     * @return a list of page numbers
     */
    public List<BigInteger> getPdfPageDifferenceConcernedPages() {
        XmlModificationDetection modificationDetection = pdfRevision.getModificationDetection();
        if (modificationDetection != null) {
            List<XmlModification> pageDifference = modificationDetection.getPageDifference();
            return getConcernedPages(pageDifference);
        }
        return Collections.emptyList();
    }

    /**
     * This method checks whether object modifications are present after the current PDF revisions
     *
     * @return TRUE if PDF has been modified, FALSE otherwise
     */
    public boolean arePdfObjectModificationsDetected() {
        return getPdfObjectModifications() != null;
    }

    /**
     * Returns a list of changes occurred in a PDF after the current signature's revision associated
     * with a signature/document extension
     *
     * @return a list of {@link XmlObjectModification}s
     */
    public List<XmlObjectModification> getPdfExtensionChanges() {
        XmlObjectModifications pdfObjectModifications = getPdfObjectModifications();
        if (pdfObjectModifications != null) {
            return pdfObjectModifications.getExtensionChanges();
        }
        return Collections.emptyList();
    }

    /**
     * Returns a list of changes occurred in a PDF after the current signature's revision associated
     * with a signature creation, form filling
     *
     * @return a list of {@link XmlObjectModification}s
     */
    public List<XmlObjectModification> getPdfSignatureOrFormFillChanges() {
        XmlObjectModifications pdfObjectModifications = getPdfObjectModifications();
        if (pdfObjectModifications != null) {
            return pdfObjectModifications.getSignatureOrFormFill();
        }
        return Collections.emptyList();
    }

    /**
     * Returns a list of changes occurred in a PDF after the current signature's revision associated
     * with annotation(s) modification
     *
     * @return a list of {@link XmlObjectModification}s
     */
    public List<XmlObjectModification> getPdfAnnotationChanges() {
        XmlObjectModifications pdfObjectModifications = getPdfObjectModifications();
        if (pdfObjectModifications != null) {
            return pdfObjectModifications.getAnnotationChanges();
        }
        return Collections.emptyList();
    }

    /**
     * Returns a list of undefined changes occurred in a PDF after the current signature's revision
     *
     * @return a list of {@link XmlObjectModification}s
     */
    public List<XmlObjectModification> getPdfUndefinedChanges() {
        XmlObjectModifications pdfObjectModifications = getPdfObjectModifications();
        if (pdfObjectModifications != null) {
            return pdfObjectModifications.getUndefined();
        }
        return Collections.emptyList();
    }

    /**
     * This method returns a list of field names modified after the current signature's revision
     *
     * @return a list of {@link String}s
     */
    public List<String> getModifiedFieldNames() {
        List<String> names = new ArrayList<>();
        XmlObjectModifications pdfObjectModifications = getPdfObjectModifications();
        if (pdfObjectModifications != null) {
            names.addAll(getModifiedFieldNames(pdfObjectModifications.getExtensionChanges()));
            names.addAll(getModifiedFieldNames(pdfObjectModifications.getSignatureOrFormFill()));
            names.addAll(getModifiedFieldNames(pdfObjectModifications.getAnnotationChanges()));
            names.addAll(getModifiedFieldNames(pdfObjectModifications.getUndefined()));
        }
        return names;
    }

    /**
     * Returns the first signature field name
     *
     * @return {@link String} field name
     */
    public String getFirstFieldName() {
        List<XmlPDFSignatureField> fields = pdfRevision.getFields();
        if (fields != null && !fields.isEmpty()) {
            return fields.iterator().next().getName();
        }
        return null;
    }

    /**
     * Returns a list of signature field names, where the signature is referenced from
     *
     * @return a list of {@link String} signature field names
     */
    public List<String> getSignatureFieldNames() {
        List<String> names = new ArrayList<>();
        List<XmlPDFSignatureField> fields = pdfRevision.getFields();
        if (fields != null && !fields.isEmpty()) {
            for (XmlPDFSignatureField signatureField : fields) {
                names.add(signatureField.getName());
            }
        }
        return names;
    }

    /**
     * Returns the signer's name
     *
     * @return {@link String}
     */
    public String getSignerName() {
        return pdfRevision.getPDFSignatureDictionary().getSignerName();
    }

    /**
     * Returns the PDF signature dictionary /Type value
     *
     * @return {@link String}
     */
    public String getSignatureDictionaryType() {
        return pdfRevision.getPDFSignatureDictionary().getType();
    }

    /**
     * Returns the PDF signature dictionary /Filter value
     *
     * @return {@link String}
     */
    public String getFilter() {
        return pdfRevision.getPDFSignatureDictionary().getFilter();
    }

    /**
     * Returns the PDF signature dictionary /SubFilter value
     *
     * @return {@link String}
     */
    public String getSubFilter() {
        return pdfRevision.getPDFSignatureDictionary().getSubFilter();
    }

    /**
     * Returns the PDF signature dictionary /ContactInfo value
     *
     * @return {@link String}
     */
    public String getContactInfo() {
        return pdfRevision.getPDFSignatureDictionary().getContactInfo();
    }

    /**
     * Returns the PDF signature dictionary /Location value
     *
     * @return {@link String}
     */
    public String getLocation() {
        return pdfRevision.getPDFSignatureDictionary().getLocation();
    }

    /**
     * Returns the PDF signature dictionary /Reason value
     *
     * @return {@link String}
     */
    public String getReason() {
        return pdfRevision.getPDFSignatureDictionary().getReason();
    }

    /**
     * Returns the PDF signature dictionary /ByteRange value
     *
     * @return byte range
     */
    public List<BigInteger> getSignatureByteRange() {
        XmlByteRange byteRange = getXmlByteRange();
        if (byteRange != null) {
            return byteRange.getValue();
        }
        return Collections.emptyList();
    }

    /**
     * This method returns whether the PDF signature dictionary /ByteRange is found and valid
     *
     * @return TRUE if the /ByteRange is valid, FALSE otherwise
     */
    public boolean isSignatureByteRangeValid() {
        XmlByteRange byteRange = getXmlByteRange();
        if (byteRange != null) {
            return byteRange.isValid();
        }
        return false;
    }

    private XmlByteRange getXmlByteRange() {
        return pdfRevision.getPDFSignatureDictionary().getSignatureByteRange();
    }

    /**
     * This method returns whether the PDF signature dictionary is consistent across PDF revisions.
     *
     * @return TRUE if the signature dictionary is consistent, FALSE otherwise
     */
    public boolean isPdfSignatureDictionaryConsistent() {
        return pdfRevision.getPDFSignatureDictionary().isConsistent();
    }

    /**
     * Returns a {@code CertificationPermission} value of a /DocMDP dictionary, when present
     *
     * @return {@link CertificationPermission}
     */
    public CertificationPermission getDocMDPPermissions() {
        XmlDocMDP docMDP = pdfRevision.getPDFSignatureDictionary().getDocMDP();
        if (docMDP != null) {
            return docMDP.getPermissions();
        }
        return null;
    }

    /**
     * Returns a /FieldMDP dictionary content, when present
     *
     * @return {@link XmlPDFLockDictionary}
     */
    public XmlPDFLockDictionary getFieldMDP() {
        return pdfRevision.getPDFSignatureDictionary().getFieldMDP();
    }

    /**
     * Returns a /SigFieldLock dictionary, when present
     *
     * @return {@link XmlPDFLockDictionary}
     */
    public XmlPDFLockDictionary getSigFieldLock() {
        List<XmlPDFSignatureField> fields = pdfRevision.getFields();
        for (XmlPDFSignatureField field : fields) {
            XmlPDFLockDictionary sigFieldLock = field.getSigFieldLock();
            if (sigFieldLock != null) {
                return sigFieldLock;
            }
        }
        return null;
    }

    private List<BigInteger> getConcernedPages(List<XmlModification> xmlModifications) {
        List<BigInteger> pages = new ArrayList<>();
        for (XmlModification modification : xmlModifications) {
            pages.add(modification.getPage());
        }
        return pages;
    }

    private XmlObjectModifications getPdfObjectModifications() {
        XmlModificationDetection modificationDetection = pdfRevision.getModificationDetection();
        if (modificationDetection != null) {
            return modificationDetection.getObjectModifications();
        }
        return null;
    }

    private List<String> getModifiedFieldNames(List<XmlObjectModification> objectModifications) {
        List<String> names = new ArrayList<>();
        for (XmlObjectModification objectModification : objectModifications) {
            String fieldName = objectModification.getFieldName();
            if (fieldName != null) {
                names.add(fieldName);
            }
        }
        return names;
    }

}
