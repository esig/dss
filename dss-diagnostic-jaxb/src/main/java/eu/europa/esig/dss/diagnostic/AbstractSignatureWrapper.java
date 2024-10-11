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

import eu.europa.esig.dss.diagnostic.jaxb.XmlObjectModification;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFLockDictionary;
import eu.europa.esig.dss.enumerations.CertificationPermission;

import java.math.BigInteger;
import java.util.Collections;
import java.util.List;

/**
 * Contains common code for signature tokens (signature or timestamps).
 *
 */
public abstract class AbstractSignatureWrapper extends AbstractTokenProxy {

    /**
     * Default constructor
     */
    protected AbstractSignatureWrapper() {
        // empty
    }

    /**
     * Gets name of the signature or timestamp file, when applicable
     *
     * @return {@link String} file name
     */
    public abstract String getFilename();

    /**
     * Returns a PAdES-specific PDF Revision info
     * NOTE: applicable only for PAdES
     *
     * @return {@link PDFRevisionWrapper}
     */
    public abstract PDFRevisionWrapper getPDFRevision();

    /**
     * Checks if any visual modifications detected in the PDF
     *
     * @return TRUE if modifications detected in a PDF, FALSE otherwise
     */
    public boolean arePdfModificationsDetected() {
        PDFRevisionWrapper pdfRevision = getPDFRevision();
        if (pdfRevision != null) {
            return pdfRevision.arePdfModificationsDetected();
        }
        return false;
    }

    /**
     * Returns a list of PDF annotation overlap concerned pages
     *
     * @return a list of page numbers
     */
    public List<BigInteger> getPdfAnnotationsOverlapConcernedPages() {
        PDFRevisionWrapper pdfRevision = getPDFRevision();
        if (pdfRevision != null) {
            return pdfRevision.getPdfAnnotationsOverlapConcernedPages();
        }
        return Collections.emptyList();
    }

    /**
     * Returns a list of PDF visual difference concerned pages
     *
     * @return a list of page numbers
     */
    public List<BigInteger> getPdfVisualDifferenceConcernedPages() {
        PDFRevisionWrapper pdfRevision = getPDFRevision();
        if (pdfRevision != null) {
            return pdfRevision.getPdfVisualDifferenceConcernedPages();
        }
        return Collections.emptyList();
    }

    /**
     * Returns a list of pages missing/added to the final revision in a comparison with a signed one
     *
     * @return a list of page numbers
     */
    public List<BigInteger> getPdfPageDifferenceConcernedPages() {
        PDFRevisionWrapper pdfRevision = getPDFRevision();
        if (pdfRevision != null) {
            return pdfRevision.getPdfPageDifferenceConcernedPages();
        }
        return Collections.emptyList();
    }

    /**
     * This method checks whether object modifications are present after the current PDF revisions
     *
     * @return TRUE if PDF has been modified, FALSE otherwise
     */
    public boolean arePdfObjectModificationsDetected() {
        PDFRevisionWrapper pdfRevision = getPDFRevision();
        if (pdfRevision != null) {
            return pdfRevision.arePdfObjectModificationsDetected();
        }
        return false;
    }

    /**
     * Returns a list of changes occurred in a PDF after the current signature's revision associated
     * with a signature/document extension
     *
     * @return a list of {@link XmlObjectModification}s
     */
    public List<XmlObjectModification> getPdfExtensionChanges() {
        PDFRevisionWrapper pdfRevision = getPDFRevision();
        if (pdfRevision != null) {
            return pdfRevision.getPdfExtensionChanges();
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
        PDFRevisionWrapper pdfRevision = getPDFRevision();
        if (pdfRevision != null) {
            return pdfRevision.getPdfSignatureOrFormFillChanges();
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
        PDFRevisionWrapper pdfRevision = getPDFRevision();
        if (pdfRevision != null) {
            return pdfRevision.getPdfAnnotationChanges();
        }
        return Collections.emptyList();
    }

    /**
     * Returns a list of undefined changes occurred in a PDF after the current signature's revision
     *
     * @return a list of {@link XmlObjectModification}s
     */
    public List<XmlObjectModification> getPdfUndefinedChanges() {
        PDFRevisionWrapper pdfRevision = getPDFRevision();
        if (pdfRevision != null) {
            return pdfRevision.getPdfUndefinedChanges();
        }
        return Collections.emptyList();
    }

    /**
     * This method returns a list of field names modified after the current signature's revision
     *
     * @return a list of {@link String}s
     */
    public List<String> getModifiedFieldNames() {
        PDFRevisionWrapper pdfRevision = getPDFRevision();
        if (pdfRevision != null) {
            return pdfRevision.getModifiedFieldNames();
        }
        return Collections.emptyList();
    }

    /**
     * Returns the first signature field name
     *
     * @return {@link String} field name
     */
    public String getFirstFieldName() {
        PDFRevisionWrapper pdfRevision = getPDFRevision();
        if (pdfRevision != null) {
            return pdfRevision.getFirstFieldName();
        }
        return null;
    }

    /**
     * Returns a list of signature field names, where the signature is referenced from
     *
     * @return a list of {@link String} signature field names
     */
    public List<String> getSignatureFieldNames() {
        PDFRevisionWrapper pdfRevision = getPDFRevision();
        if (pdfRevision != null) {
            return pdfRevision.getSignatureFieldNames();
        }
        return Collections.emptyList();
    }

    /**
     * Returns the signer's name
     *
     * @return {@link String}
     */
    public String getSignerName() {
        PDFRevisionWrapper pdfRevision = getPDFRevision();
        if (pdfRevision != null) {
            return pdfRevision.getSignerName();
        }
        return null;
    }

    /**
     * Returns the PDF signature dictionary /Type value
     *
     * @return {@link String}
     */
    public String getSignatureDictionaryType() {
        PDFRevisionWrapper pdfRevision = getPDFRevision();
        if (pdfRevision != null) {
            return pdfRevision.getSignatureDictionaryType();
        }
        return null;
    }

    /**
     * Returns the PDF signature dictionary /Filter value
     *
     * @return {@link String}
     */
    public String getFilter() {
        PDFRevisionWrapper pdfRevision = getPDFRevision();
        if (pdfRevision != null) {
            return pdfRevision.getFilter();
        }
        return null;
    }

    /**
     * Returns the PDF signature dictionary /SubFilter value
     *
     * @return {@link String}
     */
    public String getSubFilter() {
        PDFRevisionWrapper pdfRevision = getPDFRevision();
        if (pdfRevision != null) {
            return pdfRevision.getSubFilter();
        }
        return null;
    }

    /**
     * Returns the PDF signature dictionary /ContactInfo value
     *
     * @return {@link String}
     */
    public String getContactInfo() {
        PDFRevisionWrapper pdfRevision = getPDFRevision();
        if (pdfRevision != null) {
            return pdfRevision.getContactInfo();
        }
        return null;
    }

    /**
     * Returns the PDF signature dictionary /Location value
     *
     * @return {@link String}
     */
    public String getLocation() {
        PDFRevisionWrapper pdfRevision = getPDFRevision();
        if (pdfRevision != null) {
            return pdfRevision.getLocation();
        }
        return null;
    }

    /**
     * Returns the PDF signature dictionary /Reason value
     *
     * @return {@link String}
     */
    public String getReason() {
        PDFRevisionWrapper pdfRevision = getPDFRevision();
        if (pdfRevision != null) {
            return pdfRevision.getReason();
        }
        return null;
    }

    /**
     * Returns the PDF signature dictionary /ByteRange value
     *
     * @return byte range
     */
    public List<BigInteger> getSignatureByteRange() {
        PDFRevisionWrapper pdfRevision = getPDFRevision();
        if (pdfRevision != null) {
            return pdfRevision.getSignatureByteRange();
        }
        return Collections.emptyList();
    }

    /**
     * This method returns whether the PDF signature dictionary /ByteRange is found and valid
     *
     * @return TRUE if the /ByteRange is valid, FALSE otherwise
     */
    public boolean isSignatureByteRangeValid() {
        PDFRevisionWrapper pdfRevision = getPDFRevision();
        if (pdfRevision != null) {
            return pdfRevision.isSignatureByteRangeValid();
        }
        return false;
    }

    /**
     * This method returns whether the PDF signature dictionary is consistent across PDF revisions.
     *
     * @return TRUE if the signature dictionary is consistent, FALSE otherwise
     */
    public boolean isPdfSignatureDictionaryConsistent() {
        PDFRevisionWrapper pdfRevision = getPDFRevision();
        if (pdfRevision != null) {
            return pdfRevision.isPdfSignatureDictionaryConsistent();
        }
        return false;
    }

    /**
     * Returns a {@code CertificationPermission} value of a /DocMDP dictionary, when present
     *
     * @return {@link CertificationPermission}
     */
    public CertificationPermission getDocMDPPermissions() {
        PDFRevisionWrapper pdfRevision = getPDFRevision();
        if (pdfRevision != null) {
            return pdfRevision.getDocMDPPermissions();
        }
        return null;
    }

    /**
     * Returns a /FieldMDP dictionary content, when present
     *
     * @return {@link XmlPDFLockDictionary}
     */
    public XmlPDFLockDictionary getFieldMDP() {
        PDFRevisionWrapper pdfRevision = getPDFRevision();
        if (pdfRevision != null) {
            return pdfRevision.getFieldMDP();
        }
        return null;
    }

    /**
     * Returns a /SigFieldLock dictionary, when present
     *
     * @return {@link XmlPDFLockDictionary}
     */
    public XmlPDFLockDictionary getSigFieldLock() {
        PDFRevisionWrapper pdfRevision = getPDFRevision();
        if (pdfRevision != null) {
            return pdfRevision.getSigFieldLock();
        }
        return null;
    }

}
