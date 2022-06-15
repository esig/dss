package eu.europa.esig.dss.pdf.modifications;

import java.util.Collection;

/**
 * This class is used to categorize {@code eu.europa.esig.dss.pdf.modifications.ObjectModification}s
 * to different categories.
 *
 */
public interface PdfObjectModificationsFilter {

    /**
     * Categorizes the given collection of {@code ObjectModification}s to various categories and
     * returns {@code PdfObjectModifications} containing the result of filtering.
     *
     * @param objectModifications a collection of {@link ObjectModification}s to be categorized
     * @return {@link PdfObjectModifications}
     */
    PdfObjectModifications filter(final Collection<ObjectModification> objectModifications);

}
