package eu.europa.esig.dss.asic.common;

import eu.europa.esig.dss.enumerations.ASiCContainerType;

import java.util.Collection;
import java.util.Objects;

/**
 * This class contains common methods for ASiC filename factory.
 *
 */
public abstract class AbstractASiCFilenameFactory {

    /**
     * Represents a content of an ASiC container.
     * This variable is used to determine a correct and unique naming for new ZIP entries.
     */
    protected ASiCContent asicContent;

    /**
     * This method is used to set {@code ASiCContent} representing a content of container to be signed or extended.
     * {@code ASiCContent} can be created from an existing container or from a list of documents to be signed,
     * when creating a first signature.
     *
     * @param asicContent {@link ASiCContent} representing a content of an ASiC container
     */
    public void setASiCContent(ASiCContent asicContent) {
        this.asicContent = asicContent;
    }

    /**
     * This method returns the next available suffix (i.e. number) for a new file entry across given document names.
     *
     * Ex.: For provided two signature documents, the method will return "003" suffix,
     * to be used for a signature file creation with a name "META-INF/signature003.xml".
     *
     * @param existingDocumentNames collection of {@link String} document names forbidden for usage
     * @return {@link String} available document name suffix
     */
    protected String getDocumentNameSuffixRecursively(Collection<String> existingDocumentNames) {
        int number = existingDocumentNames.size() + 1;
        String numberStr = String.valueOf(number);
        String zeroPad = "000";
        String candidateName = zeroPad.substring(numberStr.length()) + numberStr; // 2 -> 002
        if (existingDocumentNames.contains(candidateName)) {
            existingDocumentNames.add(candidateName);
            return getDocumentNameSuffixRecursively(existingDocumentNames);
        }
        return candidateName;
    }

    /**
     * This method is used to verify whether the provided {@code asicContent}
     * contains all the required information for a new filename determination
     */
    protected void assertASiCContentIsValid() {
        Objects.requireNonNull(asicContent, "ASiCContent shall be provided!");
        Objects.requireNonNull(asicContent.getContainerType(), "Type of ASiC Container shall be defined!");
        if (ASiCContainerType.ASiC_S != asicContent.getContainerType() &&
                ASiCContainerType.ASiC_E != asicContent.getContainerType()) {
            throw new IllegalArgumentException("The type of the ASiCContent shall be one of ASiC-S or ASiC-E!");
        }
    }

}
