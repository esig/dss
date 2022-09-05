package eu.europa.esig.dss.enumerations;

/**
 * This class is used to load an enumeration(s) of {@code eu.europa.esig.dss.enumerations.MimeType} interface
 *
 */
public interface MimeTypeLoader {

    /**
     * Returns a {@code MimeType} matching the MimeType {@code String}
     *
     * @param mimeTypeString {@link String} identifying the MimeType
     * @return {@link MimeType} if associated MimeType found, NULL otherwise
     */
    MimeType fromMimeTypeString(String mimeTypeString);

    /**
     * Returns {@code MimeType} matching to the provided {@code fileExtension} String
     *
     * @param fileExtension {@link String}
     * @return {@link MimeType} if associated MimeType found, NULL otherwise
     */
    MimeType fromFileExtension(String fileExtension);

}
