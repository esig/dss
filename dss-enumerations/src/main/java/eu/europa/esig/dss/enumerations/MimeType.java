package eu.europa.esig.dss.enumerations;

import java.util.ServiceLoader;

/**
 * Identifies a file MimeType and its attributes
 *
 */
public interface MimeType {

    /**
     * Gets String identifying the MimeType
     *
     * @return the mimeTypeString
     */
    String getMimeTypeString();

    /**
     * Returns file extension corresponding to the MimeType
     *
     * @return {@link String} file extension
     */
    String getExtension();

    /**
     * Returns {@code MimeType} matching to the provided {@code fileExtension} String
     *
     * @param fileExtension {@link String}
     * @return {@link MimeType} if associated MimeType found, NULL otherwise
     */
    static MimeType fromFileExtension(String fileExtension) {
        for (MimeTypeLoader mimeTypeLoader : mimeTypeLoaders()) {
            MimeType mimeType = mimeTypeLoader.fromFileExtension(fileExtension);
            if (mimeType != null) {
                return mimeType;
            }
        }
        return null;
    }

    /**
     * Returns the file extension based on the position of the '.' in the fileName.
     * File paths as "xxx.y/toto" are not handled.
     *
     * @param fileName
     *            to be analysed
     * @return the file extension or null
     */
    static String getFileExtension(final String fileName) {
        if (fileName == null || fileName.trim().length() == 0) {
            return null;
        }

        String extension = "";
        int lastIndexOf = fileName.lastIndexOf('.');
        if (lastIndexOf > 0) {
            extension = fileName.substring(lastIndexOf + 1);
        }
        return extension;
    }

    static Iterable<MimeTypeLoader> mimeTypeLoaders() {
        return ServiceLoader.load(MimeTypeLoader.class);
    }

}
