package eu.europa.esig.dss.enumerations;

/**
 * Contains methods to extract {@code MimeTypeEnum}s
 *
 */
public class MimeTypeEnumLoader implements MimeTypeLoader {

    @Override
    public MimeType fromFileExtension(String fileExtension) {
        for (MimeTypeEnum mimeTypeEnum : MimeTypeEnum.values()) {
            for (String extension : mimeTypeEnum.extensions) {
                if (fileExtension.equalsIgnoreCase(extension)) {
                    return mimeTypeEnum;
                }
            }
        }
        return null;
    }

}
