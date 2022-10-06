package eu.europa.esig.dss.cookbook.example;

// tag::demo[]
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.MimeTypeLoader;

public class CustomMimeTypeLoader implements MimeTypeLoader {

    @Override
    public MimeType fromMimeTypeString(String mimeTypeString) {
        for (CustomMimeType mimeType : CustomMimeType.values()) {
            if (mimeTypeString.equalsIgnoreCase(mimeType.mimeTypeString)) {
                return mimeType;
            }
        }
        return null;
    }

    @Override
    public MimeType fromFileExtension(String fileExtension) {
        for (CustomMimeType mimeType : CustomMimeType.values()) {
            for (String extension : mimeType.extensions) {
                if (fileExtension.equalsIgnoreCase(extension)) {
                    return mimeType;
                }
            }
        }
        return null;
    }

    public enum CustomMimeType implements MimeType {

        CER("application/pkix-cert", "cer", "crt", "p7c"),
        CSS("text/css", "css"),
        JPEG("image/jpeg", "jpeg"),
        WEBM("audio/webm", "webm");

        private final String mimeTypeString;

        private final String[] extensions;

        CustomMimeType(final String mimeTypeString, final String... extensions) {
            this.mimeTypeString = mimeTypeString;
            this.extensions = extensions;
        }

        @Override
        public String getMimeTypeString() {
            return mimeTypeString;
        }

        @Override
        public String getExtension() {
            if (extensions != null && extensions.length > 0) {
                return extensions[0];
            }
            return null;
        }

    }

}
// end::demo[]