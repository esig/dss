package eu.europa.esig.dss.cookbook.example;

import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.MimeTypeLoader;

public class CustomMimeTypeLoader implements MimeTypeLoader {

    @Override
    public MimeType fromFileExtension(String fileExtension) {
        return CustomMimeType.CUSTOM;
    }

    public enum CustomMimeType implements MimeType {
        CUSTOM;

        @Override
        public String getMimeTypeString() {
            return null;
        }

        @Override
        public String getExtension() {
            return null;
        }
    }

}
