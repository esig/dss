package eu.europa.esig.dss.pki.converter;

import eu.europa.esig.dss.pki.RevocationReason;

import java.beans.PropertyEditorSupport;

public class RevocationReasonEditor extends PropertyEditorSupport {

    @Override
    public void setAsText(final String text) throws IllegalArgumentException {
        setValue(RevocationReason.fromValue(text));
    }

}
