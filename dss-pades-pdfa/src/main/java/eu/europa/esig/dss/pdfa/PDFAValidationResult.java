package eu.europa.esig.dss.pdfa;

import java.util.Collection;

public class PDFAValidationResult {

    /** Assumed PDF/A profile for the document */
    private String profileId;

    /** Defines whether the document is compliant to the identified {@code profileId} */
    private boolean compliant;

    /** Collection of error messages returned by the validator, when validation failed */
    private Collection<String> errorMessages;

    /**
     * Gets PDF/A profile Id
     *
     * @return {@link String}
     */
    public String getProfileId() {
        return profileId;
    }

    /**
     * Sets the profile Id
     *
     * @param profileId {@link String}
     */
    public void setProfileId(String profileId) {
        this.profileId = profileId;
    }

    /**
     * Gets whether the validated document is compliant according to the returned profile Id
     *
     * @return TRUE of the document is a compliant PDF/A, FALSE otherwise
     */
    public boolean isCompliant() {
        return compliant;
    }

    /**
     * Sets whether the document is compliant to the identified profile Id
     *
     * @param compliant whether the document is a compliant PDF/A
     */
    public void setCompliant(boolean compliant) {
        this.compliant = compliant;
    }

    /**
     * Gets a list of error messages returned by the validator
     *
     * @return a collection of {@link String}s
     */
    public Collection<String> getErrorMessages() {
        return errorMessages;
    }

    /**
     * Sets a collection of error messages returned by the validator
     *
     * @param errorMessages a collection of {@link String} error messages
     */
    public void setErrorMessages(Collection<String> errorMessages) {
        this.errorMessages = errorMessages;
    }

}
