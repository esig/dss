package eu.europa.esig.dss.pdf;

import eu.europa.esig.dss.pades.CertificationPermission;

import java.util.List;

/**
 * This class defines a list of restrictions imposed to a PDF document modifications
 * by the current signature/field
 *
 */
public class SigFieldPermissions {

    /** Indicates the set of fields that should be locked */
    private Action action;

    /** Contains a set of fields */
    private List<String> fields;

    /** The access permissions (optional) */
    private CertificationPermission certificationPermission;

    /**
     * Gets the defined action
     *
     * @return {@link Action}
     */
    public Action getAction() {
        return action;
    }

    /**
     * Sets the action
     *
     * @param action {@link Action}
     */
    public void setAction(Action action) {
        this.action = action;
    }

    /**
     * Gets a list of field names
     *
     * @return a list of {@link String}s
     */
    public List<String> getFields() {
        return fields;
    }

    /**
     * Sets a list of field names
     *
     * @param fields a list of {@link String}s
     */
    public void setFields(List<String> fields) {
        this.fields = fields;
    }

    /**
     * Gets the {@code CertificationPermission}
     *
     * @return {@link CertificationPermission}
     */
    public CertificationPermission getCertificationPermission() {
        return certificationPermission;
    }

    /**
     * Sets the {@code CertificationPermission}
     *
     * @param certificationPermission {@link CertificationPermission}
     */
    public void setCertificationPermission(CertificationPermission certificationPermission) {
        this.certificationPermission = certificationPermission;
    }

    /**
     * A name which, in conjunction with Fields, indicates the set of fields that should be locked.
     */
    public enum Action {

        /** All form fields do not permit changes */
        ALL("All"),

        /** Only those form fields specified in fields do not permit changes */
        INCLUDE("Include"),

        /** Only those form fields not specified in fields do not permit changes */
        EXCLUDE("Exclude");

        /** The value of the /Action field */
        private String name;

        /**
         * Default constructor
         *
         * @param name {@link String} value of the field
         */
        Action(String name) {
            this.name = name;
        }

        /**
         * Returns name value of the field parameter
         *
         * @return {@link String}
         */
        public String getName() {
            return name;
        }

        /**
         * Returns a {@code Action} corresponding to the given {@code name}
         *
         * @param name {@link String}
         * @return {@link Action}
         */
        public static Action forName(String name) {
            for (Action action : values()) {
                if (name.equals(action.getName())) {
                    return action;
                }
            }
            throw new IllegalArgumentException(String.format("Unsupported /Action field value : %s", name));
        }

    }

}
