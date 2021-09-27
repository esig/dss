package eu.europa.esig.dss.enumerations;

/**
 * A name which, in conjunction with Fields, indicates the set of fields that should be locked.
 *
 */
public enum PdfLockAction {

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
    PdfLockAction(String name) {
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
     * @return {@link PdfLockAction}
     */
    public static PdfLockAction forName(String name) {
        for (PdfLockAction action : values()) {
            if (name.equals(action.getName())) {
                return action;
            }
        }
        throw new IllegalArgumentException(String.format("Unsupported /Action field value : %s", name));
    }

}
