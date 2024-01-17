package eu.europa.esig.jws;

import com.github.erosb.jsonsKema.Schema;
import com.github.erosb.jsonsKema.SourceLocation;
import com.github.erosb.jsonsKema.ValidationFailure;

import java.util.Iterator;
import java.util.Objects;
import java.util.Set;

/**
 * A wrapper class used to provide user-friendly message returned
 * by a {@code com.github.erosb.jsonsKema.ValidationFailure}
 *
 */
public class ValidationMessage {

    /** Validation failure returned by the validator */
    private final ValidationFailure validationFailure;

    /**
     * Default constructor
     *
     * @param validationFailure {@link ValidationFailure}
     */
    public ValidationMessage(final ValidationFailure validationFailure) {
        Objects.requireNonNull(validationFailure, "ValidationFailure cannot be null!");
        this.validationFailure = validationFailure;
    }

    /**
     * Returns a user-friendly validation message
     *
     * @return {@link String}
     */
    public String getMessage() {
        final StringBuilder sb = new StringBuilder();
        append(sb, validationFailure);
        return sb.toString();
    }

    private void append(StringBuilder sb, ValidationFailure validationFailure) {
        sb.append(validationFailure.getMessage());
        Set<ValidationFailure> causes = validationFailure.getCauses();
        if (!causes.isEmpty()) {
            sb.append(": causes(");
            Iterator<ValidationFailure> it = causes.iterator();
            while (it.hasNext()) {
                append(sb, it.next());
                if (it.hasNext()) {
                    sb.append("; ");
                }
            }
            sb.append(")");
            return;
        }
        Schema schema = validationFailure.getSchema();
        if (!schema.subschemas().isEmpty()) {
            append(sb, schema);
        } else {
            append(sb, validationFailure.getInstance().getLocation());
        }
    }

    private void append(StringBuilder sb, Schema schema) {
        if (!schema.subschemas().isEmpty()) {
            for (Schema subSchema : schema.subschemas()) {
                append(sb, subSchema);
            }
        } else {
            sb.append(", ");
            sb.append(schema);
        }
    }

    private void append(StringBuilder sb, SourceLocation location) {
        if (location != null) {
            sb.append(", location: ");
            sb.append(location);
        }
    }

}
