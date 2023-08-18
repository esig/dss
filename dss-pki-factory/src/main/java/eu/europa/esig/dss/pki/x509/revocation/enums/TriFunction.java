package eu.europa.esig.dss.pki.x509.revocation.enums;

import java.util.Objects;
import java.util.function.Function;

@FunctionalInterface
public interface TriFunction<T, U, V, R> {
    R apply(T var1, U var2, V var3);

}